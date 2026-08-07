"""CTI analyst node — external intel queries + GraphRAG HTTP retrieval + LLM analysis.

阶段 1 拆分迁移:不再直连 src.knowledge.graphrag.* 与 src.orchestration.memory。
改通过 src.graphrag.main.GraphRAGClient httpx 调 graphrag 服务:
- /engine/search  综合检索(自动 embed + milvus + neo4j + RRF)
- /memory/add    存证据(替代 MemoryManager.store_evidence)

graphrag_base_url 来自 Settings.graphrag_base_url(阶段 0-1 新增字段)。
失败时与原实现一致吞错返回 '' / 静默不存,不影响 LLM 流程。
"""
from typing import Any, Literal

import httpx
from pydantic import BaseModel

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.graphrag.main import GraphRAGClient
from src.knowledge.models.adapter import get_model_adapter
from src.orchestration.subgraphs.investigation.state import InvestigationSubState

logger = get_logger(__name__)


class IntelCard(BaseModel):
    risk_level: Literal["critical", "high", "medium", "low", "unknown"]
    related_apt: list[str]
    campaigns: list[str]
    ttps: list[str]
    recommendations: list[str]
    raw_evidence: list[str]


async def _query_virustotal(ioc: str, api_key: str) -> dict:
    if not api_key:
        return {}
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"x-apikey": api_key})
            if resp.status_code == 200:
                return resp.json()
    except Exception as exc:
        logger.warning("virustotal_query_failed", ioc=ioc, error=str(exc))
    return {}


async def _query_graphrag(ioc_values: list[str]) -> str:
    """调 graphrag 服务 /engine/search,返回 formatted context string。

    失败时返回 '' 并吞错(原行为保留)。
    """
    client = GraphRAGClient()
    try:
        result = await client.engine_search(ioc_values=ioc_values, top_k=5)
        return result.get("context", "") or ""
    except Exception as exc:
        logger.debug("graphrag_unavailable", error=str(exc))
        return ""
    finally:
        await client.close()


async def cti_analyst_node(state: InvestigationSubState) -> dict[str, Any]:
    settings = get_settings()
    iocs = state.get("iocs", {})
    all_ioc_values = iocs.get("ips", []) + iocs.get("domains", []) + iocs.get("hashes", [])

    # Parallel external intelligence queries
    import asyncio

    vt_results = await asyncio.gather(
        *[_query_virustotal(ioc, settings.virustotal_api_key) for ioc in all_ioc_values[:5]],
        return_exceptions=True,
    )

    evidence = [str(r) for r in vt_results if isinstance(r, dict) and r]
    graph_relations = state.get("graph_relations", [])

    # Local GraphRAG retrieval (走 graphrag HTTP)
    graphrag_context = await _query_graphrag(all_ioc_values)

    prompt = (
        "You are a CTI analyst. Based on the following IOCs and evidence, "
        "produce a structured threat intelligence card.\n\n"
        f"IOCs: {all_ioc_values}\n"
        f"Graph relations: {graph_relations[:10]}\n"
        f"External evidence: {evidence[:3]}\n"
        f"Local intel context:\n{graphrag_context[:1000]}\n\n"
        "Return a JSON with: risk_level, related_apt, campaigns, ttps, recommendations, raw_evidence"
    )

    adapter = get_model_adapter()
    # P1-SUB-3 (2026-07-19): wrap LLM call in try/except. If the model is
    # down or rate-limited, fall back to a degraded intel card with risk=unknown
    # so the rest of the investigation subgraph (playbook_matcher, route)
    # keeps moving instead of crashing the whole node.
    try:
        intel_card = await adapter.chat_completion(
            messages=[{"role": "user", "content": prompt}],
            schema=IntelCard,
        )
    except Exception as exc:
        logger.warning("cti_llm_failed", error=str(exc))
        intel_card = IntelCard(
            risk_level="unknown",
            related_apt=[],
            campaigns=[],
            ttps=[],
            recommendations=["CTI LLM unavailable -- manual review required"],
            raw_evidence=evidence[:5],
        )

    log_entry = f"CTI: risk={intel_card.risk_level} apt={intel_card.related_apt}"
    # 阶段 1:memory.add 改走 graphrag HTTP。
    # 阶段 5 收尾:抽 `_store_memory` 函数作为 monkeypatch 钩子,
    # 单测 test_investigation.py 可在 cti 模块上 mock 此函数而不需依赖 graphrag 服务。
    await _store_memory(
        event_id=state.get("event_id", "unknown"),
        node="cti_analyst",
        content=f"Risk: {intel_card.risk_level}",
        metadata=intel_card.model_dump(),
    )
    return {
        "raw_intel": intel_card.model_dump(),
        "investigation_log": state.get("investigation_log", []) + [log_entry],
    }


async def _store_memory(
    event_id: str,
    node: str,
    content: str,
    metadata: dict | None = None,
) -> None:
    """阶段 5 收尾:cti 节点调用 graphrag /memory/add 的可 mock 钩子。

    单元测试可在 src.orchestration.subgraphs.investigation.cti_analyst 模块上
    monkeypatch 此函数,避免依赖真实 graphrag 服务。
    """
    try:
        client = GraphRAGClient()
        try:
            await client.memory_add(
                event_id=event_id,
                node=node,
                content=content,
                metadata=metadata,
            )
        finally:
            await client.close()
    except Exception as mem_err:
        logger.warning("memory_store_failed", error=str(mem_err))
