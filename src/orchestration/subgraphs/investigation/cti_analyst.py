from typing import Any, Literal

import httpx
from pydantic import BaseModel

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
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


async def cti_analyst_node(state: InvestigationSubState) -> dict[str, Any]:
    settings = get_settings()
    iocs = state.get("iocs", {})
    all_ioc_values = (
        iocs.get("ips", []) + iocs.get("domains", []) + iocs.get("hashes", [])
    )

    # Parallel external intelligence queries
    import asyncio
    vt_results = await asyncio.gather(
        *[_query_virustotal(ioc, settings.virustotal_api_key) for ioc in all_ioc_values[:5]],
        return_exceptions=True,
    )

    evidence = [str(r) for r in vt_results if isinstance(r, dict) and r]
    graph_relations = state.get("graph_relations", [])

    prompt = (
        "You are a CTI analyst. Based on the following IOCs and evidence, "
        "produce a structured threat intelligence card.\n\n"
        f"IOCs: {all_ioc_values}\n"
        f"Graph relations: {graph_relations[:10]}\n"
        f"External evidence: {evidence[:3]}\n\n"
        "Return a JSON with: risk_level, related_apt, campaigns, ttps, recommendations, raw_evidence"
    )

    adapter = get_model_adapter()
    intel_card = await adapter.chat_completion(
        messages=[{"role": "user", "content": prompt}],
        schema=IntelCard,
    )

    log_entry = f"CTI: risk={intel_card.risk_level} apt={intel_card.related_apt}"
    return {
        "raw_intel": intel_card.model_dump(),
        "investigation_log": state.get("investigation_log", []) + [log_entry],
    }
