"""2026-08-06 空闲补扫执行器:重新分析失败批次的 finding。

被 ``src.scan_engine.llm_analysis.rescan_loop`` 调用。逻辑:
1. 读 ``llm:retry:{task_id}`` 取待补扫 finding_id + 已尝试次数
2. 已尝试次数 ≥ llm_analysis_max_total_attempts -> 标记 "AI全部分析失败"/
   "AI部分分析失败" 并清队列(不再自动补扫,任务保留)
3. 否则取一批(≤15)重新调 LLM 分析(走 chat_with_retry 即时重试)
4. 成功 -> 写回 vuln 的 ai_* 字段 + 从待补扫队列移除
5. 失败 -> 尝试次数 +1 留在队列,等下一轮空闲
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.common.logging.logger import get_logger
from src.scan_engine.llm_analysis import (
    chat_with_retry,
    list_retry_tasks,
    mark_analysis_outcome,
    remove_retry_batch,
)

logger = get_logger(__name__)

BATCH_SIZE = 15


async def rescan_one_batch(task_id: str) -> bool:
    """处理一个任务的一个补扫批次。返回 True 表示该任务还有待补扫内容(继续)。"""
    from src.common.config.settings import get_settings
    from src.orchestration.subgraphs.vulnscan.nodes import _build_analysis_prompt

    s = get_settings()
    pending = await list_retry_tasks(limit=200)
    item = next((p for p in pending if p["task_id"] == task_id), None)
    if item is None:
        return False
    entries = item["entries"]
    if not entries:
        return False

    # 找尝试次数最小的批次(优先处理尝试少的)
    entries.sort(key=lambda e: e["attempts"])
    batch_entries = entries[:BATCH_SIZE]

    # 已达上限?全部达到 -> 终态标记
    max_attempts = s.llm_analysis_max_total_attempts
    if all(e["attempts"] >= max_attempts for e in entries):
        from src.api.store import get_event_store  # noqa: F401  # 仅占位(实际用 vulnscan store)

        await _mark_final(task_id, entries)
        return False

    # 取一批未达上限的
    batch_entries = [e for e in entries if e["attempts"] < max_attempts][:BATCH_SIZE]
    finding_ids = [e["finding_id"] for e in batch_entries]
    if not finding_ids:
        return False

    # 构造 findings(从 vulnscan store 读该 task 的这些 finding)
    try:
        from src.agents.models import VulnFilter
        from src.agents.store import get_vulnscan_store

        store = get_vulnscan_store()
        vulns = await store.list_vulns(VulnFilter(task_id=task_id, limit=10000))
        vuln_map = {str(v.get("finding_id") or v.get("id") or ""): v for v in vulns}
    except Exception as exc:
        logger.warning("llm_rescan_load_findings_failed", task_id=task_id, error=str(exc))
        return False

    findings = [vuln_map.get(fid) for fid in finding_ids if fid in vuln_map]
    if not findings:
        await remove_retry_batch(task_id, finding_ids)
        return True

    try:
        from src.knowledge.models.adapter import get_model_adapter

        adapter = get_model_adapter()
        from pydantic import BaseModel

        class AnalyzedFinding(BaseModel):
            finding_id: str
            ai_severity: str
            ai_filtered: bool
            reason: str
            fix_advice: str

        class AnalyzedResult(BaseModel):
            analyzed: list[AnalyzedFinding]

        prompt = _build_analysis_prompt(findings)

        async def _call() -> Any:
            return await adapter.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                schema=AnalyzedResult,
            )

        result = await chat_with_retry(
            "rescan",
            _call,
            task_id=task_id,
            finding_ids=finding_ids,
            extra={"task_id": task_id, "rescan": True},
        )
    except Exception as exc:
        # 本次补扫失败:尝试次数已由 enqueue_retry_batch 累加过(chat_with_retry 失败路径),
        # 但注意 chat_with_retry 失败会重新 hincrby,与已有计数叠加。这里按现有计数判断上限。
        logger.warning("llm_rescan_batch_failed", task_id=task_id, error=str(exc))
        return True

    # 成功:写回 vuln + 移除待补扫
    now_iso = datetime.now(UTC).isoformat()
    ok_ids: list[str] = []
    try:
        for af in result.analyzed:
            fid = af.finding_id
            if fid not in set(finding_ids):
                continue
            try:
                await store.update_vuln(
                    fid,
                    ai_severity=af.ai_severity,
                    ai_filtered=af.ai_filtered,
                    fix_advice=af.fix_advice,
                    ai_processed=True,
                    ai_reason=af.reason,
                    ai_processed_at=now_iso,
                )
                ok_ids.append(fid)
            except Exception as exc:  # noqa: BLE001
                logger.warning("llm_rescan_update_failed", finding_id=fid, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.warning("llm_rescan_writeback_failed", task_id=task_id, error=str(exc))

    if ok_ids:
        await remove_retry_batch(task_id, ok_ids)
        logger.info("llm_rescan_succeeded", task_id=task_id, findings=len(ok_ids))

    # 该任务是否还有剩余?判断终态
    remaining = await list_retry_tasks(limit=200)
    ritem = next((p for p in remaining if p["task_id"] == task_id), None)
    if ritem and ritem["entries"] and all(e["attempts"] >= s.llm_analysis_max_total_attempts for e in ritem["entries"]):
        await _mark_final(task_id, ritem["entries"])
        return False
    return True


async def _mark_final(task_id: str, entries: list[dict[str, Any]]) -> None:
    """所有待补扫批次都达上限:标记全失败/部分失败,清队列。"""
    from src.scan_engine.llm_analysis import _redis

    try:
        r = await _redis()
        try:
            key = f"llm:retry:{task_id}"
            await r.delete(key)
        finally:
            await r.aclose()
    except Exception:
        pass

    # 统计该任务成功/失败 finding 数(尽力而为,读 vuln 的 ai_processed)
    total = len(entries)
    succeeded = 0
    try:
        from src.agents.models import VulnFilter
        from src.agents.store import get_vulnscan_store

        store = get_vulnscan_store()
        vulns = await store.list_vulns(VulnFilter(task_id=task_id, limit=10000))
        succeeded = sum(1 for v in vulns if v.get("ai_processed"))
        total = max(total, len(vulns))
    except Exception:
        pass
    await mark_analysis_outcome(task_id, total, succeeded)
