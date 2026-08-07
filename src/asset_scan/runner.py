"""asset-scan runner: 消费队列入口（需求②）。

被 TaskWorker(stream=assetscan) 调用，语义与 vulnscan 的
``run_vulnscan_from_envelope`` 一致：写 running 状态 → 调 LangGraph
子图 → 完成时更新任务/写报告。任何异常向上抛出，由 TaskWorker 走
PEL 重投 + DLQ（MAX_DELIVERY=3）。

子图 ``src.orchestration.subgraphs.asset_scan.graph`` 在阶段 C 实现；
在此之前 import 失败会令任务进 DLQ（队列/状态链路已可独立验证）。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.common.logging.logger import get_logger

logger = get_logger(__name__)


async def run_asset_scan_from_envelope(envelope: Any) -> dict[str, Any]:
    """Execute one asset-scan task end to end.

    ``envelope`` 是 AssetScanEnvelope（鸭子类型：task_id/targets/ports/
    engine/modules/actor 字段）。
    """
    from src.asset_scan.store import get_asset_store

    task_id = envelope.task_id
    store = get_asset_store()
    now = datetime.now(UTC).isoformat()

    try:
        await store.update_task(task_id, status="running", started_at=now)
        logger.info("asset_task_started", task_id=task_id, targets=envelope.targets)

        # 阶段 C 的子图：parse_intent → discover → fingerprint →
        # match_vulns → llm_analysis → generate_report。
        from src.orchestration.subgraphs.asset_scan.graph import run_asset_scan

        result = await run_asset_scan(envelope)
        await store.update_task(
            task_id,
            status="completed",
            finished_at=datetime.now(UTC).isoformat(),
        )
        logger.info("asset_task_completed", task_id=task_id)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset_task_failed", task_id=task_id, error=str(exc))
        try:
            await store.update_task(
                task_id,
                status="failed",
                finished_at=datetime.now(UTC).isoformat(),
                error=str(exc)[:2000],
            )
        except Exception as store_exc:  # noqa: BLE001
            logger.warning("asset_task_failed_state_write_error", error=str(store_exc))
        raise
