"""asset-scan 服务入口 (需求②: 内网资产扫描, agentless)。

独立第 7 个服务：启动 TaskWorker 消费 ``assetscan:queue:tasks`` 流，
用 nmap/masscan/nuclei 子进程执行资产发现 + 漏洞匹配（LangGraph 子图）。

- lifespan：ES 索引 ensure + 启动 TaskWorker（自定义 stream/group/
  runner/envelope_cls）+ 取消墓碑清扫（把僵尸 cancel key 过期清掉）
- /healthz：TaskWorker 存活探针（entrypoint fail-fast 检查 nmap/masscan/nuclei）
- 日志关键字：`assetworker_started` / `assetworker_failed`
- entrypoint：`python -m src.asset_scan.main`（entrypoint-asset-scan.sh）
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_task_worker_handle: Any = None
_cancel_sweep_task: asyncio.Task | None = None


async def _cancel_sweep_loop() -> None:
    """周期清扫过期的 assetscan 取消墓碑（TTL 之外的僵尸 key）。

    取消墓碑有 24h TTL（Redis EXPIRE 自动过期），本清扫只是兜底——
    把任务完成/失败后遗留的 cancel key 主动删掉，避免积累。
    间隔 1h。
    """
    import redis.asyncio as aioredis

    from src.common.config.settings import get_settings

    while True:
        await asyncio.sleep(3600)
        try:
            redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
            try:
                # assetscan:queue:cancel:* 的 key 数量通常很少，SCAN 足够。
                async for key in redis.scan_iter(match="assetscan:queue:cancel:*", count=100):
                    await redis.delete(key)
                    logger.info("asset_cancel_tombstone_cleaned", key=key)
            finally:
                await redis.aclose()
        except Exception as exc:  # noqa: BLE001
            logger.warning("asset_cancel_sweep_failed", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """asset-scan lifespan：索引 + TaskWorker（自定义队列）。"""
    global _task_worker_handle, _cancel_sweep_task
    logger.info("asset_scan_starting")

    # ES 索引（幂等）
    try:
        from src.asset_scan.store import get_asset_store

        await get_asset_store().ensure_indices()
        logger.info("asset_scan_es_indices_ready")
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset_scan_es_indices_failed", error=str(exc))

    if not __import__("os").environ.get("DISABLE_ASSET_WORKER"):
        try:
            from src.asset_scan.runner import run_asset_scan_from_envelope
            from src.orchestration.task_queue.enqueue import AssetScanEnvelope
            from src.orchestration.task_queue.keys import (
                ASSET_CONSUMER_GROUP,
                STREAM_ASSET_DLQ,
                STREAM_ASSET_TASKS,
            )
            from src.orchestration.task_queue.worker import TaskWorker

            worker = TaskWorker(
                stream=STREAM_ASSET_TASKS,
                group=ASSET_CONSUMER_GROUP,
                dlq=STREAM_ASSET_DLQ,
                runner=run_asset_scan_from_envelope,
                envelope_cls=AssetScanEnvelope,
            )
            _task_worker_handle = worker.start()
            logger.info(
                "assetworker_started",
                consumer=worker._consumer,
                stream=STREAM_ASSET_TASKS,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assetworker_failed", error=str(exc))

    _cancel_sweep_task = asyncio.create_task(_cancel_sweep_loop(), name="asset-cancel-sweep")

    yield

    if _task_worker_handle is not None:
        try:
            await _task_worker_handle.stop(timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("assetworker_shutdown_failed", error=str(exc))
    if _cancel_sweep_task is not None:
        _cancel_sweep_task.cancel()
        try:
            await asyncio.wait_for(_cancel_sweep_task, timeout=2.0)
        except (TimeoutError, asyncio.CancelledError):
            pass
    logger.info("asset_scan_stopping")


app = FastAPI(
    title="secagent-asset-scan",
    version="0.1.0",
    description="agentless 内网资产扫描（nmap/masscan/nuclei + LangGraph 编排）",
    lifespan=lifespan,
)

from src.common.metrics import metrics_router  # noqa: E402

app.include_router(metrics_router)


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict[str, Any]:
    """健康检查：TaskWorker 存活。"""
    worker_alive = _task_worker_handle is not None
    return {
        "status": "ok" if worker_alive else "degraded",
        "service": "asset-scan",
        "task_worker_alive": worker_alive,
    }
