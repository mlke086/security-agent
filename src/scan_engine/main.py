"""scan-engine 服务入口(阶段 2)。

启动 TaskWorker 消费 Redis Stream 跑 LangGraph 流水线。

阶段 2 拆出:此服务是 vulnscan/事件流水线的独立进程,
不再依赖 gateway 的 lifespan;通过 Redis pub/sub 与 WS 网关解耦(方案 1.4)。

- lifespan:启动 TaskWorker + (可选) events:tasks Stream 消费者
- /healthz:基础检查 + TaskWorker 存活探针
- 日志关键字:`taskworker_started` / `taskworker_failed` / `events_consumer_started`
- entrypoint:`tini -- python -m src.scan_engine.main` 由 entrypoint-scan-engine.sh 提供
"""
from __future__ import annotations

import asyncio
import os
import socket
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_task_worker_handle: Any = None
_events_consumer_task: asyncio.Task | None = None
_queue_alert_task: asyncio.Task | None = None
_llm_rescan_task: asyncio.Task | None = None
_events_consumer_stop: asyncio.Event | None = None


async def _events_consumer_loop() -> None:
    """阶段 5 收尾 P2-7:消费 preprocessing 推入的 events:tasks stream。

    跨服务契约:
    - producer:preprocessing 镜像调 enqueue_event(event_id, payload) 推入
    - consumer:本协程(在 scan-engine lifespan 启动)XREADGROUP 消费

    消费到的事件当前直接触发 run_pipeline()(阶段 4 的 LangGraph 流水线入口),
    与 vulnscan:tasks 任务的入口相同(共享 runner)。

    与 TaskWorker 区别:TaskWorker 处理用户主动触发的 vulnscan 任务(POST /vulnscan/tasks),
    本消费者处理 EDR 告警(从 Kafka 进 preprocessing 再入队)。
    """
    from src.preprocessing.vulnscan_queue.keys import (
        EVENT_CONSUMER_GROUP,
        EVENT_STREAM,
    )

    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    consumer_name = f"scan-engine-events-{socket.gethostname()}-{id(redis)}"
    logger.info(
        "events_consumer_started",
        stream=EVENT_STREAM,
        group=EVENT_CONSUMER_GROUP,
        consumer=consumer_name,
    )
    try:
        # 幂等创建消费组
        try:
            await redis.xgroup_create(
                name=EVENT_STREAM,
                groupname=EVENT_CONSUMER_GROUP,
                id="$",  # 只消费启动后新事件
                mkstream=True,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

        # 阶段 5 收尾 P-func-3:启动时 XAUTOCLAIM 抢回 idle ≥ 60s 的 PEL entry。
        # 旧进程崩溃后持有 PEL entry 永远不 ack(僵尸 consumer 持有);新进程
        # 启动后必须显式 claim 回来,否则 PEL 持续堆积。
        # 用 claim_stale_batch 一次性回收所有 idle entry(单条 claim_stale 需循环)。
        from src.orchestration.task_queue.dequeue import claim_stale_batch

        try:
            # events consumer 启动清 PEL:用 60s 阈值(远小于 task worker 的 60min,
            # 适配 events 流突发重启场景)。
            claimed = await claim_stale_batch(
                redis,
                stream=EVENT_STREAM,
                group=EVENT_CONSUMER_GROUP,
                consumer=consumer_name,
                min_idle_ms=60_000,
            )
            if claimed:
                logger.info(
                    "events_consumer_claimed_stale_entries",
                    stream=EVENT_STREAM,
                    count=len(claimed),
                )
                # 抢到的 entry 立即处理(避免只 claim 不消费的死信)
                for entry_id, fields in claimed:
                    try:
                        await _dispatch_event(fields)
                        await redis.xack(EVENT_STREAM, EVENT_CONSUMER_GROUP, entry_id)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "events_consumer_dispatch_stale_failed",
                            entry_id=entry_id,
                            error=str(exc),
                        )
                        # 仍 ack 防止永久 stale(失败由 dispatch_failed 监控告警)
                        try:
                            await redis.xack(EVENT_STREAM, EVENT_CONSUMER_GROUP, entry_id)
                        except Exception:
                            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("events_consumer_claim_stale_failed", error=str(exc))

        stop_event = _events_consumer_stop
        while stop_event is None or not stop_event.is_set():
            try:
                # 短阻塞读 2s,便于响应 stop_event
                msgs = await redis.xreadgroup(
                    groupname=EVENT_CONSUMER_GROUP,
                    consumername=consumer_name,
                    streams={EVENT_STREAM: ">"},
                    count=10,
                    block=2000,
                )
            except Exception as exc:
                # P1 修复(2026-08-06 全量测试):stream 在运行中被删除(运维清理
                # events:tasks)后 XREADGROUP 永久 NOGROUP——这里幂等重建 group,
                # 避免"报错-重试"死循环直到进程重启。
                if "NOGROUP" in str(exc):
                    try:
                        await redis.xgroup_create(
                            name=EVENT_STREAM,
                            groupname=EVENT_CONSUMER_GROUP,
                            id="$",
                            mkstream=True,
                        )
                        logger.info(
                            "events_consumer_group_recreated",
                            stream=EVENT_STREAM,
                            group=EVENT_CONSUMER_GROUP,
                        )
                        continue
                    except Exception as recreate_exc:  # noqa: BLE001
                        logger.warning(
                            "events_consumer_group_recreate_failed",
                            error=str(recreate_exc),
                        )
                else:
                    logger.warning("events_consumer_xreadgroup_error", error=str(exc))
                await asyncio.sleep(1)
                continue
            if not msgs:
                continue
            for _stream_name, entries in msgs:
                for entry_id, fields in entries:
                    try:
                        await _dispatch_event(fields)
                    except Exception as exc:
                        logger.exception(
                            "events_consumer_dispatch_failed",
                            entry_id=entry_id,
                            error=str(exc),
                        )
                    # 无论成功失败都 ack,失败由 DLQ 或 monitor 兜底
                    try:
                        await redis.xack(EVENT_STREAM, EVENT_CONSUMER_GROUP, entry_id)
                    except Exception as exc:
                        logger.warning(
                            "events_consumer_xack_failed",
                            entry_id=entry_id,
                            error=str(exc),
                        )
    finally:
        await redis.aclose()
        logger.info("events_consumer_stopped")


# 阶段 5 收尾 P6-monitor:周期扫队列 vs alert_config 阈值,超阈值结构化日志。
# 不主动丢弃任何任务 — 由用户通过 gateway /api/v1/vulnscan/tasks/release 决定。
async def _queue_alert_scan_loop() -> None:
    """周期扫 vulnscan:queue:tasks 状态,对照 PG queue_alert_config 阈值。

    触发条件(任一即发):
      - 堆积任务数 >= queued_threshold(默认 50)
      - 最老任务等待时长 >= oldest_age_sec(默认 30min)
    """
    from src.orchestration.task_queue.keys import STREAM_TASKS

    settings = get_settings()
    # 第一次启动立即扫一次,之后每 check_interval_sec 扫
    interval = 60
    while True:
        try:
            cfg = await _load_alert_cfg()
            if not cfg.scan_check_enabled:
                await asyncio.sleep(interval)
                continue
            interval = max(10, cfg.check_interval_sec)

            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            try:
                xlen = await r.xlen(STREAM_TASKS)
                try:
                    info = await r.xinfo_groups(STREAM_TASKS)
                    pending = int(info[0].get("pending", 0)) if info else 0
                except Exception:
                    pending = 0

                # 最老 entry age
                first = await r.xrange(STREAM_TASKS, count=1)
                oldest_age = 0.0
                if first:
                    ms_part = first[0][0].split("-", 1)[0]
                    try:
                        oldest_age = max(
                            0.0,
                            (int(time.time() * 1000) - int(ms_part)) / 1000.0,
                        )
                    except Exception:
                        pass

                # 阈值告警(结构化日志,前端可由 log pipeline 采集)
                if xlen >= cfg.queued_threshold:
                    logger.warning(
                        "queue_alert_queued_threshold_exceeded",
                        xlen=xlen,
                        threshold=cfg.queued_threshold,
                        pending=pending,
                    )
                if oldest_age >= cfg.oldest_age_sec:
                    logger.warning(
                        "queue_alert_oldest_age_exceeded",
                        oldest_age_sec=oldest_age,
                        threshold_sec=cfg.oldest_age_sec,
                        xlen=xlen,
                    )
                # 兜底:把 pending 量(> 0)与 xlen 比对,识别"消费慢"信号
                if pending > 0 and pending >= cfg.queued_threshold // 2:
                    logger.info(
                        "queue_alert_high_pending",
                        pending=pending,
                        xlen=xlen,
                    )
            finally:
                await r.aclose()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("queue_alert_scan_error", error=str(exc))

        await asyncio.sleep(interval)


async def _dispatch_event(fields: dict) -> None:
    """阶段 5 收尾:events:tasks payload 转 vulnscan 流水线输入并执行。

    payload schema(由 preprocessing.enqueue_event 写入):
        {
            "event_id": "kafka:1234-0",
            "body": "<json str: {sanitized_text, iocs, source, ts, ...}>",
            "enqueued_at": "2026-08-06T...",
        }
    """
    body_raw = fields.get("body")
    if not body_raw:
        return
    try:
        import json as _json

        body = _json.loads(body_raw) if isinstance(body_raw, str) else body_raw
    except Exception:
        return
    event_id = body.get("event_id") or fields.get("event_id", "unknown")
    sanitized_text = body.get("sanitized_text", "")
    iocs = body.get("iocs", {})
    source = body.get("source", "events:tasks")

    # 触发与 TaskWorker 相同的 LangGraph 流水线入口
    from src.orchestration.runner import run_pipeline

    await run_pipeline(event_id, sanitized_text, iocs, source)


# 阶段 5 收尾 P6-monitor:本地 alert cfg 数据类(避免从 src.api.routers.task_monitor
# 跨包 import — scan-engine 镜像只 COPY orchestration 与 task_queue 子树,不拖入整个 src.api)


@dataclass
class _LocalAlertCfg:
    queued_threshold: int = 50
    oldest_age_sec: int = 1800
    scan_check_enabled: bool = True
    check_interval_sec: int = 60


async def _load_alert_cfg() -> _LocalAlertCfg:
    """读 PG queue_alert_config 单行,带默认值兜底(表未初始化场景)。"""
    try:
        from src.common.db.pg import get_pg_pool

        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT queued_threshold, oldest_age_sec, scan_check_enabled, "
                "check_interval_sec FROM queue_alert_config WHERE id = 1"
            )
        if row is None:
            return _LocalAlertCfg()
        return _LocalAlertCfg(
            queued_threshold=int(row["queued_threshold"]),
            oldest_age_sec=int(row["oldest_age_sec"]),
            scan_check_enabled=bool(row["scan_check_enabled"]),
            check_interval_sec=int(row["check_interval_sec"]),
        )
    except Exception:
        return _LocalAlertCfg()


# 阶段 5 收尾:events:tasks payload 转 vulnscan 流水线输入并执行(被 events_consumer
# 与 queue_alert_scan_loop 中 claim_stale 路径调用)。
async def _dispatch_event(fields: dict) -> None:
    """payload schema(由 preprocessing.enqueue_event 写入):
        {
            "event_id": "kafka:1234-0",
            "body": "<json str: {sanitized_text, iocs, source, ts, ...}>",
            "enqueued_at": "2026-08-06T...",
        }
    """
    body_raw = fields.get("body")
    if not body_raw:
        return
    try:
        import json as _json

        body = _json.loads(body_raw) if isinstance(body_raw, str) else body_raw
    except Exception:
        return
    event_id = body.get("event_id") or fields.get("event_id", "unknown")
    sanitized_text = body.get("sanitized_text", "")
    iocs = body.get("iocs", {})
    source = body.get("source", "events:tasks")

    # 触发与 TaskWorker 相同的 LangGraph 流水线入口
    from src.orchestration.runner import run_pipeline

    await run_pipeline(event_id, sanitized_text, iocs, source)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """scan-engine lifespan:启动/停止 TaskWorker + (可选) events 消费者。

    阶段 5 收尾 P1-4:启动期调 init_schema()(幂等 IF NOT EXISTS),
    避免首次部署时 scan-engine 容器先于 gateway 启动导致 approvals 表不存在。
    init_schema 失败仅 warn 不阻断——gateway 通常也会启动并执行 schema,
    两者任意一个成功即可。
    """
    global _task_worker_handle, _events_consumer_task, _events_consumer_stop
    logger.info("scan_engine_starting")
    # P1-4:幂等 schema 初始化(避免首次部署 race)
    try:
        from src.common.db.pg import init_schema

        await init_schema()
        logger.info("scan_engine_pg_schema_ready")
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_engine_pg_schema_init_failed", error=str(exc))

    if not os.environ.get("DISABLE_TASK_WORKER"):
        try:
            # PEP 562 lazy:此处显式 import 才触发 worker.py 加载
            from src.orchestration.task_queue import TaskWorker

            worker = TaskWorker()
            _task_worker_handle = worker.start()
            logger.info(
                "taskworker_started",
                consumer=getattr(worker, "consumer", "unknown"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("taskworker_failed", error=str(exc))

    # P2-7:events:tasks Stream 消费者(默认开启,ENABLE_EVENTS_CONSUMER=false 关闭)
    if os.environ.get("ENABLE_EVENTS_CONSUMER", "true").lower() in ("1", "true", "yes"):
        _events_consumer_stop = asyncio.Event()
        _events_consumer_task = asyncio.create_task(
            _events_consumer_loop(), name="scan-engine-events-consumer"
        )

    # 阶段 5 收尾 P6-monitor:周期扫队列 vs alert_config 阈值,超阈值结构化日志
    # (不主动清空队列 — 由用户通过 release 端点决定;仅告警提示)
    if os.environ.get("ENABLE_QUEUE_ALERT_SCAN", "true").lower() in ("1", "true", "yes"):
        _queue_alert_task = asyncio.create_task(
            _queue_alert_scan_loop(), name="scan-engine-queue-alert-scan"
        )

    # 2026-08-06 LLM 分析监控:空闲补扫循环(失败批次重新分析,参数走 Nacos
    # llm_analysis_*;ENABLE_LLM_RESCAN=false 可关闭)
    if os.environ.get("ENABLE_LLM_RESCAN", "true").lower() in ("1", "true", "yes"):
        from src.scan_engine.llm_analysis import rescan_loop

        _llm_rescan_task = asyncio.create_task(
            rescan_loop(), name="scan-engine-llm-rescan"
        )
    yield
    # Shutdown
    if _events_consumer_stop is not None:
        _events_consumer_stop.set()
    if _events_consumer_task is not None:
        try:
            await asyncio.wait_for(_events_consumer_task, timeout=5.0)
        except (TimeoutError, asyncio.CancelledError):
            _events_consumer_task.cancel()
        except Exception as exc:  # noqa: BLE001
            logger.warning("events_consumer_shutdown_error", error=str(exc))
        _events_consumer_task = None
        _events_consumer_stop = None
    if _task_worker_handle is not None:
        try:
            await _task_worker_handle.stop(timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("taskworker_shutdown_failed", error=str(exc))

    # 阶段 5 收尾 P6-monitor:停 queue_alert_scan 后台 task
    if "_queue_alert_task" in globals() and _queue_alert_task is not None and not _queue_alert_task.done():
        _queue_alert_task.cancel()
        try:
            await asyncio.wait_for(_queue_alert_task, timeout=2.0)
        except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    logger.info("scan_engine_stopping")


app = FastAPI(
    title="secagent-scan-engine",
    version="0.1.0",
    description="LangGraph 流水线 + Redis Stream 消费 + 沙箱执行",
    lifespan=lifespan,
)

# 阶段 5 收尾 P2-8:scan-engine 埋了 taskworker_lag 指标,需要 /metrics 端点暴露
# (供 prometheus 抓取;若没接,指标写入也无效)
from src.common.metrics import metrics_router  # noqa: E402

app.include_router(metrics_router)


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict[str, Any]:
    """健康检查:TaskWorker 存活 + (可选) events consumer 存活。"""
    worker_alive = _task_worker_handle is not None
    consumer_alive = (
        _events_consumer_task is not None and not _events_consumer_task.done()
    )
    return {
        "status": "ok" if (worker_alive or consumer_alive) else "degraded",
        "service": "scan-engine",
        "task_worker_alive": worker_alive,
        "events_consumer_alive": consumer_alive,
    }
