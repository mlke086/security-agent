"""阶段 5 收尾 P6-monitor:LLM 队列监控 API。

提供:
  - GET  /api/v1/vulnscan/tasks/stats
        状态分布统计(queued/scanning/completed/failed/cancelled) + 时间序列
  - GET  /api/v1/vulnscan/tasks/queue-status
        Redis stream 端状态(xlen / pending / DLQ / oldest age)
  - GET  /api/v1/vulnscan/tasks/alert-config
        告警阈值配置读取
  - PUT  /api/v1/vulnscan/tasks/alert-config
        告警阈值配置更新
  - POST /api/v1/vulnscan/tasks/release
        单个释放:删 ES + 清 Redis stream + 清 status_key(scanning 中拒)
  - POST /api/v1/vulnscan/tasks/release-batch
        批量释放,逐条返回成功/失败明细(由用户决定)

设计原则:
  - **不自动丢弃任何任务** — 堆积由用户通过 release API 显式决定去留
  - **scanning 状态拒绝** — 避免误杀正在处理的任务
  - 删 Redis stream 消息前先 XACK 消费者 PEL(避免 worker 重新 claim)
  - 默认 admin 权限(破坏性操作)

存储:
  - 任务主数据:Elasticsearch(via VulnscanStore)
  - 队列消息:Redis Stream(vulnscan:queue:tasks)
  - 短期状态:Redis status_key + side-channel
  - 告警阈值:PG table queue_alert_config(单行)
"""
from __future__ import annotations

import time

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.agents.store import get_vulnscan_store
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.db.pg import get_pg_pool
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/vulnscan/tasks", tags=["queue-monitor"])


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
class StatusCount(BaseModel):
    status: str
    count: int


@router.get("/stats", response_model=list[StatusCount])
async def task_stats(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> list[StatusCount]:
    """按状态分组的任务计数(从 ES task 索引)。"""
    store = get_vulnscan_store()
    statuses = ["queued", "scanning", "completed", "failed", "cancelled"]
    out: list[StatusCount] = []
    for s in statuses:
        n = await store.count_tasks(status=s)
        out.append(StatusCount(status=s, count=n))
    return out


# ---------------------------------------------------------------------------
# Queue status (Redis side)
# ---------------------------------------------------------------------------
class QueueStatus(BaseModel):
    stream: str
    xlen: int
    pending: int
    pending_consumers: int
    dlq_xlen: int
    dlq_stream: str
    oldest_entry_id: str | None
    oldest_entry_age_sec: float | None
    enabled: bool


@router.get("/queue-status", response_model=QueueStatus)
async def queue_status(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> QueueStatus:
    """Redis Stream 端队列状态(由 scan-engine 读而非 gateway 推;admin 主动查询)。"""
    from src.orchestration.task_queue.keys import (
        STREAM_DLQ,
        STREAM_TASKS,
    )

    settings = get_settings()
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        xlen = await r.xlen(STREAM_TASKS)
        try:
            info = await r.xinfo_groups(STREAM_TASKS)
            group = info[0] if info else {}
        except Exception:
            group = {}
        pending = int(group.get("pending", 0) or 0)
        consumers = int(group.get("consumers", 0) or 0)
        # DLQ(若存在)
        dlq_xlen = 0
        try:
            dlq_xlen = await r.xlen(STREAM_DLQ)
        except Exception:
            dlq_xlen = 0
        # 最老 entry_id + age
        oldest_id: str | None = None
        oldest_age: float | None = None
        try:
            first = await r.xrange(STREAM_TASKS, count=1)
            if first:
                oldest_id = first[0][0]
                ms_part = oldest_id.split("-", 1)[0]
                entry_ms = int(ms_part)
                now_ms = int(time.time() * 1000)
                oldest_age = max(0.0, (now_ms - entry_ms) / 1000.0)
        except Exception:
            pass
        return QueueStatus(
            stream=STREAM_TASKS,
            xlen=xlen,
            pending=pending,
            pending_consumers=consumers,
            dlq_xlen=dlq_xlen,
            dlq_stream=STREAM_DLQ,
            oldest_entry_id=oldest_id,
            oldest_entry_age_sec=oldest_age,
            enabled=True,
        )
    finally:
        await r.aclose()


# ---------------------------------------------------------------------------
# Release task (单个 + 批量)
# ---------------------------------------------------------------------------
class ReleaseResultItem(BaseModel):
    task_id: str
    status: str  # released / not_found / busy_scanning / error
    detail: str | None = None


class ReleaseRequest(BaseModel):
    task_ids: list[str] = Field(..., min_length=1, max_length=500)


class ReleaseResponse(BaseModel):
    items: list[ReleaseResultItem]
    released: int
    failed: int
    busy: int
    not_found: int


async def _release_one(
    task_id: str,
    actor: str,
) -> ReleaseResultItem:
    """单个任务释放:删 ES + 清 Redis stream + 清 status_key。

    仅当 ES 中 status in (queued, failed, cancelled) 时放行;scanning 拒绝。
    找不到(task 不在 ES) 视为 not_found。
    """
    from src.orchestration.task_queue.keys import (
        CONSUMER_GROUP,
        STREAM_TASKS,
        status_key,
    )

    store = get_vulnscan_store()
    try:
        task = await store.get_task(task_id)
    except Exception as exc:
        logger.warning("release_get_task_failed", task_id=task_id, error=str(exc))
        return ReleaseResultItem(task_id=task_id, status="error", detail=str(exc))

    if task is None:
        return ReleaseResultItem(task_id=task_id, status="not_found")

    # 拒绝 scanning 状态(避免误杀正在跑的任务)
    cur_status = (task.status or "").lower()
    if cur_status in ("scanning", "running"):
        return ReleaseResultItem(
            task_id=task_id,
            status="busy_scanning",
            detail=f"task is currently {task.status}; refuse to release while scanning",
        )

    # 删 ES 记录
    try:
        await store.delete_task(task_id)
    except Exception as exc:
        return ReleaseResultItem(task_id=task_id, status="error", detail=f"es delete: {exc}")

    # 清 Redis side-channel status_key
    settings = get_settings()
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        await r.delete(status_key(task_id))
        # 清 stream 消息(若有)。XDEL 不存在的 entry 不报错。
        # 不能 XACK(stale entry 还在 PEL 但不删除);XACK 也清 PEL
        # + 我们再 XDEL stream entry 避免 worker 重新读到。
        try:
            # 找 task_id 对应的 stream entry_id(envelope 写入时 payload 含 task_id)
            # P2 修复:循环翻页扫 stream(count=500/页),避免 count=200 快照
            # 漏掉 >200 条队列里更旧的 entry → ES 已删但 stream 消息残留、
            # worker 后续可能重新读到。翻页用开区间 max="(<cursor>" 排除已扫。
            target_entries: list[str] = []
            cursor: str | None = None
            pages = 0
            while pages < 20:  # 上限 20 页 = 10000 条,防恶意超长队列死循环
                if cursor is None:
                    entries = await r.xrevrange(STREAM_TASKS, count=500)
                else:
                    entries = await r.xrevrange(STREAM_TASKS, max=f"({cursor}", count=500)
                if not entries:
                    break
                for eid, fields in entries:
                    if fields.get("task_id") == task_id:
                        target_entries.append(eid)
                cursor = entries[-1][0]
                pages += 1
                if len(entries) < 500:
                    break
            for eid in target_entries:
                await r.xack(STREAM_TASKS, CONSUMER_GROUP, eid)
                await r.xdel(STREAM_TASKS, eid)
        except Exception as exc:
            logger.warning(
                "release_stream_cleanup_partial",
                task_id=task_id,
                error=str(exc),
            )
    finally:
        await r.aclose()

    await get_audit_logger().log(
        event_id=task_id,
        node="vulnscan.queue_monitor",
        action="release_task",
        actor=actor,
        details={"task_id": task_id, "previous_status": task.status},
    )
    return ReleaseResultItem(task_id=task_id, status="released")


@router.post("/release", response_model=ReleaseResultItem)
async def release_task(
    request: Request,
    task_id: str = "",
    current_user=Depends(require_role("admin")),
) -> ReleaseResultItem:
    """单个释放(路径用 query 参数,保持 OpenAPI 简单)。

    也支持 ``POST /release {task_ids: [...]}`` 形式(批量)— 见 release-batch。
    """
    if not task_id:
        body = await request.json()
        task_id = body.get("task_id", "")
    if not task_id:
        raise HTTPException(status_code=400, detail="task_id required (query or JSON body)")
    return await _release_one(task_id, actor=current_user.username)


@router.post("/release-batch", response_model=ReleaseResponse)
async def release_tasks_batch(
    req: ReleaseRequest,
    current_user=Depends(require_role("admin")),
) -> ReleaseResponse:
    """批量释放(逐条结果,用户决定堆积的去留)。

    不会"全部成功/全部失败"——返回每条 status,前端按需展示。
    """
    items: list[ReleaseResultItem] = []
    for tid in req.task_ids:
        items.append(await _release_one(tid, actor=current_user.username))
    released = sum(1 for i in items if i.status == "released")
    failed = sum(1 for i in items if i.status == "error")
    busy = sum(1 for i in items if i.status == "busy_scanning")
    not_found = sum(1 for i in items if i.status == "not_found")
    return ReleaseResponse(
        items=items,
        released=released,
        failed=failed,
        busy=busy,
        not_found=not_found,
    )


# ---------------------------------------------------------------------------
# Alert config
# ---------------------------------------------------------------------------
class AlertConfig(BaseModel):
    queued_threshold: int = Field(50, ge=1, le=10000, description="堆积任务数阈值")
    oldest_age_sec: int = Field(1800, ge=60, le=86400, description="最老任务等待秒数阈值")
    scan_check_enabled: bool = Field(True, description="是否启用周期扫描")
    check_interval_sec: int = Field(60, ge=10, le=3600, description="扫描间隔(秒)")
    updated_at: str | None = None
    updated_by: str | None = None


async def _load_alert_config() -> AlertConfig:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT queued_threshold, oldest_age_sec, scan_check_enabled, "
            "check_interval_sec, updated_at, updated_by "
            "FROM queue_alert_config WHERE id = 1"
        )
    if row is None:
        return AlertConfig()
    return AlertConfig(
        queued_threshold=int(row["queued_threshold"]),
        oldest_age_sec=int(row["oldest_age_sec"]),
        scan_check_enabled=bool(row["scan_check_enabled"]),
        check_interval_sec=int(row["check_interval_sec"]),
        updated_at=row["updated_at"].isoformat() if row["updated_at"] else None,
        updated_by=row["updated_by"],
    )


@router.get("/alert-config", response_model=AlertConfig)
async def get_alert_config(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> AlertConfig:
    return await _load_alert_config()


@router.put("/alert-config", response_model=AlertConfig)
async def put_alert_config(
    cfg: AlertConfig,
    current_user=Depends(require_role("admin")),
) -> AlertConfig:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE queue_alert_config SET "
            "queued_threshold = $1, oldest_age_sec = $2, scan_check_enabled = $3, "
            "check_interval_sec = $4, updated_at = NOW(), updated_by = $5 "
            "WHERE id = 1",
            cfg.queued_threshold,
            cfg.oldest_age_sec,
            cfg.scan_check_enabled,
            cfg.check_interval_sec,
            current_user.username,
        )
    await get_audit_logger().log(
        event_id="queue-alert-config",
        node="vulnscan.queue_monitor",
        action="update_alert_config",
        actor=current_user.username,
        details=cfg.model_dump(),
    )
    return await _load_alert_config()


__all__ = ["router"]
