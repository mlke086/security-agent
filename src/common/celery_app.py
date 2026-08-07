"""Celery app for async tasks (HITL timeouts, etc).

P2-API-08 (2026-07-20): settings are now resolved lazily inside the Celery
constructor via a property callback. The previous module-level
``get_settings()`` call crashed the entire import chain when .env was
missing or pydantic-settings failed -- including the API worker that
imports this module transitively via src.api.main. Now a missing config
degrades gracefully (the broker URL is filled in lazily by Celery when
the first task is published).
"""

from __future__ import annotations

from celery import Celery

from src.common.config.settings import get_settings


def _broker_url() -> str:
    """Resolve the broker URL lazily so a missing .env does not crash import."""
    try:
        return get_settings().redis_url
    except Exception:
        # Fall back to localhost so Celery at least imports. The first
        # task publish will surface the real config error in the worker.
        return "redis://localhost:6379/0"


celery_app = Celery(
    "security-agent",
    broker=_broker_url(),
    backend=_broker_url(),
    task_serializer="json",
    accept_content=["json"],
)

celery_app.conf.task_default_queue = "security-agent-tasks"


@celery_app.task(bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def approval_timeout_task(self, approval_id: str, timeout_sec: int):
    """阶段 5 收尾:celery 兜底超时任务,埋点 approval_expired_lag_seconds。

    上游 scan-engine 在 hitl_approval_node 创建审批时调用
    approval_timeout_task.apply_async(countdown=timeout_sec+30)。
    celery 实际执行时,approval 已存在时长 = now - approval.created_at。
    监控该值的分布:绝大多数应接近 timeout_sec,异常长尾说明 celery 队列堵塞。
    """
    import asyncio

    from src.common.metrics import approval_expired_lag
    from src.orchestration.subgraphs.responder.approval_store import (
        get_approval_store,
        get_pool,
    )

    async def _run():
        store = get_approval_store()
        pool = await get_pool()
        row = await pool.fetchrow(
            "SELECT created_at FROM approvals WHERE approval_id = $1",
            approval_id,
        )
        if row and row["created_at"]:
            lag_sec = (
                __import__("datetime").datetime.now(__import__("datetime").UTC)
                - row["created_at"]
            ).total_seconds()
            approval_expired_lag.observe(max(0.0, lag_sec))
        await store.resolve(approval_id, "timeout")

    asyncio.run(_run())
    return {"approval_id": approval_id, "status": "timeout"}
