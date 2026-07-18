"""Celery app for async tasks (HITL timeouts, etc)."""
from celery import Celery

from src.common.config.settings import get_settings

settings = get_settings()
celery_app = Celery(
    "security-agent",
    broker=settings.redis_url,
    backend=settings.redis_url,
    task_serializer="json",
    accept_content=["json"],
)

celery_app.conf.task_default_queue = "security-agent-tasks"


@celery_app.task(bind=True, max_retries=3)  # type: ignore[misc]
def approval_timeout_task(self, approval_id: str, timeout_sec: int):
    import asyncio

    from src.orchestration.subgraphs.responder.approval_store import get_approval_store
    store = get_approval_store()
    asyncio.run(store.resolve(approval_id, "timeout"))
    return {"approval_id": approval_id, "status": "timeout"}
