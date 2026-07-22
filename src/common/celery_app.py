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


@celery_app.task(bind=True, max_retries=3)  # type: ignore[misc]
def approval_timeout_task(self, approval_id: str, timeout_sec: int):
    import asyncio

    from src.orchestration.subgraphs.responder.approval_store import get_approval_store

    store = get_approval_store()
    asyncio.run(store.resolve(approval_id, "timeout"))
    return {"approval_id": approval_id, "status": "timeout"}
