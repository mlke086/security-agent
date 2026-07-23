"""Bridge between the queue envelope and the vulnscan subgraph.

Kept tiny on purpose: the worker just unpacks the envelope and calls the
existing ``run_vulnscan`` function, so we do NOT fork a second execution
path. If the subgraph grows new arguments later, add them to
``TaskEnvelope`` and forward them here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.task_queue.enqueue import TaskEnvelope
from src.orchestration.task_queue.keys import (
    STATUS_TTL_SEC,
    cancel_key,
    status_key,
)

logger = get_logger(__name__)


async def run_vulnscan_from_envelope(envelope: TaskEnvelope) -> dict:
    """Execute the vulnscan subgraph with the envelope\'s parameters.

    Updates the side-channel status key to ``running`` before calling the
    subgraph so callers polling ``GET /tasks/{id}`` see the transition
    immediately. Final status (completed / failed) is written by the
    subgraph itself via the vulnscan store.
    """
    # Mark running BEFORE the heavy work so the API can surface state.
    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        if await redis.exists(cancel_key(envelope.task_id)):
            await redis.set(
                status_key(envelope.task_id),
                _status_payload("cancelled", worker=_current_worker_name()),
                ex=STATUS_TTL_SEC,
            )
            logger.info("cancelled_task_skipped", task_id=envelope.task_id)
            return {"task_id": envelope.task_id, "status": "cancelled"}

        try:
            await redis.set(
                status_key(envelope.task_id),
                _status_payload("running", worker=_current_worker_name()),
                ex=STATUS_TTL_SEC,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "status_sidechannel_running_failed", task_id=envelope.task_id, error=str(exc)
            )

        # Local import: avoids pulling LangGraph in the API worker
        # process at startup (faster import for health checks).
        from src.orchestration.subgraphs.vulnscan.graph import run_vulnscan

        logger.info(
            "task_dequeued",
            task_id=envelope.task_id,
            engine=envelope.engine,
            targets=envelope.targets,
        )

        result = await run_vulnscan(
            source=envelope.source,
            intent_text=envelope.intent_text,
            targets=envelope.targets,
            modules=envelope.modules,
            task_id=envelope.task_id,
            engine=envelope.engine,
            nuclei_severity=envelope.nuclei_severity,
            nuclei_tags=envelope.nuclei_tags,
            nuclei_templates=envelope.nuclei_templates,
            nuclei_timeout_sec=envelope.nuclei_timeout_sec,
        )
        final_status = "completed"
        if result.get("status") == "cancelled" or await redis.exists(cancel_key(envelope.task_id)):
            final_status = "cancelled"
        try:
            await redis.set(
                status_key(envelope.task_id),
                _status_payload(final_status, worker=_current_worker_name()),
                ex=STATUS_TTL_SEC,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "status_sidechannel_final_failed", task_id=envelope.task_id, error=str(exc)
            )
        return result
    except Exception as exc:
        # Persist the failure to ES so GET /tasks/{id} reflects "failed".
        # Without this the ES record stays stuck on "scanning"/"analyzing"
        # and only the Redis side-channel (read when ES returns None) ever
        # sees "failed" (P1-VULN-03). Best-effort: if ES itself is the reason
        # the subgraph raised, this write may also fail -- swallow it so the
        # worker still re-raises and moves the message to DLQ.
        try:
            from src.agents.store import get_vulnscan_store

            await get_vulnscan_store().update_task(
                envelope.task_id,
                status="failed",
                error=str(exc)[:500],
                finished_at=datetime.now(UTC).isoformat(),
            )
        except Exception:  # noqa: BLE001
            logger.warning("task_failed_es_update_failed", task_id=envelope.task_id, error=str(exc))
        try:
            await redis.set(
                status_key(envelope.task_id),
                _status_payload("failed", worker=_current_worker_name(), error=str(exc)),
                ex=STATUS_TTL_SEC,
            )
        except Exception:  # noqa: BLE001
            pass
        logger.error("task_failed", task_id=envelope.task_id, error=str(exc))
        raise
    finally:
        await redis.aclose()


def _status_payload(status: str, *, worker: str = "", error: str = "") -> str:
    import json

    payload = {"status": status, "worker": worker, "ts": datetime.now(UTC).isoformat()}
    if error:
        payload["error"] = error[:500]
    return json.dumps(payload, ensure_ascii=False)


def _current_worker_name() -> str:
    import os
    import socket

    return f"{socket.gethostname()}-{os.getpid()}"
