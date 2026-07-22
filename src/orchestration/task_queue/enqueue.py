"""Enqueue vulnscan tasks onto the Redis Streams queue.

The API route ``POST /api/v1/vulnscan/tasks`` calls ``enqueue_task`` and
returns the generated ``task_id`` immediately -- the subgraph no longer
runs in the request goroutine, the worker does.
"""

from __future__ import annotations

import json
import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.task_queue.keys import (
    STATUS_TTL_SEC,
    STREAM_TASKS,
    status_key,
)

logger = get_logger(__name__)


@dataclass
class TaskEnvelope:
    """Serialised request to run the vulnscan subgraph.

    Every field the subgraph needs is captured here so the worker can run
    it without any other side-channel. The shape mirrors the kwargs of
    ``subgraphs.vulnscan.graph.run_vulnscan`` -- a future change to that
    function signature should be reflected here.

    P2 (2026-07-18): introduced so the API can ``XADD`` and return 200
    without awaiting subgraph execution.
    """

    task_id: str
    source: str
    intent_text: str | None = None
    targets: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=lambda: ["sys_vuln", "baseline"])
    engine: str = "matcher"
    nuclei_severity: list[str] = field(default_factory=list)
    nuclei_tags: list[str] = field(default_factory=list)
    nuclei_templates: list[str] = field(default_factory=list)
    nuclei_timeout_sec: int = 0
    actor: str = ""
    submitted_at: str = ""
    submitted_by: str = ""  # hostname of the API worker that enqueued

    def to_json(self) -> str:
        """Serialise to JSON for the XADD payload field."""
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str | bytes) -> TaskEnvelope:
        """Reverse of ``to_json``. Accepts ``bytes`` (XREAD returns bytes)
        and ``str`` (in-process dict literals from tests)."""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        obj: dict[str, Any] = json.loads(raw)
        # Filter to known fields so a future schema bump doesn't crash
        # older workers; ``from_dict`` below is forgiving by construction.
        return cls.from_dict(obj)

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> TaskEnvelope:
        """Build from a plain dict. Unknown keys are silently dropped."""
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in obj.items() if k in allowed})


async def enqueue_task(
    *,
    source: str,
    targets: list[str] | None = None,
    intent_text: str | None = None,
    modules: list[str] | None = None,
    engine: str = "matcher",
    nuclei_severity: list[str] | None = None,
    nuclei_tags: list[str] | None = None,
    nuclei_templates: list[str] | None = None,
    nuclei_timeout_sec: int = 0,
    actor: str = "",
    task_id: str | None = None,
) -> TaskEnvelope:
    """Push a task envelope onto the Redis Stream and return it.

    A short-lived status side-channel key is written so the API can serve
    ``GET /api/v1/vulnscan/tasks/{id}`` a meaningful state (``queued``)
    before the worker has had a chance to pick it up.

    Returns the envelope so the caller can echo ``task_id`` back to the
    user without re-generating it.
    """
    envelope = TaskEnvelope(
        task_id=task_id or str(uuid.uuid4()),
        source=source,
        intent_text=intent_text,
        targets=targets or [],
        modules=modules or ["sys_vuln", "baseline"],
        engine=engine,
        nuclei_severity=nuclei_severity or [],
        nuclei_tags=nuclei_tags or [],
        nuclei_templates=nuclei_templates or [],
        nuclei_timeout_sec=int(nuclei_timeout_sec or 0),
        actor=actor,
        submitted_at=datetime.now(UTC).isoformat(),
        submitted_by=socket.gethostname(),
    )

    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        # XADD with ``*`` lets Redis assign the entry id; we don't need to
        # care about the exact value -- the consumer reads by group/stream.
        payload: dict[str, str] = {
            "envelope": envelope.to_json(),
            "task_id": envelope.task_id,
            "engine": envelope.engine,
        }
        # P2-VULN-07 (2026-07-19): bound the stream with MAXLEN ~ 10000 so a
        # runaway producer (or a paused worker that keeps accumulating) does
        # not OOM Redis. The approximate trim (~) is O(1) and good enough
        # for back-pressure on a long-lived stream.
        await redis.xadd(STREAM_TASKS, payload, maxlen=10_000, approximate=True)
        # Side-channel status. Best-effort: if Redis is down, the user
        # still gets the task_id and the worker will recover via ES.
        try:
            await redis.set(
                status_key(envelope.task_id),
                json.dumps(
                    {"status": "queued", "actor": actor, "submitted_at": envelope.submitted_at}
                ),
                ex=STATUS_TTL_SEC,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "status_sidechannel_write_failed", task_id=envelope.task_id, error=str(exc)
            )
        logger.info(
            "task_enqueued",
            task_id=envelope.task_id,
            engine=envelope.engine,
            targets=envelope.targets,
        )
    finally:
        await redis.aclose()

    return envelope
