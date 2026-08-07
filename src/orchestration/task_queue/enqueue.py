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
from typing import Any, cast

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.task_queue.keys import (
    STATUS_TTL_SEC,
    STREAM_ASSET_TASKS,
    STREAM_TASKS,
    asset_status_key,
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
    nuclei_ports: list[int] = field(default_factory=list)
    nuclei_severity: list[str] = field(default_factory=list)
    nuclei_tags: list[str] = field(default_factory=list)
    nuclei_templates: list[str] = field(default_factory=list)
    nuclei_timeout_sec: int = 0
    actor: str = ""
    submitted_at: str = ""
    # 2026-07-29 UX upgrade: business groups for the targets, computed
    # by the API router at enqueue time and persisted with the task so
    # /tasks list can render the column without joining hosts.
    target_groups: list[str] = field(default_factory=list)
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


@dataclass
class AssetScanEnvelope:
    """Serialised request to run the asset-scan subgraph (需求②).

    Mirrors ``subgraphs.asset_scan.graph.run_asset_scan`` kwargs. Fields:

    - ``targets``: CIDR / single IP strings, e.g. ["10.0.0.0/24", "10.0.1.5"].
    - ``ports``: explicit port list when engine != "full"; empty = engine
      default (full scans 1-65535, fast scans top-1000).
    - ``engine``: "fast" | "full" | "global" (masscan rate / nmap ranges).
    - ``modules``: scan modules, e.g. ["discovery", "fingerprint", "cve",
      "nuclei", "brute"]; "brute" is off by default.
    - ``schedule``: optional cron expression for periodic runs (v2).
    """

    task_id: str
    source: str
    targets: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    engine: str = "fast"
    modules: list[str] = field(default_factory=lambda: ["discovery", "fingerprint", "cve", "nuclei"])
    schedule: str = ""
    actor: str = ""
    submitted_at: str = ""
    submitted_by: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str | bytes) -> AssetScanEnvelope:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return cls.from_dict(json.loads(raw))

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> AssetScanEnvelope:
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
    nuclei_ports: list[int] | None = None,
    nuclei_tags: list[str] | None = None,
    nuclei_templates: list[str] | None = None,
    nuclei_timeout_sec: int = 0,
    actor: str = "",
    task_id: str | None = None,
    # 2026-07-29 UX upgrade: business groups for the targets, computed
    # at enqueue time and persisted on the ScanTask so /tasks list
    # can render the column without a host join.
    target_groups: list[str] | None = None,
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
        nuclei_ports=nuclei_ports or [],
        target_groups=list(target_groups or []),
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
        # cast: dict is invariant in its key/value types, but redis accepts any
        # str/int key and str/int/float/bytes value -- widen for mypy only.
        await redis.xadd(STREAM_TASKS, cast(dict, payload), maxlen=10_000, approximate=True)
        # Side-channel status. Best-effort: if Redis is down, the user
        # still gets the task_id and the worker will recover via ES.
        try:
            await redis.set(
                status_key(envelope.task_id),
                json.dumps(
                    {
                        "status": "queued",
                        "actor": actor,
                        "source": envelope.source,
                        "targets": envelope.targets,
                        "submitted_at": envelope.submitted_at,
                    }
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


async def enqueue_asset_task(
    *,
    source: str,
    targets: list[str],
    ports: list[int] | None = None,
    engine: str = "fast",
    modules: list[str] | None = None,
    schedule: str = "",
    actor: str = "",
    task_id: str | None = None,
) -> AssetScanEnvelope:
    """Push an asset-scan envelope onto the assetscan stream (需求②).

    Mirrors ``enqueue_task``: XADD to ``assetscan:queue:tasks`` (bounded
    MAXLEN 10k) + short-lived queued status side-channel. The asset-scan
    service's TaskWorker consumes this stream with its own group
    ``asset-scan-workers``.
    """
    envelope = AssetScanEnvelope(
        task_id=task_id or str(uuid.uuid4()),
        source=source,
        targets=list(targets),
        ports=list(ports or []),
        engine=engine,
        modules=list(modules or ["discovery", "fingerprint", "cve", "nuclei"]),
        schedule=schedule,
        actor=actor,
        submitted_at=datetime.now(UTC).isoformat(),
        submitted_by=socket.gethostname(),
    )

    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        # P3-F fix (2026-08-07, race condition): 先写 ES 再 xadd stream.
        # 旧顺序: xadd → runner 立即 XREADGROUP → update_task → ES doc_missing.
        # 因为 runner 与 enqueue 并发, save_task 还没传到 ES runner 就 update.
        # 改为 save_task → xadd, 保证 worker 看到 entry 时 doc 必然存在.
        try:
            from src.asset_scan.store import get_asset_store

            now = datetime.now(UTC).isoformat()
            await get_asset_store().save_task(
                {
                    "task_id": envelope.task_id,
                    "source": envelope.source,
                    "targets": envelope.targets,
                    "ports": envelope.ports,
                    "engine": envelope.engine,
                    "modules": envelope.modules,
                    "schedule": envelope.schedule,
                    "actor": actor,
                    "status": "queued",
                    "created_at": now,
                    "updated_at": now,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "asset_es_task_write_failed",
                task_id=envelope.task_id,
                error=str(exc),
            )
        payload: dict[str, str] = {
            "envelope": envelope.to_json(),
            "task_id": envelope.task_id,
            "engine": envelope.engine,
        }
        await redis.xadd(
            STREAM_ASSET_TASKS, cast(dict, payload), maxlen=10_000, approximate=True
        )
        try:
            await redis.set(
                asset_status_key(envelope.task_id),
                json.dumps(
                    {
                        "status": "queued",
                        "actor": actor,
                        "source": envelope.source,
                        "targets": envelope.targets,
                        "engine": envelope.engine,
                        "submitted_at": envelope.submitted_at,
                    }
                ),
                ex=STATUS_TTL_SEC,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "asset_status_sidechannel_write_failed",
                task_id=envelope.task_id,
                error=str(exc),
            )
        logger.info(
            "asset_task_enqueued",
            task_id=envelope.task_id,
            engine=envelope.engine,
            targets=envelope.targets,
        )
    finally:
        await redis.aclose()

    return envelope
