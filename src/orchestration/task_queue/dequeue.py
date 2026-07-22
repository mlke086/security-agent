"""Dequeue helpers used by ``TaskWorker``.

Three responsibilities live here:

1. ``read_message_blocking`` -- XREADGROUP ``BLOCK`` until a new entry
   arrives or the timeout fires (long-poll).
2. ``ack_message`` -- XACK after the worker has finished subgraph exec.
3. ``claim_stale`` -- XAUTOCLAIM so a dead worker\'s pending entries get
   reassigned to a live one without operator intervention.

The consumer group is created lazily on the first call -- Redis\'s
``MKSTREAM`` lets ``XGROUP CREATE`` succeed even when the stream is empty.
"""

from __future__ import annotations

import os
import socket
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.task_queue.keys import (
    CONSUMER_GROUP,
    STREAM_DLQ,
    STREAM_TASKS,
)

logger = get_logger(__name__)

# XAUTOCLAIM looks back this many ms when grabbing stale entries. Picked
# to be larger than the typical vulnscan run (10 minutes) so a worker
# that\'s actively processing doesn\'t have its entry stolen out from
# under it; shorter than the operator\'s patience for "the queue is
# stuck" complaints.
STALE_CLAIM_MIN_IDLE_MS = 600_000  # 10 minutes

# A single entry may be redelivered at most this many times before the
# worker sends it to the DLQ stream.
MAX_DELIVERY = 3


def consumer_name() -> str:
    """Stable per-process consumer name so XAUTOCLAIM skips ourselves."""
    return f"worker-{socket.gethostname()}-{os.getpid()}"


async def ensure_group(redis: aioredis.Redis) -> None:
    from src.common.logging.logger import get_logger

    _log = get_logger(__name__)
    _log.info("ensure_group_start", stream=STREAM_TASKS, group=CONSUMER_GROUP)
    try:
        await redis.xgroup_create(
            name=STREAM_TASKS,
            groupname=CONSUMER_GROUP,
            id="0",
            mkstream=True,
        )
        _log.info("ensure_group_created", group=CONSUMER_GROUP)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            _log.error("ensure_group_failed", error=str(exc))
            raise
        _log.info("ensure_group_busygroup", group=CONSUMER_GROUP)


async def read_message_blocking(
    redis: aioredis.Redis,
    *,
    consumer: str,
    block_ms: int = 5000,
    count: int = 1,
) -> tuple[str, dict[str, Any]] | None:
    """Block until a new entry is available.

    Returns ``(entry_id, payload)`` or ``None`` on timeout. The ``id``
    field of the payload is what XACK needs to acknowledge.
    """
    resp = await redis.xreadgroup(
        groupname=CONSUMER_GROUP,
        consumername=consumer,
        streams={STREAM_TASKS: ">"},
        count=count,
        block=block_ms,
    )
    if not resp:
        return None
    # resp is [(stream_name, [(id, payload), ...]), ...]
    _stream_name, entries = resp[0]
    if not entries:
        return None
    entry_id, payload = entries[0]
    return entry_id, payload


async def ack_message(redis: aioredis.Redis, entry_id: str) -> None:
    """Acknowledge successful processing so the entry leaves PEL."""
    try:
        await redis.xack(STREAM_TASKS, CONSUMER_GROUP, entry_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("xack_failed", entry_id=entry_id, error=str(exc))


async def claim_stale(
    redis: aioredis.Redis,
    *,
    consumer: str,
    min_idle_ms: int = STALE_CLAIM_MIN_IDLE_MS,
) -> tuple[str, dict[str, Any]] | None:
    """Take ownership of an entry that\'s been idle too long.

    Returns ``(entry_id, payload)`` or ``None`` if nothing is stale. The
    caller is responsible for tracking how many times a single entry has
    been redelivered; after ``MAX_DELIVERY`` moves to DLQ.
    """
    try:
        resp = await redis.xautoclaim(
            name=STREAM_TASKS,
            groupname=CONSUMER_GROUP,
            consumername=consumer,
            min_idle_time=min_idle_ms,
            start_id="0-0",
            count=1,
        )
    except ResponseError:
        return None
    # xautoclaim returns [next_cursor, [(id, payload), ...], deleted_ids]
    if not resp or len(resp) < 2 or not resp[1]:
        return None
    entry_id, payload = resp[1][0]
    return entry_id, payload


async def pending_count(redis: aioredis.Redis) -> int:
    """How many entries are stuck in the PEL (delivered but not ACKed).

    Used by tests and the /health surface. Returns 0 on error so callers
    never have to wrap in try/except.
    """
    try:
        info = await redis.xpending(STREAM_TASKS, CONSUMER_GROUP)
        # info is a dict {"pending": N, "min": id, "max": id, "consumers": [...]}
        if isinstance(info, dict):
            return int(info.get("pending", 0))
        # redis-py sometimes returns a tuple for the summary form
        if isinstance(info, list | tuple) and info:
            return int(info[0] or 0)
    except Exception:  # noqa: BLE001
        return 0
    return 0


async def stream_depth(redis: aioredis.Redis) -> int:
    """Number of entries currently in the stream (XLEN).

    Includes both undelivered and delivered-but-unacked entries. The
    caller can subtract ``pending_count()`` to get just the queue depth.
    """
    try:
        return int(await redis.xlen(STREAM_TASKS))
    except Exception:  # noqa: BLE001
        return 0


async def move_to_dlq(
    redis: aioredis.Redis, entry_id: str, payload: dict[str, Any], reason: str
) -> None:
    """Push the payload to the DLQ stream and ACK the original.

    Splitting ACK and XADD keeps a failed write from masking the entry --
    if DLQ write fails the entry remains in the PEL and will be retried.
    """
    try:
        # V4.1: build the XADD fields through a typed local so mypy can unify
        # with redis-py's narrow Dict[str, str|bytes|int|float|...] stub.
        # payload: dict[str, Any] alone is too wide (Any does not satisfy
        # the strict union even though every value in practice is JSON-serialisable).
        dlq_fields: dict[str, str] = {
            "original_id": str(entry_id),
            "dlq_reason": str(reason),
        }
        for k, v in payload.items():
            dlq_fields[k] = "" if v is None else str(v)
        # redis-py's StreamCommands.xadd stub types fields as
        # Dict[Union[bytes, memoryview, str, int, float], ...]; mypy treats
        # dict as invariant so dict[str, str] does not unify with the wider
        # union even though str is a member. We pre-coerce every value to
        # str at the dict-build loop above, so the runtime payload matches.
        await redis.xadd(STREAM_DLQ, dlq_fields)  # type: ignore[arg-type]
        await redis.xack(STREAM_TASKS, CONSUMER_GROUP, entry_id)
        logger.warning("task_moved_to_dlq", entry_id=entry_id, reason=reason)
    except Exception as exc:  # noqa: BLE001
        logger.error("dlq_move_failed", entry_id=entry_id, error=str(exc))


async def delivery_count(redis: aioredis.Redis, entry_id: str) -> int:
    """How many times an entry has been delivered to *any* consumer.

    Used by the worker to decide when to give up and DLQ. Returns 0 when
    the entry id is no longer in the PEL.
    """
    try:
        info = await redis.xpending_range(
            STREAM_TASKS,
            CONSUMER_GROUP,
            min=entry_id,
            max=entry_id,
            count=1,
        )
    except ResponseError:
        return 0
    if not info:
        return 0
    # Each item in info is a dict with ``times_delivered`` etc.
    try:
        return int(info[0].get("times_delivered", 0))
    except (AttributeError, IndexError, TypeError):
        return 0


def get_redis() -> aioredis.Redis:
    """Helper for tests so they can poke the same connection settings."""
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)
