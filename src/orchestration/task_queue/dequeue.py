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
from typing import Any, cast

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

# XAUTOCLAIM looks back this many ms when grabbing stale entries. V13
# P1-6: the default vulnscan timeout is 1800s (30 min) and collect waits
# on the agent for most of that, so a 10-minute idle threshold let a
# second worker XAUTOCLAIM a *running* task's entry -> duplicate
# dispatch, duplicate scan_command and double-written reports. Keep the
# threshold above the longest task so only entries from genuinely dead
# workers are reclaimed (operator patience for a stuck queue is handled
# by MAX_DELIVERY + the DLQ).
STALE_CLAIM_MIN_IDLE_MS = 3_600_000  # 60 minutes > max task timeout

# A single entry may be redelivered at most this many times before the
# worker sends it to the DLQ stream.
MAX_DELIVERY = 3


def consumer_name() -> str:
    """Stable per-process consumer name so XAUTOCLAIM skips ourselves."""
    return f"worker-{socket.gethostname()}-{os.getpid()}"


async def ensure_group(
    redis: aioredis.Redis,
    *,
    stream: str | None = None,
    group: str | None = None,
) -> None:
    """Create the consumer group for ``stream`` if missing (idempotent).

    P3-A (需求②): stream/group 参数化, 默认 vulnscan 队列, 向后兼容。
    asset-scan 服务用同一个函数建自己的 group。
    """
    from src.common.logging.logger import get_logger

    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    _log = get_logger(__name__)
    _log.info("ensure_group_start", stream=stream, group=group)
    try:
        await redis.xgroup_create(
            name=stream,
            groupname=group,
            id="0",
            mkstream=True,
        )
        _log.info("ensure_group_created", group=group)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            _log.error("ensure_group_failed", error=str(exc))
            raise
        _log.info("ensure_group_busygroup", group=group)


async def read_message_blocking(
    redis: aioredis.Redis,
    *,
    consumer: str,
    block_ms: int = 5000,
    count: int = 1,
    stream: str | None = None,
    group: str | None = None,
) -> tuple[str, dict[str, Any]] | None:
    """Block until a new entry is available.

    Returns ``(entry_id, payload)`` or ``None`` on timeout. The ``id``
    field of the payload is what XACK needs to acknowledge.
    P3-A: stream/group 参数化（默认 vulnscan 队列）。
    """
    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    resp = await redis.xreadgroup(
        groupname=group,
        consumername=consumer,
        streams={stream: ">"},
        count=count,
        block=block_ms,
    )
    if not resp:
        return None
    # resp is [(stream_name, [(entry_id, payload), ...]), ...]. redis-py's
    # stub types this as an opaque nested union -- cast to the real shape
    # (runtime value unchanged; the worker creates redis with
    # decode_responses=True, so stream/entry ids are str).
    stream_entries: list[tuple[str, list[tuple[str, dict[str, Any]]]]] = cast(
        list[tuple[str, list[tuple[str, dict[str, Any]]]]], resp
    )
    _stream_name, entries = stream_entries[0]
    if not entries:
        return None
    entry_id, payload = entries[0]
    return entry_id, payload


async def ack_message(
    redis: aioredis.Redis,
    entry_id: str,
    *,
    stream: str | None = None,
    group: str | None = None,
) -> None:
    """Acknowledge successful processing so the entry leaves PEL.

    P3-A: stream/group 参数化（默认 vulnscan 队列）。
    """
    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    try:
        await redis.xack(stream, group, entry_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("xack_failed", entry_id=entry_id, error=str(exc))


async def claim_stale(
    redis: aioredis.Redis,
    *,
    consumer: str,
    min_idle_ms: int = STALE_CLAIM_MIN_IDLE_MS,
    stream: str | None = None,
    group: str | None = None,
) -> tuple[str, dict[str, Any]] | None:
    """Take ownership of an entry that\'s been idle too long.

    Returns ``(entry_id, payload)`` or ``None`` if nothing is stale. The
    caller is responsible for tracking how many times a single entry has
    been redelivered; after ``MAX_DELIVERY`` moves to DLQ.

    阶段 5 收尾 P-func-3:events consumer 也用此函数,新增 stream/group 参数;
    vulnscan worker 仍传默认 STREAM_TASKS/CONSUMER_GROUP(向后兼容)。
    P3-A: 显式参数化（默认仍 vulnscan 队列）。
    """
    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    return await _claim_stale_in_stream(
        redis,
        stream=stream,
        group=group,
        consumer=consumer,
        min_idle_ms=min_idle_ms,
    )


async def _claim_stale_in_stream(
    redis: aioredis.Redis,
    *,
    stream: str,
    group: str,
    consumer: str,
    min_idle_ms: int = STALE_CLAIM_MIN_IDLE_MS,
) -> tuple[str, dict[str, Any]] | None:
    """通用 XAUTOCLAIM(可指定 stream + group)。"""
    try:
        resp = await redis.xautoclaim(
            name=stream,
            groupname=group,
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


async def claim_stale_batch(
    redis: aioredis.Redis,
    *,
    stream: str,
    group: str,
    consumer: str,
    min_idle_ms: int = STALE_CLAIM_MIN_IDLE_MS,
    max_claims: int = 100,
) -> list[tuple[str, dict[str, Any]]]:
    """阶段 5 收尾 P-func-3:批量 XAUTOCLAIM,清空旧进程 PEL 中所有 idle entry。

    与 claim_stale(单条)区别:循环调用直到 XAUTOCLAIM 返回空或达 max_claims。
    用于 events consumer 启动时一次性回收所有僵尸 entry。
    """
    claimed: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    while len(claimed) < max_claims:
        result = await _claim_stale_in_stream(
            redis,
            stream=stream,
            group=group,
            consumer=consumer,
            min_idle_ms=min_idle_ms,
        )
        if result is None:
            break
        entry_id, payload = result
        if entry_id in seen:
            # XAUTOCLAIM 同一 cursor 重复返回 → 终止
            break
        seen.add(entry_id)
        claimed.append((entry_id, payload))
    return claimed


async def pending_count(
    redis: aioredis.Redis, *, stream: str | None = None, group: str | None = None
) -> int:
    """How many entries are stuck in the PEL (delivered but not ACKed).

    Used by tests and the /health surface. Returns 0 on error so callers
    never have to wrap in try/except. P3-A: stream/group 参数化。
    """
    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    try:
        info = await redis.xpending(stream, group)
        # info is a dict {"pending": N, "min": id, "max": id, "consumers": [...]}
        if isinstance(info, dict):
            return int(info.get("pending", 0))
        # redis-py sometimes returns a tuple for the summary form
        if isinstance(info, list | tuple) and info:
            return int(info[0] or 0)
    except Exception:  # noqa: BLE001
        return 0
    return 0


async def stream_depth(
    redis: aioredis.Redis, *, stream: str | None = None
) -> int:
    """Number of entries currently in the stream (XLEN).

    Includes both undelivered and delivered-but-unacked entries. The
    caller can subtract ``pending_count()`` to get just the queue depth.
    P3-A: stream 参数化。
    """
    stream = stream or STREAM_TASKS
    try:
        return int(await redis.xlen(stream))
    except Exception:  # noqa: BLE001
        return 0


async def move_to_dlq(
    redis: aioredis.Redis,
    entry_id: str,
    payload: dict[str, Any],
    reason: str,
    *,
    stream: str | None = None,
    group: str | None = None,
    dlq: str | None = None,
) -> None:
    """Push the payload to the DLQ stream and ACK the original.

    Splitting ACK and XADD keeps a failed write from masking the entry --
    if DLQ write fails the entry remains in the PEL and will be retried.
    P3-A: stream/group/dlq 参数化（默认 vulnscan 队列）。
    """
    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    dlq = dlq or STREAM_DLQ
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
        await redis.xadd(dlq, dlq_fields)  # type: ignore[arg-type]
        await redis.xack(stream, group, entry_id)
        logger.warning("task_moved_to_dlq", entry_id=entry_id, reason=reason)
    except Exception as exc:  # noqa: BLE001
        logger.error("dlq_move_failed", entry_id=entry_id, error=str(exc))


async def delivery_count(
    redis: aioredis.Redis, entry_id: str, *, stream: str | None = None, group: str | None = None
) -> int:
    """How many times an entry has been delivered to *any* consumer.

    Used by the worker to decide when to give up and DLQ. Returns 0 when
    the entry id is no longer in the PEL. P3-A: stream/group 参数化。
    """
    stream = stream or STREAM_TASKS
    group = group or CONSUMER_GROUP
    try:
        info = await redis.xpending_range(
            stream,
            group,
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
    # Redis-py currently defaults socket reads to 5 seconds, the same as the
    # worker's XREADGROUP BLOCK window. Boundary jitter then turns an ordinary
    # empty poll into TimeoutError and restarts the worker with backoff.
    return aioredis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=15)
