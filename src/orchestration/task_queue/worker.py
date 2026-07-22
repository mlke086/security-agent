"""Long-running consumer of the vulnscan task queue.

One ``TaskWorker`` per API worker process. The worker joins the shared
consumer group, so load spreads across the fleet automatically. Entries
that get stuck in a dead worker\'s PEL are recovered by ``XAUTOCLAIM``
in the claim loop.
"""

from __future__ import annotations

import asyncio
from typing import Any

import redis.asyncio as aioredis

from src.common.logging.logger import get_logger
from src.orchestration.task_queue.dequeue import (
    MAX_DELIVERY,
    STALE_CLAIM_MIN_IDLE_MS,
    ack_message,
    claim_stale,
    consumer_name,
    delivery_count,
    ensure_group,
    get_redis,
    move_to_dlq,
    read_message_blocking,
)
from src.orchestration.task_queue.enqueue import TaskEnvelope
from src.orchestration.task_queue.runner import run_vulnscan_from_envelope

logger = get_logger(__name__)


class WorkerHandle:
    """Bundle of asyncio handles so callers can stop the worker cleanly."""

    def __init__(self, task: asyncio.Task, consumer: str) -> None:
        self.task = task
        self.consumer = consumer

    async def stop(self, timeout: float = 5.0) -> None:
        """Cancel the worker task and wait for it to drain."""
        self.task.cancel()
        try:
            await asyncio.wait_for(self.task, timeout=timeout)
        except (TimeoutError, asyncio.CancelledError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("worker_stop_error", consumer=self.consumer, error=str(exc))


class TaskWorker:
    """Asyncio consumer loop for ``STREAM_TASKS``.

    Constructor only stores config; call ``start()`` to spawn the actual
    task. ``block_ms`` controls how long XREADGROUP sleeps when the
    stream is empty -- shorter = more responsive shutdown, longer = less
    Redis chatter.

    ``redis_factory`` lets tests inject a fakeredis connection without
    touching global state. Production code passes nothing and gets the
    real Redis from settings.
    """

    def __init__(
        self,
        *,
        block_ms: int = 5000,
        claim_interval_sec: float = 30.0,
        max_concurrent: int = 8,
        redis_factory=None,
    ) -> None:
        self.block_ms = block_ms
        self.claim_interval_sec = claim_interval_sec
        self.max_concurrent = max(1, max_concurrent)
        self._redis_factory = redis_factory
        self._consumer = consumer_name()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._active_tasks: set[asyncio.Task] = set()

    @property
    def consumer(self) -> str:
        return self._consumer

    def start(self) -> WorkerHandle:
        """Spawn the worker task. Idempotent on repeated calls."""
        if self._task is not None and not self._task.done():
            return WorkerHandle(self._task, self._consumer)
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name=f"vulnscan-worker-{self._consumer}")
        logger.info("task_worker_started", consumer=self._consumer)
        return WorkerHandle(self._task, self._consumer)

    async def stop(self, drain_timeout: float = 10.0) -> None:
        """Signal the loop to exit and wait briefly.

        We CANCEL the task rather than just setting ``_stop``: the loop
        spends most of its time blocked in ``xreadgroup(block=...)``, which
        does not poll the stop event. Cancelling forces the block to
        unwind so the connection can close cleanly.

        In-flight processing tasks are NOT cancelled -- they are allowed
        to finish naturally (subgraphs may already be in the middle of
        writing to ES). We wait up to ``drain_timeout`` seconds for them.
        """
        self._stop.set()
        if self._task is None:
            return
        try:
            self._task.cancel()
            try:
                await self._task
            except (TimeoutError, asyncio.CancelledError, Exception):
                pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("task_worker_stop_error", consumer=self._consumer, error=str(exc))
        # Drain in-flight tasks so they don't keep writing to ES/Redis
        # after the connection is closed.
        if self._active_tasks:
            try:
                done, _pending = await asyncio.wait(
                    list(self._active_tasks),
                    timeout=drain_timeout,
                    return_when=asyncio.ALL_COMPLETED,
                )
                # Re-raise any unhandled exception from background tasks
                # so it shows up in the shutdown log instead of vanishing.
                # V4.1: rename to 	ask_exc to avoid mypy strict's
                # "Assignment to variable exc outside except: block" --
                # exc is already bound by the outer except blocks (~line 113)
                # and the inner drain except (~line 134), and reusing it outside
                # an except is flagged as a style bug even though the runtime
                # behaviour is identical.
                for t in done:
                    if t.cancelled():
                        continue
                    task_exc = t.exception()
                    if task_exc is not None:
                        logger.warning(
                            "in_flight_task_error_on_stop",
                            error=str(task_exc),
                            error_type=type(task_exc).__name__,
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning("drain_inflight_failed", error=str(exc))

    async def _run(self) -> None:
        """Main loop. Owns a single Redis connection for the whole life.

        P2-VULN-08 (2026-07-19): wrapped in an outer restart loop with
        exponential backoff so a transient Redis or subgraph exception does
        not permanently kill the worker. Without this, a single misbehaving
        envelope would push the entry to DLQ and then the process would
        silently stop draining the queue. Backoff caps at 30s and resets on
        a healthy 60s+ run.
        """
        backoff = 1.0
        max_backoff = 30.0
        healthy_until: float | None = None
        while not self._stop.is_set():
            if self._redis_factory is not None:
                redis = self._redis_factory()
            else:
                redis = get_redis()
            try:
                await self._run_once(redis)
                # If _run_once returns normally the loop is being asked to
                # stop (not via an exception). Reset backoff and exit.
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                # If we had a healthy stretch right before the crash, give
                # ourselves credit and reset backoff. Otherwise grow it.
                if healthy_until is not None and asyncio.get_event_loop().time() > healthy_until:
                    backoff = 1.0
                logger.error(
                    "task_worker_crashed",
                    consumer=self._consumer,
                    error=str(exc),
                    error_type=type(exc).__name__,
                    retry_in_sec=backoff,
                )
                try:
                    await redis.aclose()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=backoff)
                    # Stop event set during the wait -- exit cleanly.
                    return
                except TimeoutError:
                    pass
                backoff = min(max_backoff, backoff * 2)
                healthy_until = asyncio.get_event_loop().time() + 60.0

    async def _run_once(self, redis) -> None:
        """One pass through the consume loop. Extracted so the outer
        restart loop (P2-VULN-08) can wrap it without duplicating state.
        """
        logger.info("task_worker_enter_run", consumer=self._consumer)
        await ensure_group(redis)
        logger.info("task_worker_group_ready", consumer=self._consumer)
        await self._claim_loop(redis)  # warm up
        logger.info("task_worker_claim_loop_done", consumer=self._consumer)
        while not self._stop.is_set():
            self._gc_finished_tasks()
            if len(self._active_tasks) < self.max_concurrent:
                spawned = await self._drain_once(redis)
                # spawned is None when the stream was empty; the loop
                # still has a chance to claim stale entries below.
                del spawned  # noqa: F841
            await self._maybe_claim(redis)
        try:
            await redis.aclose()
        except Exception:  # noqa: BLE001
            pass

    async def _drain_once(self, redis: aioredis.Redis) -> asyncio.Task | None:
        """Read one entry (or return None) and spawn its processing task.

        Returning the spawned Task (or None) lets the main loop keep
        reading from the stream while the subgraph runs. Each task is
        tracked in ``_active_tasks`` so stop() can drain them.
        """
        msg = await read_message_blocking(
            redis,
            consumer=self._consumer,
            block_ms=self.block_ms,
        )
        if msg is None:
            return None
        entry_id, payload = msg
        t = asyncio.create_task(
            self._process(redis, entry_id, payload),
            name=f"vulnscan-task-{entry_id}",
        )
        self._active_tasks.add(t)
        t.add_done_callback(self._active_tasks.discard)
        return t

    def _gc_finished_tasks(self) -> None:
        """Drop references to completed tasks so the set doesn't grow.

        ``add_done_callback`` already removes the task from the set, but
        the discarded Task object can hold a traceback in its
        ``__traceback__`` attribute. Calling ``result()`` on completed
        tasks re-raises the exception (so it isn't silently lost) and
        releases the traceback reference.
        """
        for t in list(self._active_tasks):
            if t.done():
                self._active_tasks.discard(t)
                if not t.cancelled():
                    try:
                        t.result()
                    except Exception:  # noqa: BLE001
                        # Already logged by _process / _drain_once paths;
                        # the callback just makes sure we don't leak it.
                        pass

    async def _maybe_claim(self, redis: aioredis.Redis) -> None:
        """If we\'ve been idle long enough, scan for stale entries."""
        if self._last_claim_at is None or (
            asyncio.get_event_loop().time() - self._last_claim_at > self.claim_interval_sec
        ):
            await self._claim_loop(redis)
            self._last_claim_at = asyncio.get_event_loop().time()

    _last_claim_at: float | None = None

    async def _claim_loop(self, redis: aioredis.Redis) -> None:
        """Drain up to N stale entries on each call so the queue recovers
        even when the regular XREADGROUP path is busy."""
        for _ in range(8):
            claimed = await claim_stale(
                redis,
                consumer=self._consumer,
                min_idle_ms=STALE_CLAIM_MIN_IDLE_MS,
            )
            if claimed is None:
                return
            entry_id, payload = claimed
            await self._process(redis, entry_id, payload)

    async def _process(self, redis: aioredis.Redis, entry_id: str, payload: dict[str, Any]) -> None:
        """Run the subgraph for one entry, then ACK or DLQ.

        On uncaught exception we DO NOT ACK. The entry stays in PEL; the
        next claim cycle (after STALE_CLAIM_MIN_IDLE_MS) will hand it to
        another worker. Once ``delivery_count >= MAX_DELIVERY`` we move
        it to the DLQ so the queue doesn\'t grow forever on a poison
        payload.
        """
        envelope_raw = payload.get("envelope")
        if not envelope_raw:
            logger.warning("envelope_missing_in_payload", entry_id=entry_id)
            await move_to_dlq(redis, entry_id, payload, reason="envelope_missing")
            return

        try:
            envelope = TaskEnvelope.from_json(envelope_raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("envelope_parse_failed", entry_id=entry_id, error=str(exc))
            await move_to_dlq(redis, entry_id, payload, reason=f"parse:{exc}")
            return

        try:
            await run_vulnscan_from_envelope(envelope)
            await ack_message(redis, entry_id)
        except Exception as exc:  # noqa: BLE001
            attempts = await delivery_count(redis, entry_id)
            logger.warning(
                "task_run_failed",
                entry_id=entry_id,
                task_id=envelope.task_id,
                attempts=attempts,
                error=str(exc),
            )
            if attempts >= MAX_DELIVERY:
                await move_to_dlq(redis, entry_id, payload, reason=f"max_delivery:{exc}")
            # Otherwise leave it in PEL for the next claim cycle.
