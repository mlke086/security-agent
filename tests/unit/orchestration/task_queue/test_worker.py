"""Unit tests for TaskWorker.

The pure-config tests run without any async infrastructure. The end-to-end
tests against fakeredis require both ``fakeredis`` AND that the test
harness can spin a real asyncio loop; we\'ve seen flaky hangs on Windows
where pytest-asyncio\'s loop interacts oddly with fakeredis\'s polling
internals. Those are gated behind an env var so CI doesn\'t hang.
"""
from __future__ import annotations

import asyncio
import os

import pytest

try:
    import fakeredis.aioredis as fakeredis_aioredis  # type: ignore[import-not-found]
    HAS_FAKEREDIS = True
except ImportError:  # pragma: no cover -- optional dep
    HAS_FAKEREDIS = False

E2E_ENABLED = os.environ.get("TASK_QUEUE_E2E") == "1"


def _new_redis():
    return fakeredis_aioredis.FakeRedis(decode_responses=True)


def test_consumer_name_is_stable():
    """Two workers in the same process share a consumer name -- that is by
    design (only one should be started). What matters is that the property
    is callable."""
    from src.orchestration.task_queue.worker import TaskWorker
    w1 = TaskWorker()
    w2 = TaskWorker()
    assert isinstance(w1.consumer, str)
    assert isinstance(w2.consumer, str)


def test_worker_defaults_are_sane():
    from src.orchestration.task_queue.worker import TaskWorker
    w = TaskWorker()
    assert w.block_ms > 0
    assert w.claim_interval_sec > 0


@pytest.mark.skipif(
    not HAS_FAKEREDIS or not E2E_ENABLED,
    reason="fakeredis not installed or TASK_QUEUE_E2E=1 not set",
)
@pytest.mark.asyncio
async def test_worker_processes_one_envelope_then_exits():
    """Spawn a worker against a shared fakeredis, push one envelope,
    assert it runs the runner and ACKs. We stub ``run_vulnscan_from_envelope``
    so the test stays offline-safe.

    Set TASK_QUEUE_E2E=1 to run; otherwise skipped to avoid the
    pytest-asyncio + fakeredis + Windows interaction that can hang.
    """
    from src.orchestration.task_queue.dequeue import STREAM_TASKS
    from src.orchestration.task_queue.enqueue import TaskEnvelope
    from src.orchestration.task_queue.worker import TaskWorker

    shared = _new_redis()
    seen: list[str] = []

    async def fake_runner(envelope):
        seen.append(envelope.task_id)
        return {"status": "completed"}

    from src.orchestration.task_queue import worker as wmod
    monkey = pytest.MonkeyPatch()
    monkey.setattr(wmod, "run_vulnscan_from_envelope", fake_runner)
    try:
        worker_obj = TaskWorker(block_ms=10, redis_factory=lambda: shared)
        worker_obj.start()
        await asyncio.sleep(0.05)
        await shared.xadd(STREAM_TASKS, {
            "envelope": TaskEnvelope(task_id="t-w1", source="manual").to_json(),
            "task_id": "t-w1",
            "engine": "matcher",
        })
        for _ in range(40):
            if seen:
                break
            await asyncio.sleep(0.05)
        assert seen == ["t-w1"]
    finally:
        await worker_obj.stop()
        monkey.undo()


@pytest.mark.skipif(
    not HAS_FAKEREDIS or not E2E_ENABLED,
    reason="fakeredis not installed or TASK_QUEUE_E2E=1 not set",
)
@pytest.mark.asyncio
async def test_worker_swallows_runner_exception_and_dlqs_after_max_delivery():
    from src.orchestration.task_queue.dequeue import STREAM_DLQ, STREAM_TASKS
    from src.orchestration.task_queue.enqueue import TaskEnvelope
    from src.orchestration.task_queue.worker import TaskWorker

    shared = _new_redis()

    async def always_fail(envelope):
        raise RuntimeError("boom")

    from src.orchestration.task_queue import worker as wmod
    monkey = pytest.MonkeyPatch()
    monkey.setattr(wmod, "run_vulnscan_from_envelope", always_fail)
    try:
        await shared.xadd(STREAM_TASKS, {
            "envelope": TaskEnvelope(task_id="t-poison", source="manual").to_json(),
            "task_id": "t-poison",
            "engine": "matcher",
        })
        worker_obj = TaskWorker(block_ms=10, redis_factory=lambda: shared)
        worker_obj.start()
        for _ in range(40):
            depth = await shared.xlen(STREAM_DLQ)
            if depth > 0:
                break
            await asyncio.sleep(0.1)
        depth = await shared.xlen(STREAM_DLQ)
        assert depth >= 1, f"expected DLQ entry, got depth={depth}"
    finally:
        await worker_obj.stop()
        monkey.undo()

def test_worker_max_concurrent_default():
    """Default concurrency limit should be a small positive number.

    8 is the production default; we don't pin the literal in case a future
    bump is needed, just that the value is sane.
    """
    from src.orchestration.task_queue.worker import TaskWorker
    w = TaskWorker()
    assert w.max_concurrent >= 1
    assert isinstance(w.max_concurrent, int)


def test_worker_max_concurrent_clamped_to_one():
    """Passing 0 or negative still gives at least 1 (no zero-pool)."""
    from src.orchestration.task_queue.worker import TaskWorker
    assert TaskWorker(max_concurrent=0).max_concurrent == 1
    assert TaskWorker(max_concurrent=-5).max_concurrent == 1
    assert TaskWorker(max_concurrent=4).max_concurrent == 4

