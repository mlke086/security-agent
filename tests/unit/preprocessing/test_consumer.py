"""Unit tests for the Kafka AlertConsumer.

Covers _process (sanitize+extract), _emit (run_pipeline handoff + concurrency),
_send_dlq, and the run() error-splitting (parse failure -> DLQ+commit;
pipeline failure -> no commit / redeliver). run_pipeline and Kafka are mocked
so no real LLM or broker is required.
"""

from unittest.mock import AsyncMock

import pytest

from src.preprocessing.consumer import AlertConsumer


class _FakeMsg:
    def __init__(self, value: str, offset: int = 0) -> None:
        self.value = value
        self.offset = offset


class _FakeConsumer:
    """Minimal async-iterator stand-in for AIOKafkaConsumer."""

    def __init__(self, msgs: list[_FakeMsg]) -> None:
        self._msgs = list(msgs)
        self.committed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._msgs:
            return self._msgs.pop(0)
        raise StopAsyncIteration

    async def commit(self) -> None:
        self.committed = True


@pytest.fixture(autouse=True)
def _reset_pipeline_sem():
    """Reset the module-level concurrency semaphore between tests."""
    import src.preprocessing.consumer as consumer_mod

    consumer_mod._pipeline_sem = None
    yield
    consumer_mod._pipeline_sem = None


# ── _stable_event_id ─────────────────────────────────────


def test_stable_event_id_source_prefixed():
    """V13 P0-1: payload ids must be source-prefixed so two sources that
    share an id (e.g. auto-increment counters) cannot collide on the
    events table primary key."""
    c = AlertConsumer()
    assert (
        c._stable_event_id('{"id": "42", "msg": "x"}', source="raw-alerts")
        == "raw-alerts:42"
    )
    assert (
        c._stable_event_id('{"event_id": "e-1"}', source="raw-alerts")
        == "raw-alerts:e-1"
    )
    assert (
        c._stable_event_id('{"alert_id": "a-7"}', source="raw-alerts")
        == "raw-alerts:a-7"
    )
    assert (
        c._stable_event_id('{"uuid": "u-9"}', source="raw-alerts")
        == "raw-alerts:u-9"
    )


def test_stable_event_id_default_source_kafka():
    c = AlertConsumer()
    assert c._stable_event_id('{"id": "1"}') == "kafka:1"


def test_stable_event_id_hash_fallback_unchanged():
    c = AlertConsumer()
    # Non-JSON payloads keep the sha256 fallback (deterministic across
    # redeliveries, no source prefix needed -- the hash is already unique).
    assert c._stable_event_id("raw syslog line").startswith("sha256:")


# ── _process ────────────────────────────────────────────────


def test_process_structure_and_source():
    c = AlertConsumer()
    r = c._process("Honeypot captured whoami from 45.33.32.156")
    assert r["source"] == "kafka"
    assert isinstance(r["event_id"], str) and r["event_id"]
    assert isinstance(r["sanitized_text"], str)
    assert set(r["iocs"].keys()) == {"ips", "domains", "hashes", "urls"}
    assert "timestamp" in r


def test_process_extracts_public_ip():
    c = AlertConsumer()
    r = c._process("connection from 45.33.32.156 detected")
    assert "45.33.32.156" in r["iocs"]["ips"]


def test_process_excludes_private_ip():
    c = AlertConsumer()
    r = c._process("internal host 192.168.1.5 scanned")
    assert "192.168.1.5" not in r["iocs"]["ips"]


# ── _emit ───────────────────────────────────────────────────


async def test_emit_invokes_run_pipeline(monkeypatch):
    """阶段 4-2 拆分后, _emit 改为 Redis Stream 入队 (preprocessing 镜像不再依赖 LangGraph)。
    测试断言改为 enqueue_event 被正确调用。
    """
    c = AlertConsumer()
    fake_enqueue = AsyncMock()
    fake_enqueue.return_value = "evt-1"
    monkeypatch.setattr("src.preprocessing.vulnscan_queue.enqueue.enqueue_event", fake_enqueue)
    event = {"event_id": "e1", "sanitized_text": "x", "iocs": {"ips": []}, "source": "kafka"}
    await c._emit(event)
    fake_enqueue.assert_awaited_once()
    kwargs = fake_enqueue.await_args.kwargs
    assert kwargs["event_id"] == "e1"
    assert kwargs["payload"]["sanitized_text"] == "x"
    assert kwargs["payload"]["source"] == "kafka"


# ── _send_dlq ───────────────────────────────────────────────


async def test_send_dlq_posts_to_dlq():
    c = AlertConsumer()
    c._dlq_producer = AsyncMock()
    c._dlq_producer.send.return_value = AsyncMock()
    c._dlq_producer.flush.return_value = AsyncMock()
    ok = await c._send_dlq("raw payload", "some error")
    assert ok is True
    c._dlq_producer.send.assert_awaited_once()
    _, kwargs = c._dlq_producer.send.call_args
    assert kwargs["value"]["raw"] == "raw payload"
    assert kwargs["value"]["error"] == "some error"


# ── run() error splitting ───────────────────────────────────


async def test_run_parse_failure_sends_dlq_and_commits(monkeypatch):
    """A message that fails to parse must go to the DLQ and be committed."""
    c = AlertConsumer()
    fc = _FakeConsumer([_FakeMsg("garbage")])
    c._consumer = fc
    c._dlq_producer = AsyncMock()
    # P1-PRE-01 (2026-07-19): _send_dlq now awaits the send future +
    # flushes. AsyncMock's default send() return value is not awaitable,
    # so we wrap it in a fresh AsyncMock to satisfy the second await.
    c._dlq_producer.send.return_value = AsyncMock()
    c._dlq_producer.flush.return_value = AsyncMock()

    def _boom(raw: str):
        raise ValueError("parse error")

    monkeypatch.setattr(c, "_process", _boom)
    await c.run()

    assert fc.committed is True
    c._dlq_producer.send.assert_awaited_once()


async def test_run_pipeline_failure_does_not_commit(monkeypatch):
    """阶段 4-2 拆分后, _emit -> enqueue_event 入队失败必须不 commit,
    触发 Kafka 重投递 (同原语义)。"""
    c = AlertConsumer()
    fc = _FakeConsumer([_FakeMsg("whoami from 45.33.32.156")])
    c._consumer = fc
    c._dlq_producer = AsyncMock()
    monkeypatch.setattr(
        "src.preprocessing.vulnscan_queue.enqueue.enqueue_event",
        AsyncMock(side_effect=RuntimeError("redis enqueue failed")),
    )
    await c.run()

    assert fc.committed is False
    c._dlq_producer.send.assert_not_awaited()
