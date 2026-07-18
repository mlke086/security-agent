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
    c = AlertConsumer()
    fake_run = AsyncMock()
    monkeypatch.setattr("src.orchestration.runner.run_pipeline", fake_run)
    event = {"event_id": "e1", "sanitized_text": "x", "iocs": {"ips": []}, "source": "kafka"}
    await c._emit(event)
    fake_run.assert_awaited_once_with("e1", "x", {"ips": []}, "kafka")


# ── _send_dlq ───────────────────────────────────────────────

async def test_send_dlq_posts_to_dlq():
    c = AlertConsumer()
    c._dlq_producer = AsyncMock()
    await c._send_dlq("raw payload", "some error")
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

    def _boom(raw: str):
        raise ValueError("parse error")

    monkeypatch.setattr(c, "_process", _boom)
    await c.run()

    assert fc.committed is True
    c._dlq_producer.send.assert_awaited_once()


async def test_run_pipeline_failure_does_not_commit(monkeypatch):
    """A pipeline execution failure must NOT commit, so Kafka redelivers for retry."""
    c = AlertConsumer()
    fc = _FakeConsumer([_FakeMsg("whoami from 45.33.32.156")])
    c._consumer = fc
    c._dlq_producer = AsyncMock()
    monkeypatch.setattr(
        "src.orchestration.runner.run_pipeline",
        AsyncMock(side_effect=RuntimeError("pipeline boom")),
    )
    await c.run()

    assert fc.committed is False
    c._dlq_producer.send.assert_not_awaited()
