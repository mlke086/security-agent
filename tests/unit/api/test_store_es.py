"""Unit tests for ESEventStore with a mocked AsyncElasticsearch client."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.api.store import ApprovalEntry, TraceStep
from src.api.store_es import ESEventStore


@pytest.fixture(autouse=True)
def _mock_bus(monkeypatch):
    bus = MagicMock()
    bus.publish = AsyncMock()
    monkeypatch.setattr("src.api.events_bus.get_event_bus", lambda: bus)


@pytest.fixture
def store():
    s = ESEventStore()
    s._es = MagicMock()
    return s


def _src(**overrides):
    base = {
        "event_id": "e1",
        "source": "api",
        "submitted_at": "2026-01-01T00:00:00",
        "status": "completed",
        "tags": [],
        "iocs": {},
        "trace": [],
        "approvals": [],
        "mitre_ttps": [],
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_create_event(store):
    store._es.index = AsyncMock()
    rec = await store.create_event("e1", "text", {"ips": []}, "api")
    store._es.index.assert_awaited_once()
    assert rec.event_id == "e1"


@pytest.mark.asyncio
async def test_get_event(store):
    store._es.get = AsyncMock(return_value={"found": True, "_source": _src()})
    store._es.search = AsyncMock(return_value={"hits": {"hits": []}})  # _fetch_trace
    ev = await store.get_event("e1")
    assert ev is not None
    assert ev.event_id == "e1"


@pytest.mark.asyncio
async def test_get_event_missing(store):
    store._es.get = AsyncMock(return_value={"found": False})
    assert await store.get_event("nope") is None


@pytest.mark.asyncio
async def test_update_event(store):
    store._es.update = AsyncMock()
    await store.update_event("e1", status="completed", final_verdict="true_positive")
    store._es.update.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_event_noop_when_all_none(store):
    store._es.update = AsyncMock()
    await store.update_event("e1", status=None, verdict=None)
    store._es.update.assert_not_awaited()


@pytest.mark.asyncio
async def test_add_trace_step(store):
    store._es.index = AsyncMock()
    await store.add_trace_step("e1", TraceStep(node="entry", action="recv", summary="s", timestamp="t", details={}))
    store._es.index.assert_awaited_once()


@pytest.mark.asyncio
async def test_add_approval(store):
    store._es.update = AsyncMock()
    await store.add_approval("e1", ApprovalEntry(
        event_id="e1", action="approved", note="", actor="admin", role="admin", timestamp="t"))
    store._es.update.assert_awaited_once()


@pytest.mark.asyncio
async def test_metrics(store):
    store._es.search = AsyncMock(return_value={
        "hits": {"total": {"value": 5}, "hits": []},
        "aggregations": {
            "by_verdict": {"buckets": [{"key": "true_positive", "doc_count": 3}]},
            "by_priority": {"buckets": [{"key": "high", "doc_count": 2}]},
            "avg_duration": {"value": 1500},
        },
    })
    store._es.count = AsyncMock(return_value={"count": 1})
    m = await store.metrics()
    assert m["total_events"] == 5
    assert m["by_verdict"]["true_positive"] == 3
    assert m["pending_approvals"] == 1
    assert m["avg_duration_ms"] == 1500


@pytest.mark.asyncio
async def test_list_events_and_total_count(store):
    store._es.search = AsyncMock(return_value={"hits": {"hits": [{"_source": _src()}]}})
    store._es.count = AsyncMock(return_value={"count": 1})
    items = await store.list_events(limit=10)
    assert len(items) == 1
    assert items[0].event_id == "e1"
    assert await store.total_count() == 1
