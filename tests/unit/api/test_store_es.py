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
async def test_get_event_fetches_trace_by_event_id_keyword(store):
    """_fetch_trace must query event_id.keyword, not event_id.

    event_id is a UUID with hyphens (e.g. 550e8400-e29b-41d4-...). The audit
    index has no explicit mapping, so ES dynamic-maps event_id as text+keyword.
    A `term` on the text field matches analyzed tokens -- the standard analyzer
    splits the UUID on hyphens, so the full id is never a single token and the
    query returns 0 hits -> event detail page showed "暂无推理轨迹". Querying
    event_id.keyword matches the exact, unanalyzed value.
    """
    uuid_id = "550e8400-e29b-41d4-a716-446655440000"
    store._es.get = AsyncMock(return_value={"found": True, "_source": _src(event_id=uuid_id)})
    store._es.search = AsyncMock(
        return_value={
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "node": "entry",
                            "action": "received",
                            "summary": "Event received",
                            "timestamp": "2026-07-30T00:00:00",
                            "details": {},
                        }
                    }
                ]
            }
        }
    )
    ev = await store.get_event(uuid_id)
    assert ev is not None
    assert len(ev.trace) == 1
    assert ev.trace[0].node == "entry"
    # The trace query must match the exact, unanalyzed UUID. Since the
    # b37c0ab5 P0 fix, the query is a bool should over both `event_id`
    # (keyword-typed audit index) and `event_id.keyword` (legacy
    # text+keyword dynamic mapping) so either index shape matches.
    query = store._es.search.await_args.kwargs["query"]
    assert query == {
        "bool": {
            "minimum_should_match": 1,
            "should": [
                {"term": {"event_id": uuid_id}},
                {"term": {"event_id.keyword": uuid_id}},
            ],
        }
    }


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
    await store.add_trace_step(
        "e1", TraceStep(node="entry", action="recv", summary="s", timestamp="t", details={})
    )
    store._es.index.assert_awaited_once()


@pytest.mark.asyncio
async def test_add_approval(store):
    store._es.update = AsyncMock()
    await store.add_approval(
        "e1",
        ApprovalEntry(
            event_id="e1", action="approved", note="", actor="admin", role="admin", timestamp="t"
        ),
    )
    store._es.update.assert_awaited_once()


@pytest.mark.asyncio
async def test_metrics(store):
    store._es.search = AsyncMock(
        return_value={
            "hits": {"total": {"value": 5}, "hits": []},
            "aggregations": {
                "by_verdict": {"buckets": [{"key": "true_positive", "doc_count": 3}]},
                "by_priority": {"buckets": [{"key": "high", "doc_count": 2}]},
                "avg_duration": {"value": 1500},
            },
        }
    )
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
