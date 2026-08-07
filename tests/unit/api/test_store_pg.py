"""Unit tests for the PG EventStore (V13 P0-1 idempotency)."""

from unittest.mock import AsyncMock

import pytest

from src.api.store import EventStore


class _FakeConn:
    """Async-context-manager stand-in for an asyncpg connection."""

    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, sql: str, *args) -> None:
        self.executed.append((sql, args))


@pytest.fixture
def pg_store(monkeypatch):
    store = EventStore()
    conn = _FakeConn()

    async def _fake_pg_conn():
        return conn

    monkeypatch.setattr(store, "_pg_conn", _fake_pg_conn)
    store._fake_conn = conn  # type: ignore[attr-defined]
    return store


async def test_create_event_uses_idempotent_upsert(pg_store):
    """V13 P0-1: create_event must be an ON CONFLICT upsert so Kafka
    redeliveries (process-then-crash-before-commit) cannot wedge the
    consumer on a primary-key violation."""
    rec = await pg_store.create_event("e1", "text", {"ips": []}, "api")
    assert rec.event_id == "e1"
    sql, args = pg_store._fake_conn.executed[0]  # type: ignore[attr-defined]
    assert "ON CONFLICT (event_id) DO UPDATE SET data = EXCLUDED.data" in sql
    assert args[0] == "e1"


async def test_create_event_called_twice_does_not_raise(pg_store):
    """The same event_id arriving twice (redelivery) must be handled
    without raising a unique-violation -- the second call is a no-op update."""
    await pg_store.create_event("e1", "text", {"ips": []}, "api")
    # Second redelivery: same id, should not raise (fake conn records 2 calls)
    rec2 = await pg_store.create_event("e1", "text", {"ips": []}, "api")
    assert rec2.event_id == "e1"
    assert len(pg_store._fake_conn.executed) == 2  # type: ignore[attr-defined]


async def test_pg_store_rejects_missing_conn(monkeypatch):
    """Sanity: EventStore without a working connection surfaces the error
    instead of silently swallowing it (regression guard for the upsert path)."""
    store = EventStore()

    async def _boom():
        raise RuntimeError("no pg")

    monkeypatch.setattr(store, "_pg_conn", _boom)
    with pytest.raises(RuntimeError, match="no pg"):
        await store.create_event("e1", "text", {"ips": []}, "api")
