"""EventStore - event lifecycle storage. Phase 2: PG JSONB primary, ES for full-text search."""

import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

EventStatus = Literal["processing", "completed", "pending_approval", "ignored", "error", "rejected"]


class TraceStep(BaseModel):
    node: str
    action: str
    summary: str
    timestamp: str
    details: dict[str, Any] = {}


class ApprovalEntry(BaseModel):
    event_id: str
    action: str
    note: str = ""
    actor: str
    role: str
    timestamp: str


class EventRecord(BaseModel):
    event_id: str
    source: str = "api"
    submitted_at: str = ""
    finished_at: str | None = None
    status: EventStatus = "processing"
    priority: str | None = None
    tags: list[str] = []
    sanitized_text: str = ""
    iocs: dict[str, list[str]] = {}
    final_verdict: str | None = None
    confidence: float | None = None
    evidence_summary: str | None = None
    mitre_ttps: list[str] = []
    poc: str | None = None
    is_vulnerable: bool = False
    trace: list[TraceStep] = []
    approvals: list[ApprovalEntry] = []
    pending_approval_id: str | None = None
    duration_ms: int | None = None
    # P2-CORE-NEW-6 (2026-07-20): persisted execution_summary so operators
    # can audit what each approved response actually did.
    execution_summary: dict | list | None = None


class MemoryEventStore:
    """In-memory event store for demo/test, offline-safe.
    Phase 2 fallback when store_backend="memory".
    """

    def __init__(self) -> None:
        self._events: dict[str, EventRecord] = {}
        self._store_backend = "memory"

    async def create_event(self, event_id: str, text: str, iocs: dict, source: str) -> EventRecord:
        rec = EventRecord(
            event_id=event_id,
            source=source,
            submitted_at=datetime.now(UTC).isoformat(),
            sanitized_text=text,
            iocs=iocs,
        )
        self._events[event_id] = rec
        return rec

    async def get_event(self, event_id: str) -> EventRecord | None:
        return self._events.get(event_id)

    async def list_events(
        self,
        status: str | None = None,
        verdict: str | None = None,
        priority: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EventRecord]:
        items = [
            e
            for e in self._events.values()
            if (status is None or e.status == status)
            and (verdict is None or e.final_verdict == verdict)
            and (priority is None or e.priority == priority)
        ]
        items.sort(key=lambda e: e.submitted_at, reverse=True)
        return items[offset : offset + limit]

    async def total_count(self) -> int:
        return len(self._events)

    async def update_event(self, event_id: str, **kwargs: Any) -> None:
        if event_id in self._events:
            for k, v in kwargs.items():
                setattr(self._events[event_id], k, v)

    async def add_trace_step(self, event_id: str, step: TraceStep) -> None:
        if event_id in self._events:
            self._events[event_id].trace.append(step)

    async def add_approval(self, event_id: str, approval: ApprovalEntry) -> None:
        if event_id in self._events:
            self._events[event_id].approvals.append(approval)

    async def metrics(self) -> dict[str, Any]:
        from collections import Counter

        events = list(self._events.values())
        verdicts = Counter(e.final_verdict for e in events if e.final_verdict)
        priorities = Counter(e.priority for e in events if e.priority)
        durations = [d for e in events if (d := e.duration_ms) is not None]
        avg_dur = int(sum(durations) / len(durations)) if durations else 0
        pending = sum(1 for e in events if e.status == "pending_approval")
        return {
            "total_events": len(events),
            "by_verdict": dict(verdicts),
            "by_priority": dict(priorities),
            "pending_approvals": pending,
            "avg_duration_ms": avg_dur,
        }

    async def close(self) -> None:
        self._events.clear()


class EventStore:
    """PG-backed event store (Phase 2: replaces in-memory dict)."""

    def __init__(self) -> None:
        self._store_backend = "pg"

    async def _pg_conn(self):
        """Return a PG connection context manager (async with ... as conn)."""
        from src.common.db.pg import get_pg_pool

        pool = await get_pg_pool()
        return pool.acquire()  # PoolAcquireContext (async context manager)

    async def create_event(self, event_id: str, text: str, iocs: dict, source: str) -> EventRecord:
        rec = EventRecord(
            event_id=event_id,
            source=source,
            submitted_at=datetime.now(UTC).isoformat(),
            sanitized_text=text,
            iocs=iocs,
        )
        async with await self._pg_conn() as conn:
            await conn.execute(
                "INSERT INTO events (event_id, data) VALUES ($1, $2::jsonb)",
                event_id,
                rec.model_dump_json(),
            )
        return rec

    async def get_event(self, event_id: str) -> EventRecord | None:
        async with await self._pg_conn() as conn:
            row = await conn.fetchrow("SELECT data FROM events WHERE event_id=$1", event_id)
        if row is None:
            return None
        return EventRecord(**json.loads(row["data"]))

    async def list_events(
        self,
        status: str | None = None,
        verdict: str | None = None,
        priority: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EventRecord]:
        where = []
        params: list[Any] = []
        idx = 0
        if status:
            idx += 1
            where.append(f"data->>'status' = ${idx}")
            params.append(status)
        if verdict:
            idx += 1
            where.append(f"data->>'final_verdict' = ${idx}")
            params.append(verdict)
        if priority:
            idx += 1
            where.append(f"data->>'priority' = ${idx}")
            params.append(priority)
        sql = "SELECT data FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY data->>'submitted_at' DESC"
        if limit:
            idx += 1
            params.append(limit)
            sql += f" LIMIT ${idx}"
        if offset:
            idx += 1
            params.append(offset)
            sql += f" OFFSET ${idx}"
        async with await self._pg_conn() as conn:
            rows = await conn.fetch(sql, *params)
        return [EventRecord(**json.loads(row["data"])) for row in rows]

    async def total_count(self) -> int:
        async with await self._pg_conn() as conn:
            val = await conn.fetchval("SELECT COUNT(*) FROM events")
        return val or 0

    # P2-API-05 (2026-07-20): callers can now CLEAR a field by passing the
    # special sentinel ``_CLEAR``. Previously every None was silently
    # skipped so we could never reset pending_approval_id / finished_at
    # back to null -- they were stuck forever once set.
    _CLEAR = object()

    async def update_event(self, event_id: str, **kwargs) -> None:
        # V4.1 (P0-4): _CLEAR is a class-level sentinel on EventStore; look it up
        # off the class instead of doing a late module-level import (which mypy
        # cannot resolve and which ruff N806 would also flag if rebound to a local).
        _clear = type(self)._CLEAR
        set_parts = []
        params = []
        idx = 0
        for k, v in kwargs.items():
            if v is None:
                continue
            if v is _clear:
                idx += 1
                set_parts.append(f"data = data - '{k}'")
            else:
                idx += 1
                set_parts.append(f"data['{k}'] = to_jsonb(${idx}::jsonb)")
                params.append(json.dumps(v))
        if not set_parts:
            return
        set_parts.append("updated_at = NOW()")
        idx += 1
        params.append(event_id)
        sql = f"UPDATE events SET {', '.join(set_parts)} WHERE event_id=${idx}"
        async with await self._pg_conn() as conn:
            await conn.execute(sql, *params)
        try:
            from src.api.events_bus import get_event_bus

            await get_event_bus().publish(
                f"events:{event_id}", {"type": "event_update", "event_id": event_id}
            )
            await get_event_bus().publish(
                "events:list", {"type": "event_update", "event_id": event_id}
            )
            await get_event_bus().publish(
                "metrics", {"type": "metrics_update", "event_id": event_id}
            )
        except Exception:
            pass

    async def add_trace_step(self, event_id: str, step: TraceStep) -> None:
        async with await self._pg_conn() as conn:
            await conn.execute(
                "UPDATE events SET data = jsonb_set(data, '{trace}', "
                "COALESCE(data->'trace', '[]'::jsonb) || $1::jsonb), "
                "updated_at = NOW() WHERE event_id=$2",
                step.model_dump_json(),
                event_id,
            )
        try:
            from src.api.events_bus import get_event_bus

            await get_event_bus().publish(
                f"events:{event_id}",
                {"type": "trace_update", "event_id": event_id, "node": step.node},
            )
        except Exception:
            pass

    async def add_approval(self, event_id: str, approval: ApprovalEntry) -> None:
        async with await self._pg_conn() as conn:
            await conn.execute(
                "UPDATE events SET data = jsonb_set(data, '{approvals}', "
                "COALESCE(data->'approvals', '[]'::jsonb) || $1::jsonb), "
                "updated_at = NOW() WHERE event_id=$2",
                approval.model_dump_json(),
                event_id,
            )

    async def metrics(self) -> dict:
        async with await self._pg_conn() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM events") or 0
            rows = await conn.fetch(
                "SELECT data->>'final_verdict' as v, COUNT(*) as c FROM events GROUP BY v ORDER BY c DESC"
            )
            by_verdict = {r["v"] or "unknown": r["c"] for r in rows}
            rows = await conn.fetch(
                "SELECT data->>'priority' as p, COUNT(*) as c FROM events GROUP BY p ORDER BY c DESC"
            )
            by_priority = {r["p"] or "none": r["c"] for r in rows}
            pending = (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM events WHERE data->>'status' = 'pending_approval'"
                )
                or 0
            )
            avg_duration = (
                await conn.fetchval(
                    "SELECT COALESCE(AVG((data->>'duration_ms')::int), 0) FROM events"
                )
                or 0
            )
        return {
            "total_events": total,
            "by_verdict": by_verdict,
            "by_priority": by_priority,
            "pending_approvals": pending,
            "avg_duration_ms": int(avg_duration),
        }

    async def close(self) -> None:
        return None


_pg_store: EventStore | None = None
_mem_store: MemoryEventStore | None = None


def get_event_store(backend: str | None = None) -> EventStore | MemoryEventStore:
    """Return event store singleton.

    backend=None reads settings.store_backend:
      "es"     -> Elasticsearch  (store_es.py)
      "pg"     -> PostgreSQL     (EventStore, this module)
      "memory" -> In-memory dict (MemoryEventStore, this module)
    """
    if backend is None:
        backend = get_settings().store_backend
    if backend == "es":
        from src.api.store_es import get_es_event_store

        return get_es_event_store()  # type: ignore[return-value]
    if backend == "memory":
        global _mem_store
        if _mem_store is None:
            _mem_store = MemoryEventStore()
        return _mem_store
    global _pg_store
    if _pg_store is None:
        _pg_store = EventStore()
    return _pg_store
