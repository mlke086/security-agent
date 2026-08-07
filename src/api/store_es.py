"""ESEventStore — Event persistence backed by Elasticsearch."""

import uuid
from datetime import UTC, datetime

from elasticsearch import AsyncElasticsearch, NotFoundError

from src.api.store import ApprovalEntry, EventRecord, TraceStep
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


class ESEventStore:
    """Event store backed by Elasticsearch, matching EventStore interface.

    - Event records stored in security-agent-events (indexed by event_id)
    - Trace steps stored in security-agent-audit (aggregated by event_id query)
    - Approvals embedded in event document (append-only array)
    """

    def __init__(self) -> None:
        s = get_settings()
        self._es = AsyncElasticsearch(hosts=[s.es_hosts])
        self._events_index = s.es_index_events
        self._audit_index = s.es_index_audit

    async def create_event(self, event_id: str, text: str, iocs: dict, source: str) -> EventRecord:
        rec = EventRecord(
            event_id=event_id,
            source=source,
            submitted_at=datetime.now(UTC).isoformat(),
            sanitized_text=text,
            iocs=iocs,
        )
        await self._es.index(index=self._events_index, id=event_id, document=rec.model_dump())
        return rec

    async def get_event(self, event_id: str) -> EventRecord | None:
        resp = await self._es.get(index=self._events_index, id=event_id, ignore=[404])  # type: ignore[call-arg]
        if not resp.get("found"):
            return None
        data = resp["_source"]
        # Supplement trace from audit index
        data["trace"] = await self._fetch_trace(event_id)
        return EventRecord(**data)

    async def list_events(
        self,
        status: str | None = None,
        verdict: str | None = None,
        priority: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EventRecord]:
        must = []
        if status:
            must.append({"term": {"status": status}})
        if verdict:
            must.append({"term": {"final_verdict": verdict}})
        if priority:
            must.append({"term": {"priority": priority}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}

        resp = await self._es.search(
            index=self._events_index,
            query=query,
            sort=[{"submitted_at": {"order": "desc"}}],
            from_=offset,
            size=limit,
        )
        return [EventRecord(**h["_source"]) for h in resp["hits"]["hits"]]

    async def total_count(self) -> int:
        resp = await self._es.count(index=self._events_index)
        return resp["count"]

    async def update_event(self, event_id: str, **kwargs) -> None:
        doc = {k: v for k, v in kwargs.items() if v is not None}
        if not doc:
            return
        # V13 P2-10: updating a vanished event must not surface an ES
        # NotFoundError to callers (e.g. the Kafka consumer redelivery
        # path) as a hard failure -- the event is simply gone.
        try:
            await self._es.update(index=self._events_index, id=event_id, doc=doc)
        except NotFoundError:
            return
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
        """Write a trace step to audit index (appended to event's trace on read)."""
        doc = {
            "doc_id": str(uuid.uuid4()),
            "event_id": event_id,
            "node": step.node,
            "action": step.action,
            "summary": step.summary,
            "details": step.details,
            "timestamp": step.timestamp or datetime.now(UTC).isoformat(),
        }
        await self._es.index(index=self._audit_index, document=doc)
        try:
            from src.api.events_bus import get_event_bus

            await get_event_bus().publish(
                f"events:{event_id}",
                {"type": "trace_update", "event_id": event_id, "node": step.node},
            )
        except Exception:
            pass

    async def add_approval(self, event_id: str, approval: ApprovalEntry) -> None:
        await self._es.update(
            index=self._events_index,
            id=event_id,
            script={
                "source": "ctx._source.approvals.add(params.approval)",
                "params": {"approval": approval.model_dump()},
                "lang": "painless",
            },
        )

    async def metrics(self) -> dict:
        resp = await self._es.search(
            index=self._events_index,
            aggs={
                "by_verdict": {
                    "terms": {"field": "final_verdict", "size": 20, "missing": "unknown"}
                },
                "by_priority": {"terms": {"field": "priority", "size": 10, "missing": "none"}},
                "avg_duration": {"avg": {"field": "duration_ms"}},
            },
            size=0,
        )
        pa = await self._es.count(
            index=self._events_index, query={"term": {"status": "pending_approval"}}
        )
        aggs = resp.get("aggregations", {})
        return {
            "total_events": resp["hits"]["total"]["value"],
            "by_verdict": {
                b["key"]: b["doc_count"] for b in aggs.get("by_verdict", {}).get("buckets", [])
            },
            "by_priority": {
                b["key"]: b["doc_count"] for b in aggs.get("by_priority", {}).get("buckets", [])
            },
            "pending_approvals": pa["count"],
            "avg_duration_ms": round(aggs.get("avg_duration", {}).get("value", 0) or 0),
        }

    async def close(self) -> None:
        await self._es.close()

    async def _fetch_trace(self, event_id: str) -> list[TraceStep]:
        # Query event_id.keyword, NOT event_id. The audit index has no explicit
        # mapping, so ES dynamic-maps event_id as text+keyword. event_id is a
        # UUID (e.g. 550e8400-e29b-41d4-a716-446655440000); a `term` query on
        # the text field matches against analyzed tokens, and the standard
        # analyzer splits the UUID on hyphens -> no single token equals the
        # full id -> 0 matches -> the event detail page showed "暂无推理轨迹"
        # even though add_trace_step wrote the steps. .keyword is the exact,
        # unanalyzed value and matches correctly.
        # P0 修复(2026-08-06 全量测试):audit index 的 event_id 实际 mapping
        # 是 keyword(无 .keyword 子字段),原查询 term event_id.keyword 永远
        # 0 命中 → 事件详情页 trace 永远为空(即使 add_trace_step 写成功)。
        # 兼容两种索引形态:keyword 类型直接 term event_id;text+keyword 老索引
        # 用 event_id.keyword。bool should 任一命中即可。
        resp = await self._es.search(
            index=self._audit_index,
            query={
                "bool": {
                    "should": [
                        {"term": {"event_id": event_id}},
                        {"term": {"event_id.keyword": event_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            sort=[{"timestamp": "asc"}],
            # V13 P2-10: 100 hard-capped the trace for long pipelines (the
            # investigation/vuln-check/respond chain writes ~20-30 steps per
            # event; LLM-heavy runs can exceed 100 with retries).
            size=1000,
        )
        return [
            TraceStep(
                node=h["_source"].get("node", "?"),
                action=h["_source"].get("action", ""),
                summary=h["_source"].get("summary", ""),
                timestamp=h["_source"].get("timestamp", ""),
                details=h["_source"].get("details", {}),
            )
            for h in resp["hits"]["hits"]
        ]


_es_store: ESEventStore | None = None


def get_es_event_store() -> ESEventStore:
    global _es_store
    if _es_store is None:
        _es_store = ESEventStore()
    return _es_store
