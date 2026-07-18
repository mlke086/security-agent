"""Shared pipeline runner — extracted from main.py for API + Consumer reuse."""

import time
from datetime import UTC, datetime
from typing import Any

from src.api.store import TraceStep, get_event_store
from src.common.logging.logger import get_logger
from src.orchestration.main_graph.graph import get_compiled_graph

logger = get_logger(__name__)


async def run_pipeline(event_id: str, text: str, iocs: dict, source: str) -> dict[str, Any]:
    """Run the LangGraph pipeline, persist results via EventStore.

    Returns the full graph result dict (verdict, confidence, etc.).
    Raises on failure — caller decides error handling (suppress for API,
    retry/no-commit for Kafka consumer).
    """
    store = get_event_store()
    await store.create_event(event_id, text, iocs, source)

    t0 = time.time()
    graph = get_compiled_graph()
    raw_event = {"event_id": event_id, "sanitized_text": text, "iocs": iocs, "source": source}
    result = await graph.ainvoke({"event_id": event_id, "raw_event": raw_event, "audit_log": []})
    duration_ms = int((time.time() - t0) * 1000)

    sub = result.get("subgraph_result") or {}
    verdict = sub.get("final_verdict", result.get("final_verdict", "unknown"))
    confidence = sub.get("confidence_score", result.get("confidence_score"))

    for audit_entry in result.get("audit_log", []):
        await store.add_trace_step(event_id, TraceStep(
            node=audit_entry.get("node", "?"),
            action="processed",
            summary=audit_entry.get("summary", ""),
            timestamp=audit_entry.get("ts", ""),
            details={},
        ))

    pending = result.get("pending_action") or {}
    status = "pending_approval" if pending.get("approval_id") else "completed"

    await store.update_event(
        event_id,
        status=status, final_verdict=verdict, confidence=confidence,
        priority=result.get("priority"), tags=result.get("event_tags", []),
        duration_ms=duration_ms,
        finished_at=datetime.now(UTC).isoformat(),
        pending_approval_id=pending.get("approval_id"),
    )

    logger.info("pipeline_complete", event_id=event_id, verdict=verdict, duration_ms=duration_ms)
    return result
