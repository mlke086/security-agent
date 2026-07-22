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
        await store.add_trace_step(
            event_id,
            TraceStep(
                node=audit_entry.get("node", "?"),
                action="processed",
                summary=audit_entry.get("summary", ""),
                timestamp=audit_entry.get("ts", ""),
                details={},
            ),
        )

    pending = result.get("pending_action") or {}
    status = _status_from_result(pending, result.get("error"))

    # P2-CORE-NEW-6 (2026-07-20): persist execution_summary on the event
    # record so operators can see what each approved response actually did.
    # Previously this was returned in pending_action but never written to
    # the store -- L1/L2 auto-approved runs had no audit trail of which
    # operations fired.
    exec_summary = pending.get("execution_summary")
    await store.update_event(
        event_id,
        status=status,
        final_verdict=verdict,
        confidence=confidence,
        priority=result.get("priority"),
        tags=result.get("event_tags", []),
        duration_ms=duration_ms,
        finished_at=datetime.now(UTC).isoformat(),
        pending_approval_id=pending.get("approval_id"),
        execution_summary=exec_summary,
    )

    logger.info("pipeline_complete", event_id=event_id, verdict=verdict, duration_ms=duration_ms)
    return result


def _status_from_result(pending: dict, error: str | None) -> str:
    """Derive the event-store status from the graph result.

    P1-CORE-NEW-1: hitl_approval_node blocks until the approval reaches a
    terminal state (approved/rejected/timeout), so by the time respond_node
    returns, ``approval_id`` being set does NOT mean "still pending" -- it
    means a decision was made. The old code treated approval_id presence as
    pending_approval, mis-storing every L3+ event (approved+executed,
    rejected, timeout) as pending_approval.

    Mapping:
      responder error/timeout (no pending_action) -> "error"
      L1/L2 auto-approve (approval_id None, status approved) -> "completed"
      L3+ approved -> "completed"
      L3+ rejected -> "rejected"
      L3+ timeout -> "error"
      approval_id set but no terminal status -> "pending_approval" (defensive)
    """
    if error:
        return "error"
    approval_status = pending.get("approval_status")
    if approval_status == "approved":
        return "completed"
    if approval_status == "rejected":
        return "rejected"
    if approval_status == "timeout":
        return "error"
    if pending.get("approval_id"):
        return "pending_approval"
    return "completed"
