"""Operations & approval routers."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.api.auth.routes import require_role
from src.api.store import ApprovalEntry, EventRecord, get_event_store
from src.common.audit.audit_logger import get_audit_logger
from src.common.logging.logger import get_logger
from src.orchestration.subgraphs.responder.hitl_handler import (
    list_pending_approvals as _list_pending_approvals,
)
from src.orchestration.subgraphs.responder.hitl_handler import resolve_approval_by_event_id

logger = get_logger(__name__)
router = APIRouter(tags=["operations"])


class EventListResponse(BaseModel):
    items: list[EventRecord]
    total: int


class TraceResponse(BaseModel):
    event_id: str
    trace: list[dict[str, Any]]
    approvals: list[ApprovalEntry]
    trace_count: int
    approval_count: int


class ApprovalListResponse(BaseModel):
    items: list[dict[str, Any]]


class ApprovalActionResponse(BaseModel):
    status: str
    event_id: str
    action: str


class MetricsResponse(BaseModel):
    total_events: int
    by_verdict: dict[str, int]
    by_priority: dict[str, int]
    pending_approvals: int
    avg_duration_ms: int


class TimelinePoint(BaseModel):
    time: str
    total: int
    true_positive: int
    false_positive: int
    other: int


class TimelineResponse(BaseModel):
    timeline: list[TimelinePoint]


# ── Events ──────────────────────────────────────────────────


@router.get("/api/v1/events", response_model=EventListResponse)
async def list_events(
    status: str | None = None,
    verdict: str | None = None,
    priority: str | None = None,
    limit: int = 50,
    offset: int = 0,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_event_store()
    items = await store.list_events(
        status=status, verdict=verdict, priority=priority, limit=limit, offset=offset
    )
    return EventListResponse(items=items, total=await store.total_count())


@router.get("/api/v1/events/{event_id}", response_model=EventRecord)
async def get_event_detail(
    event_id: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_event_store()
    ev = await store.get_event(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev


@router.get("/api/v1/events/{event_id}/trace", response_model=TraceResponse)
async def get_event_trace(
    event_id: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """Get reasoning trace for an event (trace steps aggregated from the store)."""
    store = get_event_store()
    ev = await store.get_event(event_id)
    trace = [s.model_dump() for s in ev.trace] if ev else []
    approvals = list(ev.approvals) if ev else []
    return TraceResponse(
        event_id=event_id,
        trace=trace,
        approvals=approvals,
        trace_count=len(trace),
        approval_count=len(approvals),
    )


# ── Approvals ────────────────────────────────────────────────


@router.get("/api/v1/approvals", response_model=ApprovalListResponse)
async def get_approvals(
    current_user=Depends(require_role("admin", "responder", "analyst")),
):
    return ApprovalListResponse(items=await _list_pending_approvals())


@router.post("/api/v1/events/{event_id}/approve", response_model=ApprovalActionResponse)
async def approve_event(
    event_id: str,
    action: str = "approved",
    note: str = "",
    current_user=Depends(require_role("admin", "responder")),
):
    store = get_event_store()
    ev = await store.get_event(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")

    entry = ApprovalEntry(
        event_id=event_id,
        action=action,
        note=note,
        actor=current_user.username,
        role=current_user.role,
        timestamp=datetime.now(UTC).isoformat(),
    )
    await store.add_approval(event_id, entry)

    # P2-CORE-NEW-10 (2026-07-20): vote through ApprovalStore so the
    # multi-reviewer quorum is honoured. add_vote() only flips approval
    # status to "approved" once the required vote count is met; mirror
    # that onto the event so we don't flip the event to "completed"
    # before the second reviewer has voted on an L4/L5 op.
    from src.orchestration.subgraphs.responder.approval_store import (
        get_approval_store,
    )

    vote_result = await get_approval_store().add_vote(
        event_id=event_id,
        actor=current_user.username,
        decision=action,
    )
    approval_status = vote_result.get("status", "pending")
    if approval_status == "approved":
        await store.update_event(event_id, status="completed")
    elif approval_status == "rejected":
        await store.update_event(event_id, status="rejected")
    # else: pending -- keep the event status as-is until the quorum is met.

    try:
        await resolve_approval_by_event_id(event_id, action, actor=current_user.username)
    except Exception as exc:
        # Non-fatal: the vote is persisted; any blocked wait_result() will
        # pick it up via the next PG poll.
        logger.warning("approval_resolve_notify_failed", event_id=event_id, error=str(exc))
    await get_audit_logger().log(
        event_id=event_id,
        node="approval",
        action=action,
        actor=current_user.username,
        details={"note": note},
    )

    logger.info(
        "event_approved",
        event_id=event_id,
        action=action,
        actor=current_user.username,
        approval_status=approval_status,
        vote_count=vote_result.get("count", 0),
    )
    return ApprovalActionResponse(status="ok", event_id=event_id, action=action)


# ── Metrics ──────────────────────────────────────────────────


@router.get("/api/v1/metrics", response_model=MetricsResponse)
async def get_metrics(
    current_user=Depends(require_role("admin", "analyst")),
):
    return MetricsResponse(**(await get_event_store().metrics()))


@router.get("/api/v1/metrics/timeline", response_model=TimelineResponse)
async def get_metrics_timeline(
    window: str = "1h",
    current_user=Depends(require_role("admin", "analyst")),
):
    """Return event counts grouped by hour for dashboard trend chart."""
    store = get_event_store()
    items = await store.list_events(limit=200)
    from collections import defaultdict

    hourly: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "true_positive": 0, "false_positive": 0, "other": 0}
    )
    for ev in items:
        hour = ev.submitted_at[:13] if ev.submitted_at else "unknown"
        hourly[hour]["total"] += 1
        if ev.final_verdict == "true_positive":
            hourly[hour]["true_positive"] += 1
        elif ev.final_verdict == "false_positive":
            hourly[hour]["false_positive"] += 1
        else:
            hourly[hour]["other"] += 1
    return TimelineResponse(
        timeline=[TimelinePoint(time=k, **v) for k, v in sorted(hourly.items())]
    )
