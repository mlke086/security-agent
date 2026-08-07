"""Monitor router (Phase 5 of monitoring plan).

Endpoints:
  GET /api/v1/agents/{agent_id}/monitor
      List the most recent monitor snapshots for one agent. Returns
      a slim shape (no full process list) because the console drawer
      only needs a timeline; the heavy payload can be added later
      if a particular UI needs it.

RBAC: admin/analyst/viewer all read. This is read-only telemetry, not
a defensive action.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Path, Query

from src.agents.monitor_store import get_monitor_store
from src.api.auth.routes import require_role

router = APIRouter(prefix="/api/v1/agents", tags=["monitor"])


@router.get("/{agent_id}/monitor")
async def list_monitor_events(
    agent_id: str = Path(..., min_length=1, max_length=128),
    limit: int = Query(
        default=20, ge=1, le=200, description="Max snapshots to return (most recent first)"
    ),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    """Return the most recent N monitor snapshots for ``agent_id``."""
    store = get_monitor_store()
    rows = await store.list_events(agent_id, limit=limit)
    return {
        "agent_id": agent_id,
        "items": rows,
        "count": len(rows),
        "limit": limit,
    }


# -- host performance metrics (需求①: Agent 性能监控, 2026-08-06) ------------

_METRICS_RANGES = {"1h": 3600, "24h": 86400, "7d": 604800}


@router.get("/{agent_id}/metrics")
async def list_host_metrics(
    agent_id: str = Path(..., min_length=1, max_length=128),
    range_: str = Query(default="24h", alias="range", pattern="^(1h|24h|7d)$"),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    """Return host performance time-series for ``agent_id`` (需求①).

    ``range=1h|24h`` returns raw points (ts asc); ``range=7d`` returns
    downsampled points (date_histogram avg, interval from
    ``metrics_downsample_7d_interval``, default 5m) so the response stays
    ~2k points instead of 40k raw docs. ``latest`` is the most recent
    sample (for the drawer's mini cards). Old agents that never report
    host_metrics yield an empty ``points`` list -- the frontend shows the
    "Agent 版本过低/未上报" hint.
    """
    from datetime import timedelta

    from src.agents.metrics_store import get_metrics_store
    from src.common.config.settings import get_settings

    now = datetime.now(UTC)
    since = now - timedelta(seconds=_METRICS_RANGES[range_])
    settings = get_settings()
    downsample = settings.metrics_downsample_7d_interval if range_ == "7d" else None
    store = get_metrics_store()
    points = await store.query_timeseries(
        agent_id,
        since.isoformat(),
        now.isoformat(),
        downsample_interval=downsample,
    )
    latest = await store.latest(agent_id)
    return {
        "agent_id": agent_id,
        "range": range_,
        "points": points,
        "latest": latest,
    }


@router.get("/{agent_id}/metrics/latest")
async def get_latest_host_metrics(
    agent_id: str = Path(..., min_length=1, max_length=128),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    """Return the single most recent host performance sample (需求①).

    Lightweight counterpart of the time-series endpoint, used by the
    host-row mini indicators; returns ``{"agent_id": ..., "present": False}``
    when the agent never reported metrics.
    """
    from src.agents.metrics_store import get_metrics_store

    latest = await get_metrics_store().latest(agent_id)
    if latest is None:
        return {"agent_id": agent_id, "present": False}
    return {"agent_id": agent_id, "present": True, **latest}
