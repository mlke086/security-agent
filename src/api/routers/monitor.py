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
