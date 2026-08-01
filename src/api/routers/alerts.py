"""Alerts router (Phase 1 of monitoring plan).

Endpoints:
  POST /api/v1/alerts/ingest   - accept a vendor-specific JSON, normalize,
                                 persist via AlertStore. This is the primary
                                 inbound path for Wazuh / Elkeid / Syslog
                                 integrations (Phase 1) and the others in
                                 later phases.
  GET  /api/v1/alerts          - list alerts with optional filters.
  GET  /api/v1/alerts/{id}     - single alert.
  PATCH /api/v1/alerts/{id}/status - acknowledge / resolve / false-positive.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from src.agents.alert_store import get_alert_store
from src.agents.models import AlertIngestRequest, AlertIngestResponse
from src.api.auth.routes import require_role
from src.common.logging.logger import get_logger
from src.preprocessing.edr_adapter import normalize

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.post("/ingest", response_model=AlertIngestResponse)
async def ingest_alert(
    body: AlertIngestRequest,
    current_user=Depends(require_role("admin", "analyst")),
) -> AlertIngestResponse:
    """Normalize a vendor JSON into our common Alert model and persist.

    The `source` field in the body is the canonical hint, but if a future
    adapter ships raw bytes (e.g. syslog over webhook) we let the normalizer
    fall back to its default mapping.
    """
    try:
        alert = normalize(body.payload, body.source)
    except Exception as exc:
        logger.warning("alert_normalize_failed", source=str(body.source), error=str(exc))
        raise HTTPException(status_code=400, detail=f"normalize failed: {exc}")

    store = get_alert_store()
    try:
        await store.save_alert(alert)
    except Exception as exc:
        logger.error("alert_persist_failed", alert_id=alert.alert_id, error=str(exc))
        raise HTTPException(status_code=500, detail="persist failed")

    logger.info(
        "alert_ingested",
        alert_id=alert.alert_id,
        source=str(alert.source),
        severity=str(alert.severity),
        hostname=alert.hostname,
    )
    return AlertIngestResponse(
        alert_id=alert.alert_id,
        received_at=alert.received_at,
        severity=alert.severity,
    )


@router.get("")
async def list_alerts(
    severity: str | None = Query(default=None, description="critical/high/medium/low/info"),
    status: str | None = Query(
        default=None, description="new/acknowledged/in_progress/resolved/false_positive"
    ),
    source: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    store = get_alert_store()
    try:
        rows = await store.list_alerts(
            severity=severity,
            status=status,
            source=source,
            hostname=hostname,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {
        "items": [_serialise(r) for r in rows],
        "limit": limit,
        "offset": offset,
        "count": len(rows),
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    store = get_alert_store()
    row = await store.get_alert(alert_id)
    if not row:
        raise HTTPException(status_code=404, detail="alert not found")
    return _serialise(row)


@router.patch("/{alert_id}/status")
async def update_status(
    alert_id: str,
    body: dict,
    current_user=Depends(require_role("admin", "analyst", "responder")),
) -> dict:
    """Update operator workflow state (new -> acknowledged -> in_progress -> resolved)."""
    new_status = body.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="status field required")
    valid = ("new", "acknowledged", "in_progress", "resolved", "false_positive")
    if new_status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid}")
    store = get_alert_store()
    ok = await store.update_alert_status(alert_id, new_status)
    if not ok:
        raise HTTPException(status_code=404, detail="alert not found")
    return {"alert_id": alert_id, "status": new_status, "updated_at": datetime.now(UTC).isoformat()}


def _serialise(row: dict) -> dict:
    """Convert asyncpg Record (dict) into a JSON-friendly dict.

    asyncpg returns datetime as Python datetime; convert to ISO 8601.
    JSONB columns come back as raw strings (since we serialize on insert);
    parse them back into dicts/list so the UI gets structured data.
    """
    import json

    out = {}
    for k, v in row.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        elif k in ("iocs", "mitre_attack", "tags", "raw") and isinstance(v, str):
            try:
                out[k] = json.loads(v)
            except (TypeError, ValueError):
                out[k] = v
        else:
            out[k] = v
    return out
