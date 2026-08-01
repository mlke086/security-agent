"""Detection router (Phase 3 of monitoring plan).

Endpoints:
  POST /api/v1/detect/run          - run Sigma rules against a single event.
                                       Each match is persisted as an Alert
                                       via AlertStore so the AlertInboxPage
                                       can surface it. Returns the list of
                                       alert_ids produced.
  GET  /api/v1/detect/rules        - list currently loaded Sigma rules.
  POST /api/v1/detect/rules/load   - (re)load the bundled builtin rules.
                                       Useful in tests and for ops to
                                       force a refresh after dropping
                                       custom rules.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.auth.routes import require_role
from src.common.logging.logger import get_logger
from src.detection.detector import get_detector, init_builtin_rules

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/detect", tags=["detection"])


class DetectRunRequest(BaseModel):
    event: dict[str, Any] = Field(
        ...,
        description="Raw event payload (any JSON the Sigma rules can match).",
    )
    event_id: str | None = Field(
        default=None,
        description="Optional caller-supplied event id. A uuid4 is generated if missing.",
    )


class DetectRunResponse(BaseModel):
    event_id: str
    matched: int
    alert_ids: list[str]
    rule_ids: list[str]


class RuleSummary(BaseModel):
    rule_id: str
    title: str
    level: str
    product: str
    service: str
    category: str


@router.post("/run", response_model=DetectRunResponse)
async def run_detection(
    body: DetectRunRequest,
    current_user=Depends(require_role("admin", "analyst")),
) -> DetectRunResponse:
    """Run all loaded Sigma rules against ``body.event`` and persist hits.

    Returns the matched alert_ids. Already-matched (rule_id, event_id)
    pairs are deduped by ``build_alert`` (sha256-derived stable id), so
    re-running the same input is safe.
    """
    event_id = body.event_id or str(uuid.uuid4())
    detector = get_detector()
    if not detector.list_rules():
        # First call before lifespan startup -- eagerly load builtin rules
        # so a standalone ``docker exec`` smoke test still works.
        init_builtin_rules()
    alerts = await detector.run_rules(body.event, event_id)
    return DetectRunResponse(
        event_id=event_id,
        matched=len(alerts),
        alert_ids=[a.alert_id for a in alerts],
        rule_ids=[a.rule_id for a in alerts],
    )


@router.get("/rules", response_model=list[RuleSummary])
async def list_rules(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> list[RuleSummary]:
    detector = get_detector()
    if not detector.list_rules():
        init_builtin_rules()
    return [
        RuleSummary(
            rule_id=r.rule_id,
            title=r.title,
            level=str(r.level.value if hasattr(r.level, "value") else r.level),
            product=r.product,
            service=r.service,
            category=r.category,
        )
        for r in detector.list_rules()
    ]


@router.post("/rules/load")
async def reload_builtin_rules(
    current_user=Depends(require_role("admin")),
) -> dict:
    n = init_builtin_rules()
    logger.info("detection_rules_reloaded", count=n)
    return {"loaded": n}
