from datetime import UTC, datetime
from typing import Any

from src.common.audit.audit_logger import get_audit_logger
from src.common.logging.logger import get_logger
from src.orchestration.main_graph.state import AuditEntry, MainGraphState

logger = get_logger(__name__)


async def aggregator_node(state: MainGraphState) -> dict[str, Any]:
    sub = state.get("subgraph_result") or {}
    verdict = sub.get("final_verdict", "unknown")
    confidence = sub.get("confidence_score", 0.0)

    entry: AuditEntry = {
        "node": "aggregator",
        "ts": datetime.now(UTC).isoformat(),
        "summary": f"verdict={verdict} confidence={confidence}",
    }
    try:
        audit = get_audit_logger()
        await audit.log(event_id=state["event_id"], node="aggregator", action=verdict)
    except Exception:
        pass
    logger.info("aggregation_complete", event_id=state["event_id"], verdict=verdict)

    # Preserve the upstream "stage" so route_after_verdict can still tell that
    # this aggregation came from the vuln-check subgraph (P1-CORE-1). The default
    # for first-pass investigation is "investigate"; vuln_hunter sets
    # "stage": "verify" on its result.
    preserved_stage = state.get("stage") or "investigate"

    return {
        "final_verdict": verdict,
        "confidence_score": confidence,
        "stage": preserved_stage,
        "audit_log": [entry],
    }


async def ignore_node(state: MainGraphState) -> dict[str, Any]:
    entry: AuditEntry = {
        "node": "ignore",
        "ts": datetime.now(UTC).isoformat(),
        "summary": "Event archived as low-priority / noise",
    }
    logger.info("event_ignored", event_id=state["event_id"])

    return {
        "final_verdict": "ignored",
        "stage": "done",
        "audit_log": [entry],
    }
