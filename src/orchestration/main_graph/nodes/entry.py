from datetime import UTC, datetime
from typing import Any

from src.common.audit.audit_logger import get_audit_logger
from src.common.logging.logger import get_logger
from src.orchestration.main_graph.state import AuditEntry, MainGraphState

logger = get_logger(__name__)


async def entry_node(state: MainGraphState) -> dict[str, Any]:
    """Validate incoming event and initialise processing state."""
    raw = state.get("raw_event", {})
    event_id = raw.get("event_id", "unknown")

    entry: AuditEntry = {
        "node": "entry",
        "ts": datetime.now(UTC).isoformat(),
        "summary": f"Event received: {event_id}",
    }
    try:
        audit = get_audit_logger()
        await audit.log(event_id=event_id, node="entry", action="received")
    except Exception:
        pass
    return {
        "event_id": event_id,
        "stage": "triage",
        "error": None,
        "audit_log": [entry],
    }
