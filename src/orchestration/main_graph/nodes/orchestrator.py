from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.common.logging.logger import get_logger
from src.knowledge.models.adapter import get_model_adapter
from src.orchestration.main_graph.state import AuditEntry, MainGraphState

logger = get_logger(__name__)

# ---------- Honeypot rule: direct high-priority without LLM ----------
_HONEYPOT_COMMANDS = frozenset(["whoami", "id", "uname", "ifconfig", "cat /etc/passwd"])


def _honeypot_rule(text: str) -> bool:
    lower = text.lower()
    return any(cmd in lower for cmd in _HONEYPOT_COMMANDS)


# ---------- Pydantic output schema ----------
class TriageResult(BaseModel):
    priority: Literal["high", "medium", "low"]
    event_tags: list[str] = Field(default_factory=list)
    noise_score: float = Field(ge=0.0, le=1.0)
    reasoning: str


_FEW_SHOT = """
Examples:
- Event: honeypot captured "whoami && id" from 45.33.32.156 → priority: high, tags: ["honeypot","lateral_movement"]
- Event: port scan from 192.168.1.5 on internal network → priority: low, tags: ["scan"], noise_score: 0.9
- Event: CVE-2024-1234 exploit attempt on prod-api-01 → priority: high, tags: ["vulnerability","exploit"]
- Event: failed login admin/admin on vpn-gw from 10.0.0.1 → priority: low, tags: ["brute_force"], noise_score: 0.85
- Event: lateral movement RDP from compromised workstation → priority: high, tags: ["lateral_movement"]
"""


async def orchestrator_node(state: MainGraphState) -> dict[str, Any]:
    raw_text = str(state.get("raw_event", {}).get("sanitized_text", ""))

    # Fast rule path — skip LLM for obvious honeypot activity
    if _honeypot_rule(raw_text):
        result = TriageResult(
            priority="high",
            event_tags=["honeypot"],
            noise_score=0.0,
            reasoning="Honeypot rule match",
        )
    else:
        adapter = get_model_adapter()
        prompt = (
            f"{_FEW_SHOT}\n\n"
            f"Classify this security event:\n{raw_text[:2000]}\n\n"
            "Return JSON matching the schema."
        )
        result = await adapter.chat_completion(
            messages=[{"role": "user", "content": prompt}],
            schema=TriageResult,
        )

    entry: AuditEntry = {
        "node": "orchestrator",
        "ts": datetime.now(UTC).isoformat(),
        "summary": f"priority={result.priority} tags={result.event_tags} noise={result.noise_score:.2f}",
    }
    logger.info("triage_complete", **entry)

    return {
        "priority": result.priority,
        "event_tags": result.event_tags,
        "stage": "route",
        "audit_log": [entry],
    }
