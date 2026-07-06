from typing import Any, Literal

from pydantic import BaseModel, Field

from src.common.logging.logger import get_logger
from src.knowledge.models.adapter import get_model_adapter
from src.orchestration.subgraphs.investigation.state import InvestigationSubState

logger = get_logger(__name__)

_COT_PROMPT = """You are a senior security investigator. Use Chain-of-Thought reasoning:

Step 1: Analyze the IOC characteristics
Step 2: Compare with threat intelligence
Step 3: Identify attack chain and TTPs
Step 4: Cross-validate internal and external evidence
Step 5: Output final verdict with confidence

Event:
{event_text}

Intelligence:
{intel_summary}

Return JSON: verdict (true_positive|false_positive|benign), confidence (0-1),
evidence_summary (≤100 chars), mitre_ttps (list), recommended_action (string)
"""


class VerdictResult(BaseModel):
    verdict: Literal["true_positive", "false_positive", "benign"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_summary: str
    mitre_ttps: list[str]
    recommended_action: str


async def investigator_node(state: InvestigationSubState) -> dict[str, Any]:
    raw_event = state.get("raw_event", {})
    raw_intel = state.get("raw_intel", {})

    prompt = _COT_PROMPT.format(
        event_text=str(raw_event.get("sanitized_text", ""))[:1500],
        intel_summary=str(raw_intel)[:1000],
    )

    adapter = get_model_adapter()
    result = await adapter.chat_completion(
        messages=[{"role": "user", "content": prompt}],
        schema=VerdictResult,
    )

    log_entry = f"Investigator: verdict={result.verdict} confidence={result.confidence:.2f}"
    logger.info("investigation_complete", event_id=state.get("event_id"), verdict=result.verdict)

    return {
        "final_verdict": result.verdict,
        "confidence_score": result.confidence,
        "evidence_summary": result.evidence_summary,
        "mitre_ttps": result.mitre_ttps,
        "investigation_log": state.get("investigation_log", []) + [log_entry],
    }
