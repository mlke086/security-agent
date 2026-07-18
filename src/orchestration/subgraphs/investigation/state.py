from typing import Any

from typing_extensions import TypedDict


class InvestigationSubState(TypedDict):
    event_id: str
    raw_event: dict[str, Any]
    iocs: dict[str, list[str]]
    raw_intel: dict[str, Any] | None
    graph_relations: list[dict[str, Any]]
    investigation_log: list[str]
    final_verdict: str | None
    confidence_score: float | None
    evidence_summary: str | None
    mitre_ttps: list[str]
