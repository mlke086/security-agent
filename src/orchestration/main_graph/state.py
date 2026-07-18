import operator
from typing import Annotated, Any

from typing_extensions import TypedDict


class AuditEntry(TypedDict):
    node: str
    ts: str
    summary: str


class MainGraphState(TypedDict):
    event_id: str
    raw_event: dict[str, Any]
    priority: str                          # high | medium | low
    event_tags: list[str]
    stage: str                             # triage | investigate | verify | respond | done
    final_verdict: str | None
    confidence_score: float | None
    pending_action: dict[str, Any] | None
    subgraph_result: dict[str, Any] | None
    error: str | None
    audit_log: Annotated[list[AuditEntry], operator.add]
