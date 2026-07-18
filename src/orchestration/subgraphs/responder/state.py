from typing import Any

from typing_extensions import TypedDict


class ResponderSubState(TypedDict):
    event_id: str
    verdict: str
    confidence: float
    event_tags: list[str]
    recommended_action: str
    iocs: dict[str, Any]
    playbook_draft: dict[str, Any] | None
    operation_level: str | None
    approval_id: str | None
    approval_status: str | None  # pending | approved | rejected | timeout
    execution_result: dict[str, Any] | None
