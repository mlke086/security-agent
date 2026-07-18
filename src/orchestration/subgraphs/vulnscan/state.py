"""VulnScan subgraph state TypedDict."""
from typing import Annotated, TypedDict

from langgraph.graph.message import add_messages


class VulnScanState(TypedDict):
    task_id: str
    source: str
    intent_text: str | None

    # Parsed intent
    targets: list[str]
    modules: list[str]
    resource_limit: dict
    schedule: str | None

    # Task tracking
    task: dict | None
    dispatched: bool
    total_targets: int
    received_results: int

    # Collected findings
    collected_findings: list[dict]

    # Report
    report: dict | None

    # Error handling
    error: str | None
    status: str

    # Messages for LLM interaction
    messages: Annotated[list, add_messages]
