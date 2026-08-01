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

    # P0 (2026-07-31): engine + nuclei knobs MUST be declared in the TypedDict
    # so LangGraph / checkpointer does not silently drop them across node
    # boundaries. _default_state sets these; dispatch reads them to build the
    # scan_command payload. Without explicit keys here they were stripped during
    # state transitions, causing every scan to run as "matcher" regardless of
    # the operator's selection.
    nuclei_timeout_sec: int
    engine: str
    nuclei_severity: list[str]
    nuclei_tags: list[str]
    nuclei_templates: list[str]
    target_groups: list[str]

    nuclei_ports: list[int]
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

    # AI processing flag (V10 stage 2.2: generate_report reads this from state)
    ai_processed: bool

    # Messages for LLM interaction
    messages: Annotated[list, add_messages]
