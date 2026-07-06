from typing import Any
from typing_extensions import TypedDict

from src.orchestration.subgraphs.vuln_hunter.memory import VulnHunterMemory


class VulnHunterSubState(TypedDict):
    event_id: str
    cve_info: dict[str, Any]
    memory: VulnHunterMemory
    current_poc: str | None
    last_exec_result: dict[str, Any] | None
    final_poc: str | None
    is_vulnerable: bool
    exploit_chain: str | None
