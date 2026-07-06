import uuid
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel

from src.common.logging.logger import get_logger
from src.knowledge.models.adapter import get_model_adapter
from src.orchestration.subgraphs.responder.state import ResponderSubState

logger = get_logger(__name__)

_PLAYBOOK_DIR = Path(__file__).parent.parent.parent.parent / "orchestration" / "playbooks"

# Operation risk levels
OpLevel = Literal["L1", "L2", "L3", "L4", "L5"]

_LEVEL_KEYWORDS: dict[OpLevel, list[str]] = {
    "L1": ["tag", "alert", "notify", "log"],
    "L2": ["quarantine_file", "terminate_process"],
    "L3": ["firewall_block", "edr_policy", "dns_block"],
    "L4": ["isolate_host", "network_block", "bulk"],
    "L5": ["global_block", "shutdown", "wipe"],
}


class Operation(BaseModel):
    type: str
    level: OpLevel
    params: dict[str, Any] = {}


class Playbook(BaseModel):
    playbook_id: str
    description: str
    operations: list[Operation]
    max_level: OpLevel


def _infer_level(op_type: str) -> OpLevel:
    for level in ("L5", "L4", "L3", "L2"):
        if any(kw in op_type for kw in _LEVEL_KEYWORDS[level]):  # type: ignore[index]
            return level  # type: ignore[return-value]
    return "L1"


def _load_playbooks() -> list[dict]:
    playbooks = []
    if _PLAYBOOK_DIR.exists():
        for f in _PLAYBOOK_DIR.glob("*.yaml"):
            try:
                playbooks.extend(yaml.safe_load(f.read_text()))
            except Exception:
                pass
    return playbooks


class GeneratedPlaybook(BaseModel):
    playbook_id: str
    description: str
    operations: list[dict[str, Any]]


async def playbook_matcher_node(state: ResponderSubState) -> dict[str, Any]:
    verdict = state.get("verdict", "")
    iocs = state.get("iocs", {})
    confidence = state.get("confidence", 0.0)

    # Try rule-based match first
    all_playbooks = _load_playbooks()
    matched = None
    for pb in all_playbooks:
        trigger = pb.get("trigger", {})
        if (
            trigger.get("verdict") == verdict
            and confidence >= trigger.get("confidence_min", 0.0)
        ):
            matched = pb
            break

    if matched:
        operations = [Operation(type=op["type"], level=op.get("level", "L1"), params=op.get("params", {}))
                      for op in matched.get("operations", [])]
    else:
        # LLM-generated playbook
        adapter = get_model_adapter()
        prompt = (
            f"Security event: verdict={verdict}, confidence={confidence:.2f}, iocs={iocs}\n"
            "Generate a response playbook JSON with: playbook_id, description, operations "
            "(each with type and params). Use only these operation types: "
            "firewall_block, isolate_host, siem_tag, edr_policy, notify_analyst, dns_block"
        )
        generated: GeneratedPlaybook = await adapter.chat_completion(
            messages=[{"role": "user", "content": prompt}],
            schema=GeneratedPlaybook,
        )
        operations = [
            Operation(
                type=op["type"],
                level=_infer_level(op["type"]),
                params=op.get("params", {}),
            )
            for op in generated.operations
        ]

    max_level: OpLevel = "L1"
    level_rank = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
    for op in operations:
        if level_rank[op.level] > level_rank[max_level]:
            max_level = op.level

    playbook = Playbook(
        playbook_id=matched["playbook_id"] if matched else str(uuid.uuid4())[:8],
        description=matched.get("description", "Auto-generated playbook") if matched else "LLM generated",
        operations=operations,
        max_level=max_level,
    )

    return {
        "playbook_draft": playbook.model_dump(),
        "operation_level": max_level,
    }
