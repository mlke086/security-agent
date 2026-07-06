from typing import Any

from pydantic import BaseModel

from src.common.logging.logger import get_logger
from src.execution.linter.poc_linter import PoCLinter
from src.execution.sandbox.executor import SandboxExecutor
from src.knowledge.models.adapter import get_model_adapter
from src.orchestration.subgraphs.vuln_hunter.memory import VulnHunterMemory
from src.orchestration.subgraphs.vuln_hunter.state import VulnHunterSubState

logger = get_logger(__name__)

MAX_ITERATIONS = 10
_linter = PoCLinter()
_sandbox = SandboxExecutor()


class PoCOutput(BaseModel):
    poc_code: str
    reasoning: str
    updated_constraints: list[str]


_PROMPT_TEMPLATE = """You are a security researcher generating PoC exploit code.

<memory_history>
{memory_history}
</memory_history>

<constraints>
{constraints}
</constraints>

<target>
{target_info}
</target>

<current_task>
Generate iteration {iteration} PoC. MUST avoid all failed paths. Return JSON with:
- poc_code: the Python exploit code (only allowed imports: requests,socket,json,re,time,sys,struct,hashlib,base64)
- reasoning: why this approach should work
- updated_constraints: any new constraints discovered
</current_task>"""


def _build_memory_history(memory: VulnHunterMemory) -> str:
    lines = []
    for i, poc in enumerate(memory.poc_candidates, 1):
        snippet = poc[:200].replace("\n", " ")
        lines.append(f'<iteration round="{i}"><poc_tried>{snippet}...</poc_tried></iteration>')
    if memory.negative_evidence:
        lines.append("<negative_paths>" + " | ".join(memory.negative_evidence) + "</negative_paths>")
    return "\n".join(lines)


async def generate_poc_node(state: VulnHunterSubState) -> dict[str, Any]:
    memory: VulnHunterMemory = state["memory"]
    memory.increment_iteration()

    prompt = _PROMPT_TEMPLATE.format(
        memory_history=_build_memory_history(memory),
        constraints="\n".join(f"- {c}" for c in memory.constraints),
        target_info=memory.target_info,
        iteration=memory.iteration_count,
    )

    adapter = get_model_adapter()
    result = await adapter.chat_completion(
        messages=[{"role": "user", "content": prompt}],
        schema=PoCOutput,
    )

    for constraint in result.updated_constraints:
        memory.add_constraint(constraint)

    return {"current_poc": result.poc_code, "memory": memory}


async def linter_check_node(state: VulnHunterSubState) -> dict[str, Any]:
    code = state.get("current_poc") or ""
    lint_result = _linter.check(code)

    if not lint_result.passed:
        memory: VulnHunterMemory = state["memory"]
        evidence = f"Round {memory.iteration_count}: Linter rejected — {lint_result.error_detail}"
        memory.add_negative_evidence(evidence)
        if lint_result.suggestion:
            memory.add_constraint(lint_result.suggestion)
        return {"memory": memory, "last_exec_result": {"status": "linter_fail", "detail": lint_result.error_detail}}

    return {}


async def sandbox_exec_node(state: VulnHunterSubState) -> dict[str, Any]:
    last = state.get("last_exec_result") or {}
    if last.get("status") == "linter_fail":
        return {}

    code = state.get("current_poc") or ""
    exec_result = await _sandbox.execute(code)

    memory: VulnHunterMemory = state["memory"]
    if not exec_result.is_vulnerable:
        evidence = f"Round {memory.iteration_count}: Sandbox {exec_result.status} — {exec_result.stderr[:100]}"
        memory.add_negative_evidence(evidence)

    return {
        "last_exec_result": exec_result.model_dump(),
        "memory": memory,
    }


async def finalize_node(state: VulnHunterSubState) -> dict[str, Any]:
    memory: VulnHunterMemory = state["memory"]
    exec_result = state.get("last_exec_result") or {}
    is_vulnerable = exec_result.get("is_vulnerable", False)

    if is_vulnerable:
        memory.final_poc = state.get("current_poc")
        return {
            "final_poc": memory.final_poc,
            "is_vulnerable": True,
            "exploit_chain": f"Verified in {memory.iteration_count} iterations",
            "memory": memory,
        }

    return {
        "final_poc": None,
        "is_vulnerable": False,
        "exploit_chain": f"Not reproduced after {memory.iteration_count} iterations",
        "memory": memory,
    }


def check_convergence(state: VulnHunterSubState) -> str:
    exec_result = state.get("last_exec_result") or {}
    memory: VulnHunterMemory = state["memory"]

    if exec_result.get("is_vulnerable"):
        return "finalize"
    if memory.iteration_count >= MAX_ITERATIONS:
        return "finalize"
    return "generate_poc"
