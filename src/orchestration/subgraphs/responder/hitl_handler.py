import uuid
from typing import Any

import httpx
from langgraph.types import interrupt

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.subgraphs.responder.state import ResponderSubState

logger = get_logger(__name__)

_LEVEL_TIMEOUT: dict[str, int] = {
    "L3": 300,   # 5 minutes
    "L4": 900,   # 15 minutes
    "L5": 1800,  # 30 minutes
}


async def _push_approval_card(
    event_id: str,
    approval_id: str,
    playbook: dict,
    level: str,
    timeout_sec: int,
) -> None:
    settings = get_settings()
    text = (
        f"**安全事件审批请求**\n"
        f"事件 ID: {event_id}\n"
        f"操作等级: {level}\n"
        f"剧本: {playbook.get('description', '')}\n"
        f"操作数: {len(playbook.get('operations', []))}\n"
        f"审批超时: {timeout_sec // 60} 分钟\n"
        f"审批 ID: {approval_id}"
    )
    card = {"msgtype": "markdown", "markdown": {"content": text}}

    for webhook_url in filter(None, [settings.wechat_work_webhook, settings.dingtalk_webhook]):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(webhook_url, json=card)
        except Exception as exc:
            logger.warning("webhook_push_failed", error=str(exc))


async def hitl_approval_node(state: ResponderSubState) -> dict[str, Any]:
    level = state.get("operation_level", "L1")

    # L1 / L2: auto-execute, no approval needed
    if level in ("L1", "L2"):
        return {"approval_status": "approved", "approval_id": None}

    approval_id = str(uuid.uuid4())
    timeout_sec = _LEVEL_TIMEOUT.get(level, 300)

    await _push_approval_card(
        event_id=state["event_id"],
        approval_id=approval_id,
        playbook=state.get("playbook_draft") or {},
        level=level,
        timeout_sec=timeout_sec,
    )

    # Suspend graph execution waiting for human approval callback
    approval_result = interrupt({"approval_id": approval_id, "timeout_sec": timeout_sec})

    decision = approval_result.get("decision", "rejected") if isinstance(approval_result, dict) else "rejected"
    logger.info("hitl_decision", approval_id=approval_id, decision=decision)

    return {
        "approval_id": approval_id,
        "approval_status": decision,
    }


async def execute_response_node(state: ResponderSubState) -> dict[str, Any]:
    approval_status = state.get("approval_status", "rejected")
    if approval_status != "approved":
        logger.info("response_skipped", reason=approval_status, event_id=state["event_id"])
        return {"execution_result": {"status": "skipped", "reason": approval_status}}

    playbook = state.get("playbook_draft") or {}
    operations = playbook.get("operations", [])

    executed = []
    for op in operations:
        logger.info("executing_operation", type=op.get("type"), level=op.get("level"))
        executed.append({"type": op.get("type"), "status": "executed"})

    return {
        "execution_result": {
            "status": "completed",
            "executed_operations": executed,
            "approval_id": state.get("approval_id"),
        }
    }
