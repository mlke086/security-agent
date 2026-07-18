"""hitl_handler.py — HITL approval workflow backed by Redis ApprovalStore."""

import uuid
from typing import Any

import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.subgraphs.responder.approval_store import get_approval_store
from src.orchestration.subgraphs.responder.state import ResponderSubState

logger = get_logger(__name__)

_LEVEL_TIMEOUT: dict[str, int] = {
    "L3": 300,
    "L4": 900,
    "L5": 1800,
}

_REQUIRED_APPROVERS: dict[str, int] = {
    "L3": 1,
    "L4": 2,
    "L5": 2,
}


# ── Backward-compatible wrappers over ApprovalStore ──────────


async def _add_pending_approval(approval_id: str, event_id: str, level: str, n_required: int = 1) -> None:
    store = get_approval_store()
    await store.create(approval_id, event_id, level, n_required)


async def list_pending_approvals() -> list[dict]:
    store = get_approval_store()
    return await store.list_pending()


async def get_pending_approval(approval_id: str) -> dict | None:
    store = get_approval_store()
    return await store.get(approval_id)


async def resolve_approval_by_event_id(event_id: str, decision: str, actor: str = "system") -> bool:
    store = get_approval_store()
    result = await store.add_vote(event_id, actor, decision)
    return result["status"] != "not_found"


# ── Webhook push ─────────────────────────────────────────────


async def _push_approval_card(
    event_id: str,
    approval_id: str,
    playbook: dict,
    level: str,
    timeout_sec: int,
) -> None:
    settings = get_settings()
    n_required = _REQUIRED_APPROVERS.get(level, 1)
    text = (
        f"**安全事件审批请求**\n"
        f"事件 ID: {event_id}\n"
        f"操作等级: {level}\n"
        f"需审批人数: {n_required}\n"
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


# ── Graph nodes ──────────────────────────────────────────────


async def hitl_approval_node(state: ResponderSubState) -> dict[str, Any]:
    level = state.get("operation_level") or "L1"

    if level in ("L1", "L2"):
        return {"approval_status": "approved", "approval_id": None}

    approval_id = str(uuid.uuid4())
    timeout_sec = get_settings().hitl_timeout_sec or _LEVEL_TIMEOUT.get(level, 300)
    n_required = _REQUIRED_APPROVERS.get(level, 1)

    store = get_approval_store()
    await store.create(approval_id, state["event_id"], level, n_required)

    await _push_approval_card(
        event_id=state["event_id"],
        approval_id=approval_id,
        playbook=state.get("playbook_draft") or {},
        level=level,
        timeout_sec=timeout_sec,
    )

    logger.info("hitl_pending", approval_id=approval_id, event_id=state["event_id"], level=level)

    result = await store.wait_result(approval_id, timeout_sec)
    status = "approved" if result == "approved" else ("rejected" if result in ("rejected", "timeout") else result)
    return {"approval_id": approval_id, "approval_status": status}


async def execute_response_node(state: ResponderSubState) -> dict[str, Any]:
    approval_status = state.get("approval_status", "rejected")
    if approval_status != "approved":
        logger.info("response_skipped", reason=approval_status, event_id=state["event_id"])
        return {"execution_result": {"status": "skipped", "reason": approval_status}}

    playbook = state.get("playbook_draft") or {}

    from src.execution.actions import ActionContext, ActionDispatcher
    settings = get_settings()
    ctx = ActionContext(
        event_id=state["event_id"],
        approval_id=state.get("approval_id"),
        actor="system",
        dry_run=settings.action_dry_run,
    )
    dispatcher = ActionDispatcher(dry_run=settings.action_dry_run)
    results = await dispatcher.execute_playbook(playbook, ctx)

    try:
        from src.common.audit.audit_logger import get_audit_logger
        await get_audit_logger().log(
            event_id=state["event_id"],
            node="responder_execute",
            action="execute_response",
            details={
                "approval_id": state.get("approval_id"),
                "results": results,
                "playbook_description": playbook.get("description", ""),
            },
        )
    except Exception as exc:
        logger.warning("audit_log_failed", error=str(exc))

    return {
        "execution_result": {
            "status": "completed" if all(r["status"] in ("success", "dry_run") for r in results) else "partial",
            "executed_operations": results,
            "approval_id": state.get("approval_id"),
        }
    }


async def reject_response_node(state: ResponderSubState) -> dict[str, Any]:
    reason = state.get("approval_status", "rejected")
    logger.info("response_rejected", event_id=state["event_id"], reason=reason)

    try:
        from src.common.audit.audit_logger import get_audit_logger
        await get_audit_logger().log(
            event_id=state["event_id"],
            node="responder_reject",
            action="reject_response",
            details={"approval_status": reason},
        )
    except Exception as exc:
        logger.warning("audit_log_failed", error=str(exc))

    return {"execution_result": {"status": "rejected", "reason": reason}}
