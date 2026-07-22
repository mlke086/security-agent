"""Scan conversation (dialog) endpoints.

Multi-turn chat: the operator refines scan intent across turns, can switch
models per turn, and the conversation history is persisted.

Key behavior change (Bug fix 2026-07-22):
  We now ALWAYS try to parse a ScanIntent in the background, regardless of
  whether the caller passed ``parse_intent=true``. The previous design only
  parsed when explicitly requested, which left the "执行扫描" button greyed
  out after a free-form chat that happened to contain a complete intent.
  The intent is attached to every chat response so the frontend can show
  the confirm-to-execute card without a separate "解析意图" click.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from src.agents import conversation as conv_store
from src.agents.models import ScanIntent
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.logging.logger import get_logger
from src.knowledge.models.adapter import ModelAdapter, ModelNotFoundError, get_model_adapter

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/vulnscan/conversations", tags=["scan-chat"])

SYSTEM_PROMPT = (
    "你是漏洞扫描助手。用户会用自然语言描述扫描需求（目标主机/组、"
    "扫描模块、引擎等）。你可以多轮对话（例如问清目标范围、是否包含"
    "基线检查），最终帮用户形成明确的扫描意图。当用户的意图足够明确时，"
    "简短回复并提示可以点击「执行扫描」。用户可能表达为简洁参数（如"
    "默认引擎、漏洞扫描、是、无），这种也要能正确解析。用中文回答。"
)

INTENT_PROMPT = (
    "你是漏洞扫描意图提取器。从对话中提取结构化字段：\n"
    "- targets: list[str]，目标主机名/IP/组名\n"
    "- modules: list[str]，从 ['sys_vuln','baseline'] 中选择（系统漏洞/基线）\n"
    "- engine: 'matcher' 或 'nuclei'，默认 'matcher'\n"
    "- resource_limit: dict（可选）\n"
    "- schedule: str|null（可选）\n"
    "如果某字段用户没说明，返回空，不要瞎猜。返回纯 JSON，不要 markdown。"
)


class CreateConversationRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    title: str = "新对话"
    model_id: int | None = None


class ChatRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    message: str
    model_id: int | None = None
    parse_intent: bool = False  # 已废弃：后端总是自动尝试 parse，保持兼容


class UpdateConversationRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    title: str | None = None
    model_id: int | None = None


async def _parse_intent_background(
    adapter: ModelAdapter,
    history: list[dict],
    model_id: int | None,
) -> ScanIntent | None:
    """Try to extract a ScanIntent from the conversation so far.

    Returns None on any failure -- parse_intent is best-effort. The frontend
    decides whether to show the confirm card.
    """
    try:
        # Only ask the LLM for the structured intent, NOT a free-form chat.
        msgs = [{"role": "system", "content": INTENT_PROMPT}]
        for m in history:
            if m.get("role") in ("user", "assistant"):
                msgs.append({"role": m["role"], "content": m["content"]})
        intent = await adapter.chat_completion(
            messages=msgs,
            schema=ScanIntent,
            model_id=model_id,
        )
        # Only return if we actually got a usable intent (at least one target
        # OR user clearly said "全部"/"所有" -- we err on the side of
        # including so the operator can confirm/correct).
        if not intent.targets and not intent.modules:
            return None
        return intent
    except Exception as exc:  # noqa: BLE001
        logger.warning("parse_intent_background_failed", error=str(exc))
        return None


@router.get("")
async def api_list_conversations(current_user=Depends(require_role("admin", "analyst"))):
    return {"items": await conv_store.list_conversations()}


@router.post("")
async def api_create_conversation(
    req: CreateConversationRequest,
    current_user=Depends(require_role("admin", "analyst")),
):
    return await conv_store.create_conversation(req.title, req.model_id)


@router.get("/{conv_id}")
async def api_get_conversation(
    conv_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    conv = await conv_store.get_conversation(conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="会话不存在")
    return conv


@router.patch("/{conv_id}")
async def api_update_conversation(
    conv_id: str,
    req: UpdateConversationRequest,
    current_user=Depends(require_role("admin", "analyst")),
):
    conv = await conv_store.update_conversation(conv_id, title=req.title, model_id=req.model_id)
    if not conv:
        raise HTTPException(status_code=404, detail="会话不存在")
    return conv


@router.delete("/{conv_id}")
async def api_delete_conversation(
    conv_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    ok = await conv_store.delete_conversation(conv_id)
    if not ok:
        raise HTTPException(status_code=404, detail="会话不存在")
    return {"status": "ok"}


@router.post("/{conv_id}/chat")
async def api_chat(
    conv_id: str,
    req: ChatRequest,
    current_user=Depends(require_role("admin", "analyst")),
):
    """Multi-turn dialog. Persists user + assistant, returns the updated
    conversation along with the (auto-extracted) ScanIntent if any."""
    conv = await conv_store.get_conversation(conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="会话不存在")

    model_id = req.model_id or conv.get("model_id")
    adapter = get_model_adapter()

    # Build the LLM history including the new user message.
    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    for m in conv["messages"]:
        if m.get("role") in ("user", "assistant"):
            history.append({"role": m["role"], "content": m["content"]})
    history.append({"role": "user", "content": req.message})

    try:
        # Free-form chat reply.
        reply = await adapter.chat_completion(messages=history, model_id=model_id)

        # Background-style intent extraction. Run it after the chat so we
        # don't add latency to the user-visible response -- but include the
        # intent in the returned payload when available so the frontend can
        # light up the confirm card immediately.
        intent = await _parse_intent_background(adapter, history, model_id)
    except ModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"模型调用失败: {exc}")

    # Persist user + assistant.
    conv = await conv_store.append_message(conv_id, "user", req.message)
    conv = await conv_store.append_message(conv_id, "assistant", str(reply))
    if intent is not None:
        await get_audit_logger().log(
            event_id="scan-chat",
            node="scan_chat.router",
            action="auto_parse_intent",
            actor=current_user.username,
            details={"conv_id": conv_id},
        )
        return {"reply": str(reply), "intent": intent.model_dump(), "conversation": conv}
    return {"reply": str(reply), "conversation": conv}
