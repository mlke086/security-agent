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

import asyncio
import re

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

TITLE_PROMPT = (
    "你是一个对话标题生成助手。基于下面用户和助手的对话内容，"
    "用 6-15 个中文字符生成一个简洁的主题标题。要求：\n"
    "  - 抓住对话的核心主题，例如 扫描 test 组漏洞 / 询问系统架构 / 查询 CVE-2024-3094\n"
    "  - 不要使用书名号、引号、句号、问号、emoji\n"
    "  - 不要 关于 / 如何 / 什么是 这种无意义前缀\n"
    "  - 直接输出标题文字，不要任何其他说明"
)

# Treated as "untitled" -- a non-default title means the user (or a prior
# generation pass) has already named this conversation, so we leave it alone.
DEFAULT_TITLES = frozenset({"", "新对话", "新会话", "未命名对话", "Untitled"})


def _clean_title(raw: str) -> str:
    """Strip quotes / punctuation / emoji and clamp length.

    Best-effort: any weirdness on the LLM side (markdown fences,
    "标题：" prefixes, surrounding brackets, etc.) gets cleaned up here so we
    never store a noisy value.
    """
    if not raw:
        return ""
    s = raw.strip()
    # strip markdown code fences
    s = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", s, flags=re.MULTILINE)
    # strip common prefixes the LLM sometimes adds
    for prefix in ("标题：", "标题:", "Title:", "title:", "主题：", "主题:", "Title："):
        if s.startswith(prefix):
            s = s[len(prefix) :].strip()
    # strip surrounding ASCII + CJK quotes / brackets
    quote_chars = (
        chr(34) + chr(39) + chr(96) + chr(0x201C) + chr(0x201D) + chr(0x2018) + chr(0x2019)
    )
    bracket_chars = chr(0x300A) + chr(0x300B) + chr(0x3010) + chr(0x3011) + "[]()"
    s = s.strip(quote_chars + bracket_chars)
    # remove punctuation that does not belong in a title -- keep CJK, ASCII
    # alnum, hyphen and slash so CVE-2024-3094 survives intact.
    s = re.sub(r"[\s。，！？、；：,.!?;:：；，！？、；：\u3000]+", " ", s)
    s = re.sub(r"[^\u4e00-\u9fff\w\-/]", "", s)
    s = re.sub(r"\s+", "", s)
    if len(s) > 20:
        s = s[:20]
    return s


async def _maybe_generate_title(
    conv_id: str,
    model_id: int | None,
) -> None:
    """Background: ask the LLM to summarize the conversation into a short
    title, then PATCH the conversation. Idempotent -- skips if the title has
    already been set (either by a previous run or by the operator editing it).

    Runs as a fire-and-forget asyncio.Task spawned from the chat handler; any
    exception is logged but never propagated to the caller.
    """
    try:
        conv = await conv_store.get_conversation(conv_id)
        if not conv:
            return
        # Skip if already named
        if (conv.get("title") or "").strip() not in DEFAULT_TITLES:
            return
        msgs = conv.get("messages") or []
        user_msgs = [m for m in msgs if m.get("role") == "user"]
        # Generate a title from the very first user message onward. Even a
        # single sentence ("扫描 test 组主机") gives the LLM enough signal for
        # a 6-15 char topic. We do still skip if there's literally nothing
        # to summarize (no user turns yet).
        if len(user_msgs) < 1:
            return
        # Take the first 4 turns (2 user + 2 assistant) -- enough to capture
        # the topic without burning tokens on long sessions.
        recent = [m for m in msgs if m.get("role") in ("user", "assistant")][-4:]
        convo_lines = []
        for m in recent:
            role = "用户" if m["role"] == "user" else "助手"
            content = (m.get("content") or "").strip().replace("\n", " ")
            if len(content) > 200:
                content = content[:200] + "..."
            convo_lines.append(f"{role}: {content}")
        convo_text = "\n".join(convo_lines)

        adapter = get_model_adapter()
        raw_title = await adapter.chat_completion(
            messages=[
                {"role": "system", "content": TITLE_PROMPT},
                {"role": "user", "content": f"对话内容：\n{convo_text}\n\n请生成标题："},
            ],
            model_id=model_id,
            temperature=0.3,
        )
        title = _clean_title(str(raw_title))
        if not title:
            logger.warning("auto_title_empty", conv_id=conv_id)
            return
        # Re-check after the LLM round-trip -- the user might have manually
        # edited the title in the meantime, or another concurrent chat call
        # could have already named it.
        conv = await conv_store.get_conversation(conv_id)
        if not conv or (conv.get("title") or "").strip() not in DEFAULT_TITLES:
            return
        await conv_store.update_conversation(conv_id, title=title)
        logger.info("auto_title_generated", conv_id=conv_id, title=title)
    except Exception as exc:  # noqa: BLE001
        logger.warning("auto_title_failed", conv_id=conv_id, error=str(exc))


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
    # Auto-title: kick off in the background after persisting the turn so the
    # conversation has enough content to summarize. Fire-and-forget; failures
    # are logged inside the task and never block the chat response.
    asyncio.create_task(_maybe_generate_title(conv_id, model_id))
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
