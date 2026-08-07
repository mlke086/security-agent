"""Scan conversation storage (需求3 对话式扫描).

PG-backed multi-turn chat history. Each conversation holds a messages array
([{role, content, ts, ...}]) so the operator can refine scan intent across turns,
switch models, and resume past sessions. The chat endpoint appends the user
message, calls the ModelAdapter with the full history, and appends the reply.

Message shape (jsonb array element):
  {role: "user"|"assistant", content: str, ts: iso, route?: str,
   intent?: dict, sources?: list, task_id?: str}

`route` / `intent` / `sources` are populated by the chat router so the
historical intent card can re-render without a second LLM call. `task_id` is
written by `patch_message` once the operator clicks "执行扫描" -- it powers the
"已创建任务 #xxx → 查看" link on the historical card.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from src.common.logging.logger import get_logger

logger = get_logger(__name__)


class InvalidConversationIdError(ValueError):
    """Raised when a conversation id is not a valid UUID.

    Routers map this to HTTP 400. The raw uuid.UUID ValueError previously
    surfaced as an unhandled 500 (V13 P2-9).
    """


def validate_conv_id(conv_id: str) -> uuid.UUID:
    """Parse and validate a conversation id (V13 P2-9)."""
    try:
        return uuid.UUID(conv_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidConversationIdError(repr(conv_id)) from exc

# ---- Auto-title (V12 5.10) -----------------------------------------------
# Moved here from scan_chat.py so BOTH the legacy scan-chat route and the
# unified /api/v1/chat route can spawn title generation. V9 unified the
# routers but the auto-title call was only wired into the legacy one, so
# conversations created via /chat kept the default "新对话" title forever.

TITLE_PROMPT = (
    "用 6-15 个中文字符生成一个简洁的主题标题。要求：\n"
    "  - 抓住对话的核心主题，例如 扫描 test 组漏洞 / 询问系统架构 / 查询 CVE-2024-3094\n"
    "  - 不要使用书名号、引号、句号、问号、emoji\n"
    "  - 不要 关于 / 如何 / 什么是 这种无意义前缀\n"
    "  - 直接输出标题文字，不要任何其他说明"
)

# Treated as "untitled" -- a non-default title means the user (or a prior
# generation pass) has already named this conversation, so we leave it alone.
DEFAULT_TITLES = frozenset({"", "新对话", "新会话", "未命名对话", "Untitled"})


def clean_title(raw: str) -> str:
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
    s = re.sub(r"[\s。，！？、；：,.!?;:：；，！？、；：　]+", " ", s)
    s = re.sub(r"[^一-鿿\w\-/]", "", s)
    s = re.sub(r"\s+", "", s)
    if len(s) > 20:
        s = s[:20]
    return s


async def maybe_generate_title(
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
        conv = await get_conversation(conv_id)
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

        from src.knowledge.models.adapter import get_model_adapter

        adapter = get_model_adapter()
        raw_title = await adapter.chat_completion(
            messages=[
                {"role": "system", "content": TITLE_PROMPT},
                {"role": "user", "content": f"对话内容：\n{convo_text}\n\n请生成标题："},
            ],
            model_id=model_id,
            temperature=0.3,
        )
        title = clean_title(str(raw_title))
        if not title:
            logger.warning("auto_title_empty", conv_id=conv_id)
            return
        # Re-check after the LLM round-trip -- the user might have manually
        # edited the title in the meantime, or another concurrent chat call
        # could have already named it.
        conv = await get_conversation(conv_id)
        if not conv or (conv.get("title") or "").strip() not in DEFAULT_TITLES:
            return
        await update_conversation(conv_id, title=title)
        logger.info("auto_title_generated", conv_id=conv_id, title=title)
    except Exception as exc:  # noqa: BLE001
        logger.warning("auto_title_failed", conv_id=conv_id, error=str(exc))


# Whitelisted metadata keys. We allow-list to keep the jsonb shape predictable
# (audit/analytics code may rely on it) and to avoid persisting anything that
# the chat router accidentally forwards.
_META_KEYS: frozenset[str] = frozenset({"route", "intent", "sources", "task_id"})


async def _pg_conn():
    from src.common.db.pg import get_pg_pool as _get_pool

    pool = await _get_pool()
    return pool.acquire()


def _row_to_dict(row) -> dict[str, Any]:
    msgs = row["messages"]
    if isinstance(msgs, str):
        msgs = json.loads(msgs)
    return {
        "id": str(row["id"]),
        "title": row["title"],
        "model_id": row["model_id"],
        "messages": msgs or [],
        "created_at": row["created_at"].isoformat() if row["created_at"] else "",
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else "",
    }


async def list_conversations(limit: int = 50) -> list[dict[str, Any]]:
    async with await _pg_conn() as conn:
        rows = await conn.fetch(
            "SELECT id, title, model_id, created_at, updated_at "
            "FROM scan_conversations ORDER BY updated_at DESC LIMIT $1",
            limit,
        )
    return [
        {
            "id": str(r["id"]),
            "title": r["title"],
            "model_id": r["model_id"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else "",
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else "",
        }
        for r in rows
    ]


async def get_conversation(conv_id: str) -> dict[str, Any] | None:
    async with await _pg_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM scan_conversations WHERE id=$1", validate_conv_id(conv_id)
        )
    return _row_to_dict(row) if row else None


async def create_conversation(title: str = "新对话", model_id: int | None = None) -> dict[str, Any]:
    conv_id = uuid.uuid4()
    async with await _pg_conn() as conn:
        row = await conn.fetchrow(
            "INSERT INTO scan_conversations (id, title, model_id) VALUES ($1,$2,$3) RETURNING *",
            conv_id,
            title,
            model_id,
        )
    logger.info("conversation_created", id=str(conv_id))
    return _row_to_dict(row)


def _sanitize_meta(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Drop anything not in `_META_KEYS` so callers can't smuggle junk into
    the jsonb. None / empty input yields an empty dict (no `meta` field on the
    message -- keeps the storage shape identical to pre-meta messages for
    backward compatibility with conversations written before this change)."""
    if not meta:
        return {}
    return {k: v for k, v in meta.items() if k in _META_KEYS}


async def append_message(
    conv_id: str,
    role: str,
    content: str,
    meta: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Append a message and return ``(conversation, persisted_message)``.

    `meta` (optional) is a dict of whitelisted keys (`route`, `intent`,
    `sources`, `task_id`) that gets merged into the message object. The
    historical intent card uses these to re-render without a second LLM call.

    Returning the *persisted* message (rather than the freshly built
    dict) is important: the actual `ts` we wrote is what lives in PG
    jsonb, including its microsecond tick and timezone suffix. The
    caller (chat router) hands it back to the frontend so a later
    `patch_message(ts, ...)` is guaranteed to find the same row --
    otherwise the frontend-generated `ts` differs from ours by a
    few microseconds and the patch silently misses (V9 follow-up).
    """
    msg: dict[str, Any] = {"role": role, "content": content, "ts": datetime.now(UTC).isoformat()}
    clean = _sanitize_meta(meta)
    if clean:
        msg.update(clean)
    async with await _pg_conn() as conn:
        row = await conn.fetchrow(
            """UPDATE scan_conversations
               SET messages = messages || $1::jsonb, updated_at = NOW()
               WHERE id = $2 RETURNING *""",
            json.dumps([msg]),
            validate_conv_id(conv_id),
        )
    if not row:
        return None, None
    conv = _row_to_dict(row)
    persisted = (conv.get("messages") or [])[-1] if conv.get("messages") else None
    return conv, persisted


async def patch_message(
    conv_id: str,
    ts: str,
    patch: dict[str, Any],
) -> dict[str, Any] | None:
    """Update one message in-place by its `ts`. Used to write back `task_id`
    after the operator clicks "执行扫描", so the historical intent card can
    show "已创建任务 #xxx → 查看" on reload.

    Only the last message with a matching `ts` is patched -- the same `ts`
    can technically repeat across messages (millisecond-level resolution), so
    we patch from the tail where the intent card is most recently rendered.
    Returns the updated conversation, or None if the message wasn't found.
    """
    clean = _sanitize_meta(patch)
    if not clean:
        # Nothing to write; return the conversation as-is so the caller can
        # still render the rest of the chat.
        return await get_conversation(conv_id)

    async with await _pg_conn() as conn:
        row = await conn.fetchrow(
            "SELECT messages FROM scan_conversations WHERE id=$1", validate_conv_id(conv_id)
        )
    if not row:
        return None
    msgs = row["messages"]
    if isinstance(msgs, str):
        msgs = json.loads(msgs)
    if not msgs:
        return _row_to_dict(row)
    # Walk from the tail; the most recently rendered intent card is the
    # one we just clicked execute on.
    patched = False
    for i in range(len(msgs) - 1, -1, -1):
        m = msgs[i]
        if isinstance(m, dict) and m.get("ts") == ts:
            msgs[i] = {**m, **clean}
            patched = True
            break
    if not patched:
        logger.warning("patch_message_not_found", conv_id=conv_id, ts=ts)
    async with await _pg_conn() as conn:
        row = await conn.fetchrow(
            """UPDATE scan_conversations
               SET messages = $1::jsonb, updated_at = NOW()
               WHERE id = $2 RETURNING *""",
            json.dumps(msgs, ensure_ascii=False),
            validate_conv_id(conv_id),
        )
    return _row_to_dict(row) if row else None


async def update_conversation(conv_id: str, **fields) -> dict[str, Any] | None:
    allowed = {"title", "model_id"}
    sets: list[str] = ["updated_at=NOW()"]
    params: list = [validate_conv_id(conv_id)]
    idx = 1
    for k, v in fields.items():
        if k in allowed and v is not None:
            idx += 1
            sets.append(f"{k}=${idx}")
            params.append(v)
    async with await _pg_conn() as conn:
        await conn.execute(f"UPDATE scan_conversations SET {', '.join(sets)} WHERE id=$1", *params)
        row = await conn.fetchrow(
            "SELECT * FROM scan_conversations WHERE id=$1", validate_conv_id(conv_id)
        )
    return _row_to_dict(row) if row else None


async def delete_conversation(conv_id: str) -> bool:
    async with await _pg_conn() as conn:
        result = await conn.execute(
            "DELETE FROM scan_conversations WHERE id=$1", validate_conv_id(conv_id)
        )
    return result.endswith(" 1") or result == "DELETE 1"
