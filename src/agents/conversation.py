"""Scan conversation storage (需求3 对话式扫描).

PG-backed multi-turn chat history. Each conversation holds a messages array
([{role, content, ts}]) so the operator can refine scan intent across turns,
switch models, and resume past sessions. The chat endpoint appends the user
message, calls the ModelAdapter with the full history, and appends the reply.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from src.common.logging.logger import get_logger

logger = get_logger(__name__)


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
            "SELECT * FROM scan_conversations WHERE id=$1", uuid.UUID(conv_id)
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


async def append_message(conv_id: str, role: str, content: str) -> dict[str, Any] | None:
    """Append a message and return the updated conversation."""
    msg = {"role": role, "content": content, "ts": datetime.now(UTC).isoformat()}
    async with await _pg_conn() as conn:
        row = await conn.fetchrow(
            """UPDATE scan_conversations
               SET messages = messages || $1::jsonb, updated_at = NOW()
               WHERE id = $2 RETURNING *""",
            json.dumps([msg]),
            uuid.UUID(conv_id),
        )
    return _row_to_dict(row) if row else None


async def update_conversation(conv_id: str, **fields) -> dict[str, Any] | None:
    allowed = {"title", "model_id"}
    sets: list[str] = ["updated_at=NOW()"]
    params: list = [uuid.UUID(conv_id)]
    idx = 1
    for k, v in fields.items():
        if k in allowed and v is not None:
            idx += 1
            sets.append(f"{k}=${idx}")
            params.append(v)
    async with await _pg_conn() as conn:
        await conn.execute(f"UPDATE scan_conversations SET {', '.join(sets)} WHERE id=$1", *params)
        row = await conn.fetchrow(
            "SELECT * FROM scan_conversations WHERE id=$1", uuid.UUID(conv_id)
        )
    return _row_to_dict(row) if row else None


async def delete_conversation(conv_id: str) -> bool:
    async with await _pg_conn() as conn:
        result = await conn.execute(
            "DELETE FROM scan_conversations WHERE id=$1", uuid.UUID(conv_id)
        )
    return result.endswith(" 1") or result == "DELETE 1"
