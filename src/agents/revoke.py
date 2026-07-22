"""Cross-worker agent revocation.

``revoke_agent`` is the single entry point: it marks the token as revoked
in PostgreSQL (so the next reconnect fails) and publishes a Redis event
that every worker subscribes to so any in-flight WebSocket is closed.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

REVOKE_CHANNEL_PREFIX = "agent:revoke:"


def revoke_channel(agent_id: str) -> str:
    return REVOKE_CHANNEL_PREFIX + agent_id


def _payload(agent_id: str) -> str:
    return json.dumps({"agent_id": agent_id, "ts": datetime.now(UTC).isoformat()})


async def revoke_agent(agent_id: str) -> dict[str, Any]:
    """Revoke an agent token and ask every worker to close its WS.

    Returns a small summary so the calling router can audit-log it.
    """
    from src.common.db.pg import get_pg_pool

    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE agent_tokens SET revoked_at = NOW() "
            "WHERE agent_id = $1 AND revoked_at IS NULL",
            agent_id,
        )

    redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    listeners = 0
    try:
        listeners = await redis.publish(revoke_channel(agent_id), _payload(agent_id))
    finally:
        await redis.aclose()

    summary = {"agent_id": agent_id, "subscribers": int(listeners or 0)}
    logger.info("agent_token_revoked", **summary)
    return summary


async def listen_for_revocations(callback) -> None:
    """Subscribe to revocation events. ``callback(agent_id)`` runs per event."""
    redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.psubscribe(f"{REVOKE_CHANNEL_PREFIX}*")
    try:
        async for message in pubsub.listen():
            if message is None or message.get("type") != "pmessage":
                continue
            try:
                data = json.loads(message.get("data") or "{}")
            except json.JSONDecodeError:
                continue
            agent_id = data.get("agent_id")
            if agent_id:
                try:
                    await callback(agent_id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "revoke_callback_failed", agent_id=agent_id, error=str(exc)
                    )
    finally:
        try:
            await pubsub.aclose()
        finally:
            await redis.aclose()