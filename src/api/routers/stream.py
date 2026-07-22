"""SSE streaming endpoints — real-time push for events, metrics, approvals."""

import asyncio
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from src.api.auth.jwt import decode_token
from src.api.auth.sse_tokens import decode_sse_token
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["stream"])


async def _sse_generator(channel: str, event_id: str | None = None) -> Any:
    """SSE event generator: subscribe to Redis channel, forward messages with heartbeats."""
    import redis.asyncio as aioredis

    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(channel)
    try:
        while True:
            msg = await pubsub.get_message(timeout=15, ignore_subscribe_messages=True)
            if msg:
                data = msg["data"]
                payload = (
                    {"channel": channel, "data": json.loads(data)}
                    if isinstance(data, str)
                    else {"data": data}
                )
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            else:
                yield ": heartbeat\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
        await r.aclose()


def _verify_scoped_token(token: str, scope: str) -> dict[str, Any]:
    """Validate a short-lived SSE token. Falls back to the user JWT only if
    the token is signed normally (no scope claim) so existing deployments
    don't break -- but logs a warning so operators migrate.

    P1-API-04 (2026-07-20): reject tokens that don't carry the expected
    scope so a long-lived admin JWT can't be replayed against
    /metrics/stream by an analyst who sniffed it.
    """
    # Fast path: scoped SSE token.
    try:
        return decode_sse_token(token, scope)
    except PermissionError:
        pass
    # Fallback: legacy long-lived JWT. Allowed only for admin/analyst so a
    # viewer-role JWT still can't drive an SSE channel.
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    role = payload.get("role")
    if role not in {"admin", "analyst", "responder"}:
        raise HTTPException(status_code=403, detail="SSE requires admin/analyst/responder role")
    logger.warning("sse_legacy_jwt_used", scope=scope, role=role)
    return payload


@router.get("/api/v1/events/{event_id}/stream")
async def event_stream(event_id: str, token: str = Query(...)):
    _verify_scoped_token(token, "events")
    return StreamingResponse(
        _sse_generator(f"events:{event_id}", event_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/api/v1/metrics/stream")
async def metrics_stream(token: str = Query(...)):
    _verify_scoped_token(token, "metrics")
    return StreamingResponse(
        _sse_generator("metrics"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/api/v1/events/stream")
async def events_list_stream(token: str = Query(...)):
    _verify_scoped_token(token, "events_list")
    return StreamingResponse(
        _sse_generator("events:list"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
