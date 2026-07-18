"""SSE streaming endpoints — real-time push for events, metrics, approvals."""

import asyncio
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from src.api.auth.jwt import decode_token
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
                payload = {"channel": channel, "data": json.loads(data)} if isinstance(data, str) else {"data": data}
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            else:
                yield ": heartbeat\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
        await r.aclose()


def _verify_token(token: str) -> dict[str, Any]:
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


@router.get("/api/v1/events/{event_id}/stream")
async def event_stream(event_id: str, token: str = Query(...)):
    _verify_token(token)
    return StreamingResponse(
        _sse_generator(f"events:{event_id}", event_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/api/v1/metrics/stream")
async def metrics_stream(token: str = Query(...)):
    _verify_token(token)
    return StreamingResponse(
        _sse_generator("metrics"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/api/v1/events/stream")
async def events_list_stream(token: str = Query(...)):
    _verify_token(token)
    return StreamingResponse(
        _sse_generator("events:list"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
