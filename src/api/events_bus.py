"""EventBus — Redis Pub/Sub event bus for cross-worker SSE push."""

import json
from typing import Any

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


class EventBus:
    """Redis Pub/Sub event bus for publishing state changes to SSE subscribers."""

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                get_settings().redis_url, decode_responses=True,
            )
        return self._redis

    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        try:
            r = await self._get_redis()
            await r.publish(channel, json.dumps(payload, ensure_ascii=False))
        except Exception as exc:
            logger.warning("event_bus_publish_failed", channel=channel, error=str(exc))

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()
            self._redis = None


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
