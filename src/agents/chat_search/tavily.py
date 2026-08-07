"""Tavily Search client for the AI search-agent (V13, alternative to Serper).

Same budget discipline as serper.py: metered per request, so callers MUST
gate on `_needs_realtime` (chat.py) first, and results are cached in Redis
with a short TTL. Provider switch is `settings.search_provider`
("serper" | "tavily"), hot-reloadable from Nacos.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

import httpx
import redis.asyncio as aioredis

from src.agents.chat_search.web_search import WebSearchHit
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_TAVILY_ENDPOINT = "https://api.tavily.com/search"
_CACHE_TTL_SEC = 30 * 60
_MAX_RESULTS = 5

_redis_client: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


def _cache_key(query: str) -> str:
    digest = hashlib.sha256(query.strip().lower().encode("utf-8")).hexdigest()[:16]
    return "tavily:" + digest


async def _search_tavily(query: str, api_key: str) -> list[WebSearchHit]:
    """One metered Tavily call. Never call directly without the realtime gate."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"query": query, "max_results": _MAX_RESULTS}
    async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
        resp = await client.post(_TAVILY_ENDPOINT, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
    hits: list[WebSearchHit] = []
    for item in data.get("results", []) or []:
        title = item.get("title") or ""
        url = item.get("url") or ""
        content = item.get("content") or ""
        if not title or not url:
            continue
        hits.append(WebSearchHit(title=title, url=url, snippet=content[:300]))
    return hits


async def search_realtime(query: str, api_key: str | None = None) -> list[WebSearchHit]:
    """Search with a short Redis cache. Returns [] when the key is unset."""
    key = api_key or get_settings().tavily_api_key
    if not key:
        logger.warning("tavily_api_key_not_configured")
        return []
    qkey = _cache_key(query)
    try:
        cached = await _redis().get(qkey)
        if cached:
            try:
                raw = json.loads(cached)
                return [WebSearchHit(**h) for h in raw]
            except Exception:
                pass
    except Exception:
        pass  # redis down: degrade to live search

    try:
        hits = await _search_tavily(query, key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("tavily_search_failed", error=str(exc))
        return []

    if hits:
        try:
            await _redis().set(
                qkey,
                json.dumps([asdict(h) for h in hits], ensure_ascii=False),
                ex=_CACHE_TTL_SEC,
            )
        except Exception:
            pass
    logger.info("tavily_search_done", query=query[:80], hits=len(hits), cached=False)
    return hits
