"""Serper.dev Google Search client for the AI search-agent (V13).

Usage is budget-sensitive: the Serper API is metered per request, so callers
MUST gate on `_needs_realtime` (chat.py) before invoking this module, and
results are cached in Redis for a short TTL so repeated/near-identical
realtime questions do not burn quota twice.
"""

from __future__ import annotations

import json
from dataclasses import asdict

import httpx
import redis.asyncio as aioredis

from src.agents.chat_search.web_search import WebSearchHit
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_SERPER_ENDPOINT = "https://google.serper.dev/search"
# Cache identical queries this long so a "今天的天气" asked twice within
# minutes does not double-bill the quota (Serper is per-request metered).
_CACHE_TTL_SEC = 30 * 60
_MAX_RESULTS = 5

_redis_client: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


def _cache_key(query: str) -> str:
    # V13 security review MEDIUM: hash the query so long/special-char
    # inputs cannot produce oversized or odd Redis keys; keep a short
    # readable prefix for debuggability.
    import hashlib

    digest = hashlib.sha256(query.strip().lower().encode("utf-8")).hexdigest()[:16]
    return "serper:" + digest


async def _search_serper(query: str, api_key: str) -> list[WebSearchHit]:
    """One metered Serper call. Never call directly without the realtime gate."""
    headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
    payload = {"q": query, "num": _MAX_RESULTS}
    async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
        resp = await client.post(_SERPER_ENDPOINT, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
    hits: list[WebSearchHit] = []
    for item in data.get("organic", []) or []:
        title = item.get("title") or ""
        link = item.get("link") or ""
        snippet = item.get("snippet") or ""
        if not title or not link:
            continue
        hits.append(WebSearchHit(title=title, url=link, snippet=snippet[:300]))
    return hits


async def search_realtime(query: str, api_key: str | None = None) -> list[WebSearchHit]:
    """Search with a short Redis cache. Returns [] when the key is unset."""
    key = api_key or get_settings().serper_api_key
    if not key:
        logger.warning("serper_api_key_not_configured")
        return []
    qkey = _cache_key(query)
    try:
        cached = await _redis().get(qkey)
        if cached:
            try:
                raw = json.loads(cached)
                return [WebSearchHit(**h) for h in raw]
            except Exception:
                pass  # corrupt cache entry, just search again
    except Exception:
        pass  # redis down: degrade to live search (budget note: no cache)

    try:
        hits = await _search_serper(query, key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("serper_search_failed", error=str(exc))
        return []

    # Cache successful results (never cache empty -- a transient failure
    # must not suppress a later retry).
    if hits:
        try:
            await _redis().set(
                qkey,
                json.dumps([asdict(h) for h in hits], ensure_ascii=False),
                ex=_CACHE_TTL_SEC,
            )
        except Exception:
            pass
    logger.info("serper_search_done", query=query[:80], hits=len(hits), cached=False)
    return hits
