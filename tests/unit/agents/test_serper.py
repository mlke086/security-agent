"""V13 Serper.dev 搜索客户端：缓存、无 key、解析。"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.chat_search.serper import search_realtime


@pytest.mark.asyncio
async def test_no_api_key_returns_empty_without_calling():
    """未配置 key → 直接返回 []，绝不发请求（省额度）。"""
    with (
        patch(
            "src.agents.chat_search.serper.get_settings",
            return_value=MagicMock(serper_api_key=""),
        ),
        patch("httpx.AsyncClient") as mock_client,
    ):
        hits = await search_realtime("今天的天气")
    assert hits == []
    mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_parses_organic_results():
    key = "test-key"
    raw = {
        "organic": [
            {"title": "北京天气", "link": "https://example.com/w", "snippet": "今天晴 25°C"},
            {"title": "no-link", "link": "", "snippet": "x"},
        ]
    }
    fake_resp = MagicMock()
    fake_resp.json = MagicMock(return_value=raw)

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return fake_resp

    with (
        patch(
            "src.agents.chat_search.serper.get_settings",
            return_value=MagicMock(serper_api_key=key, redis_url="redis://x"),
        ),
        patch("httpx.AsyncClient", _FakeClient),
        patch("src.agents.chat_search.serper._redis", return_value=AsyncMock(get=AsyncMock(return_value=None), set=AsyncMock())),
    ):
        hits = await search_realtime("北京天气")
    assert len(hits) == 1  # 无 link 的条目被过滤
    assert hits[0].title == "北京天气"
    assert hits[0].url == "https://example.com/w"


@pytest.mark.asyncio
async def test_redis_cache_hits_skip_http():
    """命中缓存 → 不再调 Serper（额度保护关键）。"""
    cached = json.dumps(
        [{"title": "t", "url": "https://e.com", "snippet": "s", "source": "serper"}]
    )
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=cached)

    with (
        patch(
            "src.agents.chat_search.serper.get_settings",
            return_value=MagicMock(serper_api_key="k", redis_url="redis://x"),
        ),
        patch("httpx.AsyncClient") as mock_client,
        patch("src.agents.chat_search.serper._redis", return_value=redis),
    ):
        hits = await search_realtime("北京天气")
    assert len(hits) == 1
    mock_client.assert_not_called()  # 未发任何请求
