"""V13 Tavily 搜索客户端：无 key、解析、缓存、provider 分发。"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.chat_search.tavily import search_realtime


@pytest.mark.asyncio
async def test_tavily_no_key_returns_empty():
    with (
        patch(
            "src.agents.chat_search.tavily.get_settings",
            return_value=MagicMock(tavily_api_key=""),
        ),
        patch("httpx.AsyncClient") as mock_client,
    ):
        hits = await search_realtime("今天的天气")
    assert hits == []
    mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_tavily_parses_results():
    raw = {
        "results": [
            {"title": "北京天气", "url": "https://example.com/w", "content": "今天晴 25°C"},
            {"title": "no-url", "url": "", "content": "x"},
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
            "src.agents.chat_search.tavily.get_settings",
            return_value=MagicMock(tavily_api_key="k", redis_url="redis://x"),
        ),
        patch("httpx.AsyncClient", _FakeClient),
        patch(
            "src.agents.chat_search.tavily._redis",
            return_value=AsyncMock(get=AsyncMock(return_value=None), set=AsyncMock()),
        ),
    ):
        hits = await search_realtime("北京天气")
    assert len(hits) == 1
    assert hits[0].title == "北京天气"
    assert hits[0].url == "https://example.com/w"


@pytest.mark.asyncio
async def test_tavily_redis_cache_skips_http():
    cached = json.dumps(
        [{"title": "t", "url": "https://e.com", "snippet": "s", "source": "tavily"}]
    )
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=cached)

    with (
        patch(
            "src.agents.chat_search.tavily.get_settings",
            return_value=MagicMock(tavily_api_key="k", redis_url="redis://x"),
        ),
        patch("httpx.AsyncClient") as mock_client,
        patch("src.agents.chat_search.tavily._redis", return_value=redis),
    ):
        hits = await search_realtime("北京天气")
    assert len(hits) == 1
    mock_client.assert_not_called()


# ---------------------------------------------------------------------------
# provider 分发（serper_enabled / tavily_enabled 布尔开关）
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_serper_enabled_uses_serper():
    from src.api.routers.chat import _search_web

    with (
        patch(
            "src.agents.chat_search.serper.search_realtime",
            AsyncMock(return_value=["serper-hit"]),
        ) as m_s,
        patch(
            "src.agents.chat_search.tavily.search_realtime",
            AsyncMock(return_value=["tavily-hit"]),
        ) as m_t,
        patch(
            "src.common.config.settings.get_settings",
            return_value=MagicMock(serper_enabled=True, tavily_enabled=False),
        ),
    ):
        r = await _search_web("x")
    assert r == ["serper-hit"]
    assert m_s.await_count == 1
    assert m_t.await_count == 0


@pytest.mark.asyncio
async def test_dispatch_tavily_enabled_uses_tavily():
    from src.api.routers.chat import _search_web

    with (
        patch(
            "src.agents.chat_search.serper.search_realtime",
            AsyncMock(return_value=["serper-hit"]),
        ) as m_s,
        patch(
            "src.agents.chat_search.tavily.search_realtime",
            AsyncMock(return_value=["tavily-hit"]),
        ) as m_t,
        patch(
            "src.common.config.settings.get_settings",
            return_value=MagicMock(serper_enabled=False, tavily_enabled=True),
        ),
    ):
        r = await _search_web("x")
    assert r == ["tavily-hit"]
    assert m_s.await_count == 0
    assert m_t.await_count == 1


@pytest.mark.asyncio
async def test_dispatch_both_disabled_returns_empty():
    """都 false → 不调任何后端（额度保护：关着就是关着）。"""
    from src.api.routers.chat import _search_web

    with (
        patch(
            "src.agents.chat_search.serper.search_realtime",
            AsyncMock(return_value=["serper-hit"]),
        ) as m_s,
        patch(
            "src.agents.chat_search.tavily.search_realtime",
            AsyncMock(return_value=["tavily-hit"]),
        ) as m_t,
        patch(
            "src.common.config.settings.get_settings",
            return_value=MagicMock(serper_enabled=False, tavily_enabled=False),
        ),
    ):
        r = await _search_web("x")
    assert r == []
    assert m_s.await_count == 0
    assert m_t.await_count == 0


@pytest.mark.asyncio
async def test_dispatch_both_enabled_serper_wins():
    """都 true → serper 优先（并记 warning）。"""
    from src.api.routers.chat import _search_web

    with (
        patch(
            "src.agents.chat_search.serper.search_realtime",
            AsyncMock(return_value=["serper-hit"]),
        ) as m_s,
        patch(
            "src.agents.chat_search.tavily.search_realtime",
            AsyncMock(return_value=["tavily-hit"]),
        ) as m_t,
        patch(
            "src.common.config.settings.get_settings",
            return_value=MagicMock(serper_enabled=True, tavily_enabled=True),
        ),
    ):
        r = await _search_web("x")
    assert r == ["serper-hit"]
    assert m_s.await_count == 1
    assert m_t.await_count == 0
