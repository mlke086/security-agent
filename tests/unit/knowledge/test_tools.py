"""Unit tests for the tool registry and notifier tools."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.knowledge.tools.registry import (
    call_tool,
    call_tool_sync,
    get_tool,
    list_tools,
    tool,
)


def test_tool_registration_and_lookup():
    @tool(name="test_tool_x", description="a test", category="test")
    async def fn(x):
        return x * 2

    assert get_tool("test_tool_x") is fn
    names = [t["name"] for t in list_tools()]
    assert "test_tool_x" in names
    by_cat = [t["name"] for t in list_tools(category="test")]
    assert "test_tool_x" in by_cat


@pytest.mark.asyncio
async def test_call_tool_async_fn():
    @tool(name="test_async_x")
    async def fn(x):
        return x + 1

    assert await call_tool("test_async_x", 5) == 6


def test_call_tool_sync_fn():
    @tool(name="test_sync_x")
    def fn(x):
        return x - 1

    assert call_tool_sync("test_sync_x", 5) == 4


def test_call_tool_missing_raises():
    with pytest.raises(KeyError):
        call_tool_sync("nonexistent_tool_zzz")


@pytest.mark.asyncio
async def test_notify_wechat_unconfigured():
    from src.knowledge.tools.notifier import notify_wechat

    result = await notify_wechat("title", "content")
    assert "error" in result  # no webhook configured in test env


@pytest.mark.asyncio
async def test_notify_dingtalk_unconfigured():
    from src.knowledge.tools.notifier import notify_dingtalk

    result = await notify_dingtalk("title", "content")
    assert "error" in result


@pytest.mark.asyncio
async def test_notify_wechat_sends_when_configured(monkeypatch):
    from src.knowledge.tools import notifier

    monkeypatch.setattr(notifier.get_settings(), "wechat_work_webhook", "https://example.com/webhook")
    resp = MagicMock(status_code=200)
    monkeypatch.setattr(httpx.AsyncClient, "post", AsyncMock(return_value=resp))

    result = await notifier.notify_wechat("title", "content")
    assert result["status"] == "ok"
    assert result["http_code"] == 200
