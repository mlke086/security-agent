"""V13 AI search-agent：_needs_realtime 三层门控（额度保护核心）。"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.routers.chat import _needs_realtime


class _Judge:
    def __init__(self, realtime: bool) -> None:
        self.realtime = realtime


def _mock_adapter(judge: _Judge | None):
    adapter = MagicMock()
    adapter.chat_completion = AsyncMock(return_value=judge)
    return adapter


@pytest.mark.asyncio
async def test_strong_realtime_keyword_triggers_without_llm():
    """强实时词（天气/新闻/最近/最新）→ 直接需要搜索，零 LLM 开销。"""
    for msg in ("今天北京的天气怎么样", "最近有什么重大新闻", "最新政策发布", "明天的气温"):
        need, reason = await _needs_realtime(msg, None)
        assert need is True, f"{msg} 应判为需要实时（got {reason}）"


@pytest.mark.asyncio
async def test_no_signal_never_searches():
    """无实时信号 → 不搜索（通用知识直接透传，省额度）。"""
    for msg in (
        "什么是 SQL 注入",
        "帮我解释一下 XSS 的原理",
        "HTTP 和 HTTPS 的区别",
        "SecAgent 有哪些功能",
    ):
        need, reason = await _needs_realtime(msg, None)
        assert need is False, f"{msg} 不应触发搜索（got {reason}）"


@pytest.mark.asyncio
async def test_weak_signal_llm_verdict_true_searches():
    """弱信号（CVE 等）→ LLM 复核判"需要实时"才搜。"""
    with patch(
        "src.api.routers.chat.get_model_adapter",
        return_value=_mock_adapter(_Judge(realtime=True)),
    ) as mock_get:
        need, reason = await _needs_realtime("CVE-2024-1234 有哪些公开利用方式", None)
    assert need is True
    assert reason.startswith("llm-verdict")
    mock_get.return_value.chat_completion.assert_awaited_once()


@pytest.mark.asyncio
async def test_weak_signal_llm_verdict_false_skips():
    """弱信号但 LLM 判"不需要实时"→ 不搜（例如问历史 CVE 概念）。"""
    with patch(
        "src.api.routers.chat.get_model_adapter",
        return_value=_mock_adapter(_Judge(realtime=False)),
    ):
        need, reason = await _needs_realtime("CVE 漏洞扫描的原理是什么", None)
    assert need is False


@pytest.mark.asyncio
async def test_weak_signal_llm_error_fails_closed():
    """LLM 复核异常 → 不搜（fail-closed，宁可少搜不烧额度）。"""
    adapter = MagicMock()
    adapter.chat_completion = AsyncMock(side_effect=RuntimeError("model down"))
    with patch("src.api.routers.chat.get_model_adapter", return_value=adapter):
        need, reason = await _needs_realtime("CVE 分析报告怎么理解", None)
    assert need is False
    assert reason == "llm-verdict-error"
