"""Notification tool — WeChat Work / DingTalk webhook alerts."""

import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.tools.registry import tool

logger = get_logger(__name__)


@tool(name="notify_wechat", description="Send alert via WeChat Work webhook", category="notification")
async def notify_wechat(title: str, content: str) -> dict:
    """Send a markdown message via WeChat Work webhook."""
    webhook = get_settings().wechat_work_webhook
    if not webhook:
        return {"error": "wechat_work_webhook not configured"}

    payload = {
        "msgtype": "markdown",
        "markdown": {"content": f"## {title}\n{content}"},
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook, json=payload)
            return {"status": "ok" if resp.status_code == 200 else "fail", "http_code": resp.status_code}
    except Exception as exc:
        logger.warning("wechat_notify_failed", error=str(exc))
        return {"error": str(exc)}


@tool(name="notify_dingtalk", description="Send alert via DingTalk webhook", category="notification")
async def notify_dingtalk(title: str, content: str) -> dict:
    """Send a markdown message via DingTalk webhook."""
    webhook = get_settings().dingtalk_webhook
    if not webhook:
        return {"error": "dingtalk_webhook not configured"}

    payload = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": f"## {title}\n{content}"},
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook, json=payload)
            return {"status": "ok" if resp.status_code == 200 else "fail", "http_code": resp.status_code}
    except Exception as exc:
        logger.warning("dingtalk_notify_failed", error=str(exc))
        return {"error": str(exc)}

