"""NotifyAnalystConnector — send webhook notifications (WeChat/DingTalk)."""
import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.execution.actions.base import ActionContext, ActionResult

logger = get_logger(__name__)


class NotifyAnalystConnector:
    op_types = ["notify", "notify_analyst"]

    async def execute(self, op: dict, ctx: ActionContext) -> ActionResult:
        import hashlib
        raw = f"{ctx.event_id}:{op.get('type','')}:{str(op.get('params',{}))}"
        op_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

        settings = get_settings()
        text = (
            f"**安全事件处置通知**\n"
            f"事件 ID: {ctx.event_id}\n"
            f"操作: {op.get('type')}\n"
            f"参数: {op.get('params', {})}\n"
        )
        card = {"msgtype": "markdown", "markdown": {"content": text}}

        sent_any = False
        for webhook in filter(None, [settings.wechat_work_webhook, settings.dingtalk_webhook]):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(webhook, json=card)
                    resp.raise_for_status()
                    sent_any = True
            except Exception as exc:
                logger.warning("webhook_push_failed", url=webhook[:40], error=str(exc))

        if sent_any:
            return ActionResult(op_id=op_id, op_type=op.get("type", "notify"), status="success",
                                output="Webhook notification sent")
        return ActionResult(op_id=op_id, op_type=op.get("type", "notify"), status="skipped",
                            output="No webhook configured (set wechat_work_webhook or dingtalk_webhook in .env)")

    async def rollback(self, op: dict, ctx: ActionContext) -> None:
        logger.info("notify_rollback", event_id=ctx.event_id, op_type=op.get("type"))
