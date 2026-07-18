"""DnsBlockConnector — add a domain to Redis DNS blocklist."""
import hashlib

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.execution.actions.base import ActionContext, ActionResult

logger = get_logger(__name__)


class DnsBlockConnector:
    op_types = ["dns_block"]

    async def execute(self, op: dict, ctx: ActionContext) -> ActionResult:
        raw = f"{ctx.event_id}:{op.get('type','')}:{str(op.get('params',{}))}"
        op_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        domain = op.get("params", {}).get("domain", "")

        if not domain:
            return ActionResult(op_id=op_id, op_type="dns_block", status="skipped", output="No domain specified")

        try:
            settings = get_settings()
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            await r.sadd("dns:blocklist", domain)
            await r.expire("dns:blocklist", 86400)
            await r.aclose()
            return ActionResult(op_id=op_id, op_type="dns_block", status="success",
                                output=f"Added '{domain}' to DNS blocklist")
        except Exception as exc:
            logger.warning("dns_block_failed", domain=domain, error=str(exc))
            return ActionResult(op_id=op_id, op_type="dns_block", status="failed", error=str(exc))

    async def rollback(self, op: dict, ctx: ActionContext) -> None:
        domain = op.get("params", {}).get("domain", "")
        if domain:
            try:
                settings = get_settings()
                r = aioredis.from_url(settings.redis_url, decode_responses=True)
                await r.srem("dns:blocklist", domain)
                await r.aclose()
            except Exception as exc:
                logger.warning("dns_block_rollback_failed", domain=domain, error=str(exc))
