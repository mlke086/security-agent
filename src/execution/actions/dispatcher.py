"""ActionDispatcher — routes operations to registered connectors."""

import hashlib
from typing import Any

import redis.asyncio as aioredis

from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

from .base import ActionConnector, ActionContext, ActionResult
from .connectors import (
    DnsBlockConnector,
    NotifyAnalystConnector,
    SiemTagConnector,
    SimulatorConnector,
)

logger = get_logger(__name__)


class ActionDispatcher:
    """Routes playbook operations to registered connectors with dry-run, idempotency, and rollback."""

    def __init__(self, dry_run: bool = True) -> None:
        self._dry_run = dry_run
        self._registry: dict[str, ActionConnector] = {}
        self._register(SimulatorConnector())
        self._register(NotifyAnalystConnector())
        self._register(SiemTagConnector())
        self._register(DnsBlockConnector())

    def _register(self, connector: ActionConnector) -> None:
        for ot in connector.op_types:
            self._registry[ot] = connector

    def _op_id(self, event_id: str, op: dict[str, Any]) -> str:
        raw = f"{event_id}:{op.get('type','')}:{str(op.get('params',{}))}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    async def execute_playbook(
        self, playbook: dict[str, Any], ctx: ActionContext
    ) -> list[dict[str, Any]]:
        """Execute all operations in the playbook sequentially with rollback on failure."""
        audit = get_audit_logger()
        results: list[ActionResult] = []

        for op in playbook.get("operations", []):
            op_type = op.get("type", "")
            op_id = self._op_id(ctx.event_id, op)
            connector = self._registry.get(op_type)

            # Idempotency: skip if already executed successfully (check only; mark after success)
            if await self._is_done(op_id, ctx):
                results.append(
                    ActionResult(
                        op_id=op_id,
                        op_type=op_type,
                        status="skipped",
                        output="Duplicate operation (already executed)",
                        op=op,
                    )
                )
                continue

            if not connector:
                logger.warning("connector_not_implemented", op_type=op_type)
                results.append(
                    ActionResult(
                        op_id=op_id,
                        op_type=op_type,
                        status="skipped",
                        output=f"No connector for {op_type}",
                        op=op,
                    )
                )
                continue

            if ctx.dry_run:
                await audit.log(
                    event_id=ctx.event_id,
                    node="action",
                    action="execute_op_dry_run",
                    actor=ctx.actor,
                    details={"op_type": op_type, "op_id": op_id, "params": op.get("params", {})},
                )
                results.append(
                    ActionResult(
                        op_id=op_id,
                        op_type=op_type,
                        status="dry_run",
                        output=f"Dry-run: would execute {op_type}",
                        op=op,
                    )
                )
                continue

            # Execute
            await audit.log(
                event_id=ctx.event_id,
                node="action",
                action="execute_op_start",
                actor=ctx.actor,
                details={"op_type": op_type, "op_id": op_id},
            )
            try:
                result = await connector.execute(op, ctx)
                # P1-EXEC-03: stash the original op dict (with params) so the
                # rollback path can pass it to connector.rollback().
                result.op = op
                await self._mark_done(op_id, ctx)
                results.append(result)
            except Exception as exc:
                error = str(exc)
                logger.error("execute_op_failed", op_type=op_type, op_id=op_id, error=error)
                await audit.log(
                    event_id=ctx.event_id,
                    node="action",
                    action="execute_op_error",
                    actor=ctx.actor,
                    details={"op_type": op_type, "op_id": op_id, "error": error},
                )
                results.append(
                    ActionResult(op_id=op_id, op_type=op_type, status="failed", error=error, op=op)
                )
                # Rollback already-executed operations
                await self._rollback(ctx, results)
                break

        return [r.to_dict() for r in results]

    async def _rollback(self, ctx: ActionContext, results: list[ActionResult]) -> None:
        """Best-effort rollback of successfully executed operations (reverse order).

        P1-EXEC-03 (2026-07-20): use the original op dict (with params) stored
        on each ActionResult. The previous version only forwarded {"type":
        r.op_type}, which made rollback a no-op for any connector that needs
        params (e.g. dns_block needs the domain to unblock it).
        """
        for r in reversed(results):
            if r.status != "success":
                continue
            connector = self._registry.get(r.op_type)
            if connector:
                # Prefer the full op (with params) stored on the result.
                # Fall back to {"type": op_type} for backward compat with any
                # code path that didn't populate r.op.
                op_for_rollback = r.op if r.op else {"type": r.op_type}
                try:
                    await connector.rollback(op_for_rollback, ctx)
                except Exception as exc:
                    logger.error("rollback_failed", op_type=r.op_type, error=str(exc))

    async def _is_done(self, op_id: str, ctx: ActionContext) -> bool:
        """Check only whether the op was already executed successfully."""
        if ctx.dry_run:
            return False
        try:
            settings = get_settings()
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            try:
                return bool(await r.exists(f"action:done:{op_id}"))
            finally:
                await r.aclose()
        except Exception:
            return False  # Without Redis, skip dedup (allow execution)

    async def _mark_done(self, op_id: str, ctx: ActionContext) -> None:
        """Mark the op as done AFTER successful execution so failures stay retryable."""
        if ctx.dry_run:
            return
        try:
            settings = get_settings()
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            try:
                await r.set(f"action:done:{op_id}", "1", ex=86400)
            finally:
                await r.aclose()
        except Exception:
            pass
