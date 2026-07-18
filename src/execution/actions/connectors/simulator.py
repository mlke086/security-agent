"""SimulatorConnector — dry-run default for unregistered op_types."""
from src.execution.actions.base import ActionContext, ActionResult


class SimulatorConnector:
    op_types = ["firewall_block", "isolate_host", "terminate_process", "quarantine_file", "edr_policy"]

    async def execute(self, op: dict, ctx: ActionContext) -> ActionResult:
        import hashlib
        raw = f"{ctx.event_id}:{op.get('type','')}:{str(op.get('params',{}))}"
        op_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return ActionResult(op_id=op_id, op_type=op.get("type", "unknown"),
                            status="dry_run" if ctx.dry_run else "success",
                            output=f"Simulated {op.get('type')}")

    async def rollback(self, op: dict, ctx: ActionContext) -> None:
        pass
