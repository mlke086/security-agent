"""Action execution framework — ActionContext, ActionResult, ActionConnector protocol."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol


@dataclass
class ActionContext:
    """Context for executing an action operation."""

    event_id: str
    approval_id: str | None = None
    actor: str = "system"
    dry_run: bool = True


@dataclass
class ActionResult:
    """Result of executing a single operation."""

    op_id: str
    op_type: str
    status: str = "dry_run"  # success | failed | skipped | dry_run
    output: str = ""
    error: str = ""
    started_at: str = ""
    finished_at: str = ""
    # P1-EXEC-03 (2026-07-20): preserve the original op dict (incl. params)
    # so the dispatcher can pass the full op to connector.rollback(). Without
    # this rollback sees only {"type": op_type} and connectors like dns_block
    # cannot undo (they need the domain).
    op: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = datetime.now(UTC).isoformat()
        if not self.finished_at and self.status != "dry_run":
            self.finished_at = datetime.now(UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "op_id": self.op_id,
            "op_type": self.op_type,
            "status": self.status,
            "output": self.output,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class ActionConnector(Protocol):
    """Protocol for action connectors. Each connector handles one or more op_types."""

    op_types: list[str]

    async def execute(self, op: dict[str, Any], ctx: ActionContext) -> ActionResult: ...

    async def rollback(self, op: dict[str, Any], ctx: ActionContext) -> None:
        """Best-effort rollback. Default implementation logs and does nothing."""
        from src.common.logging.logger import get_logger

        get_logger(__name__).warning("rollback_not_implemented", op_type=op.get("type"))
