"""ApprovalStore - HITL approval queue (PG for persistence, Redis pub/sub for real-time).

Phase 1 migration: approval state + votes persisted in PostgreSQL for audit/query;
Redis retained solely for pub/sub real-time notification (wait_result).
"""

import time
from typing import Any

import asyncpg
import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


class ApprovalStore:
    """Approval queue: PG for state/votes, Redis pub/sub for real-time notification."""

    def __init__(self) -> None:
        settings = get_settings()
        self._redis = aioredis.from_url(settings.redis_url, decode_responses=True)

    async def _pg(self):
        from src.common.db.pg import get_pg_pool
        return await get_pg_pool()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(self, approval_id: str, event_id: str, level: str, n_required: int = 1) -> None:
        pool = await self._pg()
        await pool.execute(
            "INSERT INTO approvals (approval_id, event_id, status, required, operation_level) "
            "VALUES ($1, $2, 'pending', $3, $4)",
            approval_id, event_id, n_required, level,
        )

    async def get(self, approval_id: str) -> dict[str, Any] | None:
        pool = await self._pg()
        row = await pool.fetchrow("SELECT * FROM approvals WHERE approval_id = $1", approval_id)
        if not row:
            return None
        votes = await pool.fetch(
            "SELECT voter, decision FROM approval_votes WHERE approval_id = $1 ORDER BY voted_at",
            approval_id,
        )
        return {
            "approval_id": str(row["approval_id"]),
            "event_id": row["event_id"],
            "status": row["status"],
            "required": row["required"],
            "operation_level": row["operation_level"],
            "approvals": [{"actor": v["voter"], "decision": v["decision"]} for v in votes],
            "created_at": row["created_at"].isoformat() if row["created_at"] else "",
        }

    async def list_pending(self) -> list[dict[str, Any]]:
        pool = await self._pg()
        rows = await pool.fetch(
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at"
        )
        results = []
        for row in rows:
            votes = await pool.fetch(
                "SELECT voter FROM approval_votes WHERE approval_id = $1",
                row["approval_id"],
            )
            results.append({
                "approval_id": str(row["approval_id"]),
                "event_id": row["event_id"],
                "status": row["status"],
                "required": row["required"],
                "operation_level": row["operation_level"],
                "approvals": [{"actor": v["voter"]} for v in votes],
                "created_at": row["created_at"].isoformat() if row["created_at"] else "",
            })
        return results

    # ------------------------------------------------------------------
    # Voting (PG transaction + Redis pub/sub notification)
    # ------------------------------------------------------------------

    async def add_vote(self, event_id: str, actor: str, decision: str) -> dict[str, Any]:
        pool = await self._pg()
        # Find pending approval for this event
        row = await pool.fetchrow(
            "SELECT approval_id, required, status FROM approvals "
            "WHERE event_id = $1 AND status = 'pending' LIMIT 1",
            event_id,
        )
        if not row:
            logger.warning("add_vote_no_approval_found", event_id=event_id)
            return {"status": "not_found", "count": 0}

        aid = str(row["approval_id"])
        required = row["required"]

        # Insert vote (UNIQUE constraint prevents double-vote)
        try:
            await pool.execute(
                "INSERT INTO approval_votes (approval_id, voter, decision) VALUES ($1, $2, $3)",
                aid, actor, decision,
            )
        except asyncpg.UniqueViolationError:
            pass  # already voted, no-op

        # Determine new status
        if decision == "rejected":
            await pool.execute(
                "UPDATE approvals SET status = 'rejected', resolved_at = NOW() WHERE approval_id = $1",
                aid,
            )
            status = "rejected"
            count = 0
        else:
            count = await pool.fetchval(
                "SELECT COUNT(*) FROM approval_votes WHERE approval_id = $1 AND decision = 'approved'",
                aid,
            )
            if count >= required:
                await pool.execute(
                    "UPDATE approvals SET status = 'approved', resolved_at = NOW() WHERE approval_id = $1",
                    aid,
                )
                status = "approved"
            else:
                status = "pending"

        # Notify waiters via Redis pub/sub
        await self._redis.publish(f"approval:notify:{aid}", f"{status}:{actor}")
        return {"status": status, "count": int(count)}

    async def resolve(self, approval_id: str, status: str) -> None:
        pool = await self._pg()
        await pool.execute(
            "UPDATE approvals SET status = $1, resolved_at = NOW() WHERE approval_id = $2",
            status, approval_id,
        )
        await self._redis.publish(f"approval:notify:{approval_id}", status)
        logger.info("approval_resolved", approval_id=approval_id, status=status)

    # ------------------------------------------------------------------
    # Wait (Redis pub/sub for real-time; PG for state check)
    # ------------------------------------------------------------------

    async def wait_result(self, approval_id: str, timeout: int = 300) -> str:
        """Block until terminal state (approved/rejected/timeout).

        Checks PG for current status, then uses Redis pub/sub for real-time
        notification. Loops ignoring 'pending' intermediate votes.
        """
        channel = f"approval:notify:{approval_id}"
        deadline = time.monotonic() + timeout

        # Fast path: check PG
        pool = await self._pg()
        row = await pool.fetchrow("SELECT status FROM approvals WHERE approval_id = $1", approval_id)
        current = row["status"] if row else "pending"
        if current != "pending":
            return current

        pubsub = self._redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            # Re-check after subscribe (lost-wakeup race)
            row = await pool.fetchrow("SELECT status FROM approvals WHERE approval_id = $1", approval_id)
            current = row["status"] if row else "pending"
            if current != "pending":
                return current

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    await self.resolve(approval_id, "timeout")
                    return "timeout"
                msg = await pubsub.get_message(
                    timeout=min(remaining, 5), ignore_subscribe_messages=True
                )
                if msg:
                    raw = str(msg["data"])
                    status = raw.split(":", 1)[0] if ":" in raw else raw
                    if status in ("approved", "rejected", "timeout"):
                        return status
                    # pending: keep waiting, re-check PG
                    row = await pool.fetchrow("SELECT status FROM approvals WHERE approval_id = $1", approval_id)
                    current = row["status"] if row else "pending"
                    if current != "pending":
                        return current
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()

    async def close(self) -> None:
        await self._redis.aclose()


_store: ApprovalStore | None = None


def get_approval_store() -> ApprovalStore:
    global _store
    if _store is None:
        _store = ApprovalStore()
    return _store
