import uuid
from datetime import UTC, datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


class AuditLogger:
    """Append-only audit log writer backed by Elasticsearch."""

    def __init__(self) -> None:
        settings = get_settings()
        self._es = AsyncElasticsearch(hosts=[settings.es_hosts])
        self._index = settings.es_index_audit

    async def log(
        self,
        event_id: str,
        node: str,
        action: str,
        actor: str = "system",
        details: dict[str, Any] | None = None,
    ) -> None:
        doc = {
            "doc_id": str(uuid.uuid4()),
            "event_id": event_id,
            "node": node,
            "action": action,
            "actor": actor,
            "details": details or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }
        try:
            await self._es.index(index=self._index, document=doc)
        except Exception as exc:
            # Audit failures must never crash the main flow — log and continue
            logger.error("audit_write_failed", error=str(exc), doc_id=doc["doc_id"])

    async def close(self) -> None:
        await self._es.close()

    async def count_for_user(self, username: str) -> int:
        """Count audit events where ``username`` is the actor or the target
        (``details.target``).

        The users router uses this to refuse hard-deleting a user who still
        has audit history: actor/target are stored as bare usernames, so a
        physical DELETE would orphan every audit entry they appear in
        (S-P1-2). Best-effort -- on ES errors we return 0 and let the PG
        dependency check remain the hard gate.
        """
        try:
            resp = await self._es.count(
                index=self._index,
                query={
                    "bool": {
                        "should": [
                            {"term": {"actor": username}},
                            {"term": {"details.target": username}},
                        ]
                    }
                },
            )
            return int(resp.get("count", 0))
        except Exception as exc:
            logger.warning("audit_count_failed", username=username, error=str(exc))
            return 0


_audit: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = AuditLogger()
    return _audit
