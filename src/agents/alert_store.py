"""AlertStore (Phase 0 of docs/Agent monitoring plan).

Persists normalized EDR alerts into:
  - PG (primary, fast filters; pg is the source of truth)
  - ES (full-text search for Phase 6 Sigma rule hunting)

Mirrors VulnscanStore:
  - ensure_indices() creates the ES index on first run
  - save_alert() / get_alert() / list_alerts() / update_alert_status() are PG-primary
  - ES writes are best-effort (failure logs a warning, does not block)
  - get_alert_store() is a loop-aware singleton so tests running on different
    loops do not see 'Event loop is closed' from the elasticsearch transport.
"""

import asyncio
import json
from datetime import datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from src.agents.models import Alert
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

INDEX_ALERTS = "secagent-alerts"

ALERTS_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "alert_id": {"type": "keyword"},
            "source": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "status": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "host_ip": {"type": "ip"},
            "agent_id": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "mitre_attack": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "iocs.ips": {"type": "ip"},
            "iocs.domains": {"type": "keyword"},
            "iocs.hashes": {"type": "keyword"},
            "iocs.urls": {"type": "keyword"},
            "title": {"type": "text"},
            "description": {"type": "text"},
            "occurred_at": {"type": "date"},
            "received_at": {"type": "date"},
            "raw": {"type": "object", "enabled": False},
        }
    },
}


def _parse_ts(value: Any) -> datetime | None:
    """asyncpg timestamptz needs a real datetime (or None). Empty -> None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


class AlertStore:
    """EDR alert store. PG-primary; ES for full-text search."""

    def __init__(self) -> None:
        s = get_settings()
        self._es = AsyncElasticsearch(hosts=[s.es_hosts])

    async def close(self) -> None:
        await self._es.close()

    async def ensure_indices(self) -> None:
        try:
            if not await self._es.indices.exists(index=INDEX_ALERTS):
                await self._es.indices.create(index=INDEX_ALERTS, body=ALERTS_MAPPING)
                logger.info("alerts_index_created", index=INDEX_ALERTS)
        except Exception as exc:
            logger.warning("alerts_index_create_failed", error=str(exc))

    async def save_alert(self, alert: Alert) -> None:
        from src.common.db.pg import get_pg_pool

        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO alerts (alert_id, source, severity, status, "
                "hostname, host_ip, agent_id, rule_id, title, "
                "occurred_at, received_at, iocs, mitre_attack, tags, raw) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14::jsonb,$15::jsonb) "
                "ON CONFLICT (alert_id) DO UPDATE SET "
                "  source = EXCLUDED.source, "
                "  severity = EXCLUDED.severity, "
                "  status = EXCLUDED.status, "
                "  hostname = EXCLUDED.hostname, "
                "  host_ip = EXCLUDED.host_ip, "
                "  agent_id = EXCLUDED.agent_id, "
                "  rule_id = EXCLUDED.rule_id, "
                "  title = EXCLUDED.title, "
                "  occurred_at = EXCLUDED.occurred_at, "
                "  iocs = EXCLUDED.iocs, "
                "  mitre_attack = EXCLUDED.mitre_attack, "
                "  tags = EXCLUDED.tags, "
                "  raw = EXCLUDED.raw",
                alert.alert_id,
                alert.source.value,
                alert.severity.value,
                alert.status.value,
                alert.hostname,
                alert.host_ip,
                alert.agent_id,
                alert.rule_id,
                alert.title,
                _parse_ts(alert.occurred_at),
                _parse_ts(alert.received_at),
                alert.iocs.model_dump_json(),
                json.dumps(alert.mitre_attack),
                json.dumps(alert.tags),
                json.dumps(alert.raw),
            )
        # Best-effort ES mirror (PG is the source of truth).
        try:
            await self._es.index(
                index=INDEX_ALERTS,
                id=alert.alert_id,
                document=alert.model_dump(mode="json"),
            )
        except Exception as exc:
            logger.warning("alerts_es_index_failed", alert_id=alert.alert_id, error=str(exc))

    async def get_alert(self, alert_id: str) -> dict | None:
        from src.common.db.pg import get_pg_pool

        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", alert_id)
        if not row:
            return None
        return dict(row)

    async def list_alerts(
        self,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        hostname: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        from src.common.db.pg import get_pg_pool

        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            params.append(severity)
            clauses.append("severity = $" + str(len(params)))
        if status:
            params.append(status)
            clauses.append("status = $" + str(len(params)))
        if source:
            params.append(source)
            clauses.append("source = $" + str(len(params)))
        if hostname:
            params.append(hostname)
            clauses.append("hostname = $" + str(len(params)))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        params.append(offset)
        sql = (
            "SELECT alert_id, source, severity, status, hostname, host_ip, "
            "agent_id, rule_id, title, occurred_at, received_at, "
            "iocs, mitre_attack, tags, raw "
            "FROM alerts"
            + where
            + " ORDER BY received_at DESC LIMIT $"
            + str(len(params) - 1)
            + " OFFSET $"
            + str(len(params))
        )
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]

    async def update_alert_status(self, alert_id: str, status: str) -> bool:
        from src.common.db.pg import get_pg_pool

        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE alerts SET status = $1 WHERE alert_id = $2",
                status,
                alert_id,
            )
        return result.endswith(" 1")

    async def count_alerts(self, severity: str | None = None) -> int:
        from src.common.db.pg import get_pg_pool

        pool = await get_pg_pool()
        if severity:
            sql = "SELECT COUNT(*) FROM alerts WHERE severity = $1"
            params: list[Any] = [severity]
        else:
            sql = "SELECT COUNT(*) FROM alerts"
            params = []
        async with pool.acquire() as conn:
            return await conn.fetchval(sql, *params)


# Loop-aware singleton. See VulnscanStore for the same pattern; rationale
# is that AsyncElasticsearch's transport pool binds to the loop active at
# first call, and pytest-asyncio's function-scoped loop means the second
# test on a new loop would otherwise crash with 'Event loop is closed'.
_alert_store: AlertStore | None = None
_alert_store_loop: asyncio.AbstractEventLoop | None = None


def get_alert_store() -> AlertStore:
    global _alert_store, _alert_store_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None
    if _alert_store is not None and _alert_store_loop is not current_loop:
        _alert_store = None
    if _alert_store is None:
        _alert_store = AlertStore()
        _alert_store_loop = current_loop
    return _alert_store
