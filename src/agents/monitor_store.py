"""Monitor event store (Phase 5 of monitoring plan).

Persists host-level monitor events (process snapshots for now; file
integrity events later) into a single Elasticsearch index. PG is
intentionally not used for these -- a 30-second tick at 1000 hosts
would mean 2.8M rows/day and the events are immutable append-only
time-series, which is exactly ES's sweet spot.

Wire format from agent (see agent/internal/monitor/process.go):

  {
    "v": 1, "type": "monitor_event", "ts": "...",
    "payload": {
      "collected_at": "...",
      "interval_sec": 30,
      "hostname": "web-01",
      "total_count": 142,
      "truncated": false,
      "processes": [
        {"pid": 1, "ppid": 0, "name": "systemd", "cmdline": "...",
         "exe": "/sbin/init", "user_name": "root", "uid": "0",
         "create_time": 0},
        ...
      ]
    }
  }

The agent's ``agent_id`` is stamped by the WS gateway on receipt
(same trust boundary as scan_result / heartbeat), not trusted from
the wire.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from src.common.config.settings import get_settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


INDEX_MONITOR = "secagent-monitor"

# Keeps the per-snapshot doc small: we do not search by process
# internals (no need for keyword indexing on every field) but we DO
# filter by agent_id + collected_at heavily. raw is disabled to keep
# the index small; the Sigma detector gets the structured data via
# its own in-process snapshot path, not by re-querying ES.
MONITOR_MAPPING: dict[str, Any] = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "agent_id": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "collected_at": {"type": "date"},
            "received_at": {"type": "date"},
            "interval_sec": {"type": "integer"},
            "total_count": {"type": "integer"},
            "truncated": {"type": "boolean"},
            "process_count": {"type": "integer"},
            "raw": {"type": "object", "enabled": False},
        }
    },
}


class MonitorStore:
    """Thin ES wrapper for monitor events. PG intentionally not used."""

    def __init__(self) -> None:
        settings = get_settings()
        self._es = AsyncElasticsearch(hosts=[settings.es_hosts])

    async def close(self) -> None:
        await self._es.close()

    async def ensure_indices(self) -> None:
        try:
            if not await self._es.indices.exists(index=INDEX_MONITOR):
                await self._es.indices.create(index=INDEX_MONITOR, body=MONITOR_MAPPING)
                logger.info("monitor_index_created", extra={"index": INDEX_MONITOR})
        except Exception as exc:  # noqa: BLE001
            logger.warning("monitor_index_create_failed", extra={"error": str(exc)})

    async def save_event(self, agent_id: str, payload: dict[str, Any]) -> None:
        """Index one monitor event. Best-effort: failures log but never raise.

        The WS gateway is the only caller; it does not care whether
        the write succeeded beyond the audit trail. The Sigma detector
        re-fetches from the agent over the WS, not from ES, so a
        transient ES outage only delays the console view, not detection.
        """
        processes = payload.get("processes") or []
        doc = {
            "agent_id": agent_id,
            "hostname": str(payload.get("hostname", "")),
            "collected_at": payload.get("collected_at"),
            "received_at": datetime.now(UTC).isoformat(),
            "interval_sec": int(payload.get("interval_sec", 0) or 0),
            "total_count": int(payload.get("total_count", 0) or 0),
            "truncated": bool(payload.get("truncated", False)),
            "process_count": len(processes) if isinstance(processes, list) else 0,
            "raw": payload,
        }
        try:
            await self._es.index(index=INDEX_MONITOR, document=doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "monitor_es_index_failed",
                extra={"agent_id": agent_id, "error": str(exc)},
            )

    async def list_events(
        self,
        agent_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return the most recent N monitor events for ``agent_id``.

        The query is intentionally simple: filter on agent_id, sort
        by received_at desc. We return a slimmed-down shape (no full
        process list) because the API consumer is the console's
        MonitorEventsDrawer; the heavy payload can be fetched by a
        separate endpoint if/when needed.
        """
        try:
            resp = await self._es.search(
                index=INDEX_MONITOR,
                body={
                    "size": max(1, min(limit, 500)),
                    "sort": [{"received_at": {"order": "desc"}}],
                    # agent_id is mapped as text+keyword (dynamic mapping
                    # wins when the index predates the explicit mapping);
                    # the .keyword sub-field gives us exact match.
                    "query": {"term": {"agent_id.keyword": agent_id}},
                    "_source": [
                        "agent_id", "hostname", "collected_at", "received_at",
                        "interval_sec", "total_count", "truncated", "process_count",
                    ],
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("monitor_es_search_failed", extra={"error": str(exc)})
            return []
        hits = resp.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]


_store: MonitorStore | None = None


def get_monitor_store() -> MonitorStore:
    """Loop-aware singleton (mirrors get_alert_store)."""
    global _store
    if _store is None:
        _store = MonitorStore()
    return _store
