"""Host performance metrics store (需求① Agent 性能监控).

Persists per-agent host_metrics samples (cpu/mem/disk/net/load) into a
single Elasticsearch index ``secagent-hostmetrics``. PG is intentionally
not used -- a 15s tick at 100 hosts is ~576k docs/day, append-only
time-series data that is exactly ES's sweet spot (ClickHouse is the
documented scale-out path once hosts >500 or retention >90d; the store
interface is the swap point, the API/frontend stay unchanged).

Wire format from agent (agent/internal/metrics/reporter.go):

  {"v":1, "type":"host_metrics", "ts":"2026-08-06T10:00:15Z", "payload":{
    "cpu_percent":42.3, "mem_percent":68.1, "mem_total_mb":8192, "mem_used_mb":5580,
    "disk_percent":71.0, "disk_total_gb":100, "disk_used_gb":71,
    "net_in_kbps":128.5, "net_out_kbps":64.2, "load1":1.05}}

The agent's ``agent_id``/``hostname`` are stamped by the WS gateway on
receipt (same trust boundary as monitor_event), not trusted from the wire.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from src.common.config.settings import get_settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


INDEX_METRICS = "secagent-hostmetrics"

# Explicit mapping so every numeric field is float-typed (dynamic mapping
# would guess long for integer-looking values and break avg aggregations
# on mixed data). ts is the agent-side sample timestamp.
METRICS_MAPPING: dict[str, Any] = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "agent_id": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "ts": {"type": "date"},
            "cpu_percent": {"type": "float"},
            "mem_percent": {"type": "float"},
            "mem_total_mb": {"type": "float"},
            "mem_used_mb": {"type": "float"},
            "disk_percent": {"type": "float"},
            "disk_total_gb": {"type": "float"},
            "disk_used_gb": {"type": "float"},
            "net_in_kbps": {"type": "float"},
            "net_out_kbps": {"type": "float"},
            "load1": {"type": "float"},
        }
    },
}

# Upper bound for a raw-point query (24h @ 15s = 5760 points; 7d is served
# by the downsampled path, so the raw cap only guards against misbehaving
# callers asking for huge windows). Must stay below ES's default
# max_result_window (10000) -- a larger size would 400 on the search.
MAX_RAW_POINTS = 9000


class HostMetricsStore:
    """Thin ES wrapper for host performance metrics. PG intentionally not used."""

    def __init__(self) -> None:
        settings = get_settings()
        self._es = AsyncElasticsearch(hosts=[settings.es_hosts])

    async def close(self) -> None:
        await self._es.close()

    async def ensure_indices(self) -> None:
        try:
            if not await self._es.indices.exists(index=INDEX_METRICS):
                await self._es.indices.create(index=INDEX_METRICS, body=METRICS_MAPPING)
                logger.info("metrics_index_created", extra={"index": INDEX_METRICS})
        except Exception as exc:  # noqa: BLE001
            logger.warning("metrics_index_create_failed", extra={"error": str(exc)})

    async def save_metrics(self, agent_id: str, hostname: str, payload: dict[str, Any]) -> None:
        """Index one host_metrics sample. Best-effort: failures log, never raise.

        Called fire-and-forget from the WS gateway -- a slow/absent ES must
        never affect the agent connection (same isolation principle as
        monitor_event). ``ts`` falls back to server receive time when the
        agent sample timestamp is missing or unparseable.
        """
        ts = payload.get("ts") or datetime.now(UTC).isoformat()
        doc: dict[str, Any] = {
            "agent_id": agent_id,
            "hostname": hostname,
            "ts": ts,
        }
        for field in (
            "cpu_percent",
            "mem_percent",
            "mem_total_mb",
            "mem_used_mb",
            "disk_percent",
            "disk_total_gb",
            "disk_used_gb",
            "net_in_kbps",
            "net_out_kbps",
            "load1",
        ):
            val = payload.get(field)
            if isinstance(val, (int, float)):
                doc[field] = float(val)
        try:
            await self._es.index(index=INDEX_METRICS, document=doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "metrics_es_index_failed",
                extra={"agent_id": agent_id, "error": str(exc)},
            )

    async def query_timeseries(
        self,
        agent_id: str,
        since: str,
        until: str,
        downsample_interval: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return time-series points for ``agent_id`` in [since, until].

        Raw mode (``downsample_interval=None``): points sorted ts asc,
        each ``{ts, cpu, mem, disk, net_in, net_out, load1}`` -- the shape
        the frontend Line charts consume.

        Downsampled mode (7d range): a ``date_histogram`` fixed_interval
        (e.g. "5m") with avg sub-aggregations, so a 7d view returns
        ~2k points instead of 40k raw docs. Bucket key (epoch millis) is
        converted back to ISO for a uniform point shape.
        """
        try:
            query = {
                "bool": {
                    "must": [
                        {"term": {"agent_id": agent_id}},
                        {"range": {"ts": {"gte": since, "lte": until}}},
                    ]
                }
            }
            if downsample_interval:
                resp = await self._es.search(
                    index=INDEX_METRICS,
                    query=query,
                    size=0,
                    aggs={
                        "series": {
                            "date_histogram": {
                                "field": "ts",
                                "fixed_interval": downsample_interval,
                            },
                            "aggs": {
                                "cpu": {"avg": {"field": "cpu_percent"}},
                                "mem": {"avg": {"field": "mem_percent"}},
                                "disk": {"avg": {"field": "disk_percent"}},
                                "net_in": {"avg": {"field": "net_in_kbps"}},
                                "net_out": {"avg": {"field": "net_out_kbps"}},
                                "load1": {"avg": {"field": "load1"}},
                            },
                        }
                    },
                )
                buckets = (resp.get("aggregations") or {}).get("series", {}).get("buckets", [])
                return [
                    {
                        "ts": datetime.fromtimestamp(b["key"] / 1000, UTC).isoformat(),
                        "cpu": _round(b.get("cpu", {}).get("value")),
                        "mem": _round(b.get("mem", {}).get("value")),
                        "disk": _round(b.get("disk", {}).get("value")),
                        "net_in": _round(b.get("net_in", {}).get("value")),
                        "net_out": _round(b.get("net_out", {}).get("value")),
                        "load1": _round(b.get("load1", {}).get("value")),
                    }
                    for b in buckets
                ]
            resp = await self._es.search(
                index=INDEX_METRICS,
                query=query,
                sort=[{"ts": {"order": "asc"}}],
                size=MAX_RAW_POINTS,
                # elasticsearch-py 8.x: parameter is ``source`` (7.x was ``_source``).
                source=[
                    "ts",
                    "cpu_percent",
                    "mem_percent",
                    "disk_percent",
                    "net_in_kbps",
                    "net_out_kbps",
                    "load1",
                ],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("metrics_es_search_failed", extra={"error": str(exc)})
            return []
        hits = resp.get("hits", {}).get("hits", [])
        return [
            {
                "ts": h["_source"].get("ts", ""),
                "cpu": _round(h["_source"].get("cpu_percent")),
                "mem": _round(h["_source"].get("mem_percent")),
                "disk": _round(h["_source"].get("disk_percent")),
                "net_in": _round(h["_source"].get("net_in_kbps")),
                "net_out": _round(h["_source"].get("net_out_kbps")),
                "load1": _round(h["_source"].get("load1")),
            }
            for h in hits
        ]

    async def latest(self, agent_id: str) -> dict[str, Any] | None:
        """Return the single most recent sample for ``agent_id`` (or None)."""
        try:
            resp = await self._es.search(
                index=INDEX_METRICS,
                query={"term": {"agent_id": agent_id}},
                sort=[{"ts": {"order": "desc"}}],
                size=1,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("metrics_es_latest_failed", extra={"error": str(exc)})
            return None
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return None
        src = hits[0]["_source"]
        return {
            "agent_id": src.get("agent_id", agent_id),
            "ts": src.get("ts", ""),
            "cpu": _round(src.get("cpu_percent")),
            "mem": _round(src.get("mem_percent")),
            "mem_total_mb": _round(src.get("mem_total_mb")),
            "mem_used_mb": _round(src.get("mem_used_mb")),
            "disk": _round(src.get("disk_percent")),
            "disk_total_gb": _round(src.get("disk_total_gb")),
            "disk_used_gb": _round(src.get("disk_used_gb")),
            "net_in": _round(src.get("net_in_kbps")),
            "net_out": _round(src.get("net_out_kbps")),
            "load1": _round(src.get("load1")),
        }

    async def delete_before(self, cutoff: str) -> int:
        """Delete samples older than ``cutoff`` (ISO string). Retention sweep.

        Returns the deleted count; failures log and return 0 -- the 6h
        sweep simply retries next round.
        """
        try:
            resp = await self._es.delete_by_query(
                index=INDEX_METRICS,
                query={"range": {"ts": {"lt": cutoff}}},
                conflicts="proceed",
            )
            return int(resp.get("deleted", 0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("metrics_es_purge_failed", extra={"error": str(exc)})
            return 0


def _round(value: Any) -> float | None:
    """Round an ES agg/hit value to 2 decimals; None stays None."""
    if value is None:
        return None
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return None


_store: HostMetricsStore | None = None


def get_metrics_store() -> HostMetricsStore:
    """Loop-aware singleton (mirrors get_monitor_store)."""
    global _store
    if _store is None:
        _store = HostMetricsStore()
    return _store
