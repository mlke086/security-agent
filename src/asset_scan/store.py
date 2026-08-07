"""Asset-scan store (需求②: 内网资产扫描, agentless).

Persists agentless scan tasks / discovered assets / matched vulns /
AI reports into four Elasticsearch indices. ES-only, like the vulnscan
results store -- these are append-heavy, filter-by-task documents and PG
holds no asset data (the hosts table is for managed/agent hosts only).

Index shapes (scheme §2.7):

    assetscan-tasks   {task_id, source, targets[], ports[], engine, modules[],
                       status, created_at, updated_at, started_at, finished_at,
                       error, actor, schedule}
    assetscan-assets  {task_id, ip, hostname, os_guess, ports[], services[],
                       status, detected_at}
    assetscan-vulns   {task_id, ip, port, service, cve, template_id, name,
                       severity, ai_severity, ai_processed, evidence,
                       fix_advice, status, detected_at}
    assetscan-reports {task_id, summary, ai_analysis, stats, top_vulns,
                       recommendations, generated_at}
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

INDEX_ASSET_TASKS = "assetscan-tasks"
INDEX_ASSET_ASSETS = "assetscan-assets"
INDEX_ASSET_VULNS = "assetscan-vulns"
INDEX_ASSET_REPORTS = "assetscan-reports"

_MAPPINGS: dict[str, dict[str, Any]] = {
    INDEX_ASSET_TASKS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "task_id": {"type": "keyword"},
                "source": {"type": "keyword"},
                "targets": {"type": "keyword"},
                "ports": {"type": "integer"},
                "engine": {"type": "keyword"},
                "modules": {"type": "keyword"},
                "status": {"type": "keyword"},
                "actor": {"type": "keyword"},
                "schedule": {"type": "keyword"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
                "started_at": {"type": "date"},
                "finished_at": {"type": "date"},
                "error": {"type": "text"},
            }
        },
    },
    INDEX_ASSET_ASSETS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "task_id": {"type": "keyword"},
                "ip": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "os_guess": {"type": "keyword"},
                "ports": {"type": "integer"},
                "services": {
                    "type": "nested",
                    "properties": {
                        "port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "product": {"type": "keyword"},
                        "version": {"type": "keyword"},
                        "cpe": {"type": "keyword"},
                        "banner": {"type": "text"},
                        "http_title": {"type": "keyword"},
                    },
                },
                "status": {"type": "keyword"},
                "detected_at": {"type": "date"},
            }
        },
    },
    INDEX_ASSET_VULNS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "vuln_id": {"type": "keyword"},
                "task_id": {"type": "keyword"},
                "ip": {"type": "keyword"},
                "port": {"type": "integer"},
                "service": {"type": "keyword"},
                "cve": {"type": "keyword"},
                "template_id": {"type": "keyword"},
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "severity": {"type": "keyword"},
                "ai_severity": {"type": "keyword"},
                "ai_processed": {"type": "boolean"},
                "ai_reason": {"type": "text"},
                "evidence": {"type": "text"},
                "fix_advice": {"type": "text"},
                "status": {"type": "keyword"},
                "detected_at": {"type": "date"},
            }
        },
    },
    INDEX_ASSET_REPORTS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "task_id": {"type": "keyword"},
                "summary": {"type": "text"},
                "ai_analysis": {"type": "text"},
                "stats": {"type": "object", "enabled": False},
                "top_vulns": {"type": "object", "enabled": False},
                "recommendations": {"type": "keyword"},
                "generated_at": {"type": "date"},
            }
        },
    },
}


class AssetScanStore:
    """Thin ES wrapper for agentless asset-scan data."""

    def __init__(self) -> None:
        settings = get_settings()
        self._es = AsyncElasticsearch(hosts=[settings.es_hosts])

    async def close(self) -> None:
        await self._es.close()

    async def ensure_indices(self) -> None:
        for index, body in _MAPPINGS.items():
            try:
                if not await self._es.indices.exists(index=index):
                    await self._es.indices.create(index=index, body=body)
                    logger.info("asset_index_created", index=index)
            except Exception as exc:  # noqa: BLE001
                logger.warning("asset_index_create_failed", index=index, error=str(exc))

    # -- tasks --

    async def save_task(self, task: dict[str, Any]) -> None:
        await self._es.index(index=INDEX_ASSET_TASKS, id=task["task_id"], document=task)

    async def update_task(self, task_id: str, **fields: Any) -> None:
        doc = {k: v for k, v in fields.items() if v is not None}
        if doc:
            doc["updated_at"] = datetime.now(UTC).isoformat()
            await self._es.update(index=INDEX_ASSET_TASKS, id=task_id, doc=doc)

    async def get_task(self, task_id: str) -> dict[str, Any] | None:
        resp = await self._es.get(index=INDEX_ASSET_TASKS, id=task_id, ignore=[404])  # type: ignore[call-arg]
        if not resp.get("found"):
            return None
        return resp["_source"]

    async def list_tasks(
        self,
        *,
        status: str | None = None,
        source: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        must: list[dict] = []
        if status:
            must.append({"term": {"status": status}})
        if source:
            must.append({"term": {"source": source}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        resp = await self._es.search(
            index=INDEX_ASSET_TASKS,
            query=query,
            sort=[{"created_at": {"order": "desc"}}],
            from_=offset,
            size=limit,
        )
        return [h["_source"] for h in resp["hits"]["hits"]]

    async def delete_task(self, task_id: str) -> None:
        """Delete task + its assets/vulns/report (cascade)."""
        for index in (INDEX_ASSET_TASKS, INDEX_ASSET_ASSETS, INDEX_ASSET_VULNS, INDEX_ASSET_REPORTS):
            try:
                await self._es.delete_by_query(
                    index=index,
                    query={"term": {"task_id": task_id}},
                    conflicts="proceed",
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("asset_task_delete_failed", index=index, task_id=task_id, error=str(exc))

    # -- assets --

    async def save_assets(self, task_id: str, assets: list[dict[str, Any]]) -> None:
        actions = [
            {"_index": INDEX_ASSET_ASSETS, "_id": f"{task_id}:{a.get('ip', '')}:{a.get('index', 0)}", "_source": {**a, "task_id": task_id}}
            for a in assets
        ]
        if not actions:
            return
        from elasticsearch.helpers import async_bulk

        await async_bulk(self._es, actions, chunk_size=500)

    async def list_assets(self, task_id: str) -> list[dict[str, Any]]:
        resp = await self._es.search(
            index=INDEX_ASSET_ASSETS,
            query={"term": {"task_id": task_id}},
            sort=[{"detected_at": {"order": "asc"}}],
            size=10000,
        )
        return [h["_source"] for h in resp["hits"]["hits"]]

    # -- vulns --

    async def save_vulns(self, task_id: str, vulns: list[dict[str, Any]]) -> None:
        actions = [
            {
                "_index": INDEX_ASSET_VULNS,
                "_id": v.get("vuln_id") or f"{task_id}:{v.get('ip', '')}:{v.get('cve', '')}:{v.get('port', 0)}",
                "_source": {**v, "task_id": task_id},
            }
            for v in vulns
        ]
        if not actions:
            return
        from elasticsearch.helpers import async_bulk

        await async_bulk(self._es, actions, chunk_size=500)

    async def list_vulns(self, task_id: str) -> list[dict[str, Any]]:
        resp = await self._es.search(
            index=INDEX_ASSET_VULNS,
            query={"term": {"task_id": task_id}},
            sort=[{"detected_at": {"order": "asc"}}],
            size=10000,
        )
        return [h["_source"] for h in resp["hits"]["hits"]]

    async def update_vuln(self, vuln_id: str, **fields: Any) -> None:
        """Update AI-analysis fields on one vuln (ai_* / fix_advice)."""
        doc = {k: v for k, v in fields.items() if v is not None}
        if not doc:
            return
        try:
            await self._es.update(index=INDEX_ASSET_VULNS, id=vuln_id, doc=doc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("asset_vuln_update_failed", vuln_id=vuln_id, error=str(exc))

    # -- reports --

    async def save_report(self, task_id: str, report: dict[str, Any]) -> None:
        await self._es.index(index=INDEX_ASSET_REPORTS, id=task_id, document=report)

    async def get_report(self, task_id: str) -> dict[str, Any] | None:
        resp = await self._es.get(index=INDEX_ASSET_REPORTS, id=task_id, ignore=[404])  # type: ignore[call-arg]
        if not resp.get("found"):
            return None
        return resp["_source"]


_store: AssetScanStore | None = None


def get_asset_store() -> AssetScanStore:
    """Loop-aware singleton (mirrors get_vulnscan_store)."""
    global _store
    if _store is None:
        _store = AssetScanStore()
    return _store
