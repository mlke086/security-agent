"""ES-backed store for vulnscan subsystem (hosts, tasks, results, vulns, reports).
Phase 2: Host CRUD uses PG as primary store with ES mirror for search.
Tasks/Results/Vulns/Reports remain ES-only (full-text / aggregation).
"""

from datetime import UTC, datetime

from elasticsearch import AsyncElasticsearch

from src.agents.models import Host, ScanReport, ScanResult, ScanTask, VulnFinding
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

INDEX_HOSTS = "vulnscan-hosts"
INDEX_TASKS = "vulnscan-tasks"
INDEX_RESULTS = "vulnscan-results"
INDEX_VULNS = "vulnscan-vulns"
INDEX_REPORTS = "vulnscan-reports"

_MAPPINGS = {
    INDEX_HOSTS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "status": {"type": "keyword"},
                "group": {"type": "keyword"},
                "rule_version": {"type": "keyword"},
                "last_heartbeat": {"type": "date"},
            }
        },
    },
    INDEX_TASKS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "status": {"type": "keyword"},
                "source": {"type": "keyword"},
                "targets": {"type": "keyword"},
                "created_at": {"type": "date"},
            }
        },
    },
    INDEX_RESULTS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "task_id": {"type": "keyword"},
                "agent_id": {"type": "keyword"},
                "is_final": {"type": "boolean"},
                "ts": {"type": "date"},
            }
        },
    },
    INDEX_VULNS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "task_id": {"type": "keyword"},
                "agent_id": {"type": "keyword"},
                "cve": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "ai_severity": {"type": "keyword"},
                "status": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "category": {"type": "keyword"},
                "detected_at": {"type": "date"},
            }
        },
    },
    INDEX_REPORTS: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "task_id": {"type": "keyword"},
                "generated_at": {"type": "date"},
            }
        },
    },
}


def _parse_ts(value):
    """Best-effort parse an ISO-8601 string / datetime / None for asyncpg timestamptz.

    asyncpg's timestamptz codec rejects bare strings -- it needs a real
    datetime.datetime (or datetime.date / int / None). Empty / unparseable
    input is normalised to None so asyncpg writes NULL instead of crashing.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Handle ``Z`` suffix (Python <3.11 fromisoformat didn't accept it).
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


class VulnscanStore:
    """ES-backed store for the vulnerability scanning subsystem.
    Phase 2: Host CRUD is PG-primary with ES mirror; tasks/results/vulns stay ES-only.
    """

    def __init__(self) -> None:
        s = get_settings()
        self._es = AsyncElasticsearch(hosts=[s.es_hosts])

    async def _pg_conn(self):
        """Return a PG connection context manager (async with ... as conn)."""
        from src.common.db.pg import get_pg_pool as _get_pool

        pool = await _get_pool()
        return pool.acquire()  # PoolAcquireContext (async context manager)

    async def ensure_indices(self) -> None:
        """Create ES indices with mappings if they do not already exist."""
        for name, body in _MAPPINGS.items():
            try:
                if not await self._es.indices.exists(index=name):
                    await self._es.indices.create(index=name, body=body)
                    logger.info("vulnscan_index_created", index=name)
            except Exception as exc:
                logger.warning("vulnscan_index_create_failed", index=name, error=str(exc))

    # -- Hosts (Phase 2: PG primary + ES mirror) --

    async def save_host(self, host: Host) -> None:
        data = host.model_dump()
        status_val = host.status.value if hasattr(host.status, "value") else str(host.status)
        # P0-fix (2026-07-17): last_heartbeat is a timestamptz column. The Host
        # Pydantic model defaults it to "", and asyncpg refuses to bind "" to a
        # timestamptz (it expects datetime.date/datetime or None). Normalise
        # here so every caller is safe regardless of whether they remembered to
        # set last_heartbeat.
        last_hb = _parse_ts(getattr(host, "last_heartbeat", None))
        # PG primary
        async with await self._pg_conn() as conn:
            await conn.execute(
                """
                INSERT INTO hosts (agent_id, hostname, ip, os, arch, kernel, status,
                                   group_name, agent_version, rule_version, last_heartbeat)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                ON CONFLICT (agent_id) DO UPDATE SET
                    hostname=$2, ip=$3, os=$4, arch=$5, kernel=$6, status=$7,
                    group_name=$8, agent_version=$9, rule_version=$10, last_heartbeat=$11,
                    updated_at=NOW()
            """,
                host.agent_id,
                host.hostname,
                host.ip,
                host.os,
                host.arch,
                host.kernel,
                status_val,
                host.group,
                host.agent_version,
                getattr(host, "rule_version", "") or "",
                last_hb,
            )
        # ES mirror (fire-and-forget)
        try:
            await self._es.index(index=INDEX_HOSTS, id=host.agent_id, document=data)
        except Exception as exc:
            logger.warning("host_es_mirror_failed", agent_id=host.agent_id, error=str(exc))

    async def get_host(self, agent_id: str) -> Host | None:
        # PG primary
        try:
            async with await self._pg_conn() as conn:
                row = await conn.fetchrow("SELECT * FROM hosts WHERE agent_id=$1", agent_id)
            if row:
                lhb = row["last_heartbeat"].isoformat() if row["last_heartbeat"] else ""
                return Host(
                    agent_id=row["agent_id"],
                    hostname=row["hostname"] or "",
                    ip=row["ip"] or "",
                    os=row["os"] or "",
                    arch=row["arch"] or "",
                    kernel=row["kernel"] or "",
                    status=row["status"],
                    group=row["group_name"],
                    agent_version=row["agent_version"],
                    last_heartbeat=lhb,
                    created_at=row["created_at"].isoformat(),
                )
        except Exception as exc:
            logger.warning("host_pg_read_failed", agent_id=agent_id, error=str(exc))
        # ES fallback
        resp = await self._es.get(index=INDEX_HOSTS, id=agent_id, ignore=[404])  # type: ignore[call-arg]
        if not resp.get("found"):
            return None
        return Host(**resp["_source"])

    async def list_hosts(
        self,
        status: str | None = None,
        group: str | None = None,
        limit: int = 100,
        offset: int = 0,
        exclude_decommissioned: bool = True,
    ) -> list[Host]:
        # PG primary
        try:
            async with await self._pg_conn() as conn:
                where = []
                params = []
                idx = 0
                if status:
                    idx += 1
                    where.append(f"status=${idx}")
                    params.append(status)
                elif exclude_decommissioned:
                    # Default ON: hide soft-deleted hosts from the operator
                    # view so deleting a host actually makes it disappear.
                    where.append("status<>'decommissioned'")
                if group:
                    idx += 1
                    where.append(f"group_name=${idx}")
                    params.append(group)
                sql = "SELECT * FROM hosts"
                if where:
                    sql += " WHERE " + " AND ".join(where)
                sql += " ORDER BY last_heartbeat DESC NULLS LAST"
                sql += f" LIMIT {limit} OFFSET {offset}"
                rows = await conn.fetch(sql, *params)
            if rows:
                return [
                    Host(
                        agent_id=r["agent_id"],
                        hostname=r["hostname"] or "",
                        ip=r["ip"] or "",
                        os=r["os"] or "",
                        arch=r["arch"] or "",
                        kernel=r["kernel"] or "",
                        status=r["status"],
                        group=r["group_name"],
                        agent_version=r["agent_version"],
                        last_heartbeat=r["last_heartbeat"].isoformat()
                        if r["last_heartbeat"]
                        else "",
                        created_at=r["created_at"].isoformat(),
                    )
                    for r in rows
                ]
        except Exception as exc:
            logger.warning("host_pg_list_failed", error=str(exc))
        # ES fallback
        must = []
        if status:
            must.append({"term": {"status": status}})
        elif exclude_decommissioned:
            # Mirror the PG default -- hide decommissioned from operator view.
            must.append({"bool": {"must_not": [{"term": {"status": "decommissioned"}}]}})
        if group:
            must.append({"term": {"group": group}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        resp = await self._es.search(
            index=INDEX_HOSTS,
            query=query,
            sort=[{"last_heartbeat": {"order": "desc"}}],
            from_=offset,
            size=limit,
        )
        return [Host(**h["_source"]) for h in resp["hits"]["hits"]]

    # -- Host groups (Phase 2: PG only; group_name is the join key) --

    async def list_groups(self) -> list[dict]:
        """List all host groups with member counts.

        Includes groups that exist only on ``hosts.group_name`` (legacy rows
        predating the ``host_groups`` table) so the UI can manage them too.
        """
        async with await self._pg_conn() as conn:
            rows = await conn.fetch("""
                SELECT g.group_name AS name,
                       g.description AS description,
                       g.created_at AS created_at,
                       COALESCE(c.cnt, 0) AS member_count,
                       'managed' AS origin
                FROM host_groups g
                LEFT JOIN (
                    SELECT group_name, COUNT(*) AS cnt
                    FROM hosts
                    WHERE status <> 'decommissioned' AND group_name IS NOT NULL
                    GROUP BY group_name
                ) c ON c.group_name = g.group_name
                UNION
                SELECT h.group_name AS name,
                       NULL AS description,
                       NULL AS created_at,
                       COUNT(*) AS member_count,
                       'legacy' AS origin
                FROM hosts h
                WHERE h.status <> 'decommissioned' AND h.group_name IS NOT NULL
                  AND h.group_name NOT IN (SELECT group_name FROM host_groups)
                GROUP BY h.group_name
                ORDER BY name
            """)
        return [dict(r) for r in rows]

    async def create_group(self, name: str, description: str = "") -> None:
        async with await self._pg_conn() as conn:
            await conn.execute(
                "INSERT INTO host_groups (group_name, description) VALUES ($1, $2)",
                name,
                description,
            )

    async def delete_group(self, name: str) -> int:
        """Delete a group row. Returns the number of hosts still referencing
        it. P1-4 修复：有成员时不删除（仅返回 count），由调用方决定是否
        拒绝 -- 避免组行被删但 hosts.group_name 仍引用变成 legacy 孤儿。
        """
        async with await self._pg_conn() as conn:
            cnt = await conn.fetchval(
                "SELECT COUNT(*) FROM hosts WHERE group_name=$1 AND status<>'decommissioned'",
                name,
            )
            if cnt:
                return cnt
            await conn.execute("DELETE FROM host_groups WHERE group_name=$1", name)
        return 0

    _ALLOWED_HOST_COLS = frozenset(
        {
            "status",
            "hostname",
            "ip",
            "os",
            "arch",
            "kernel",
            "group_name",
            "agent_version",
            "rule_version",
            "last_heartbeat",
        }
    )
    # 可空字段：传 None 时显式写 NULL（用于"清空"语义，如清空主机组）。
    # 其他字段 None 仍按"跳过"处理（避免误把 hostname/ip 等清空）。
    _NULLABLE_HOST_COLS = frozenset({"group_name"})

    async def update_host(self, agent_id: str, **fields) -> None:
        # PG primary
        try:
            # P0-fix (2026-07-17): same defensive normalisation as save_host.
            # ``last_heartbeat`` is a timestamptz column; asyncpg only accepts
            # datetime objects, never bare strings. Parse + fall back to ``now``.
            from datetime import UTC, datetime

            for k, v in list(fields.items()):
                if k == "last_heartbeat":
                    if not v or (isinstance(v, str) and not v.strip()):
                        fields[k] = datetime.now(UTC)
                    else:
                        fields[k] = _parse_ts(v) or datetime.now(UTC)
            async with await self._pg_conn() as conn:
                set_clauses = ["updated_at=NOW()"]
                params = [agent_id]
                idx = 1
                for k, v in fields.items():
                    # P1-3 修复：可空字段（group_name）允许 None 写 NULL，
                    # 使 update_host_group(agent_id, None) 清空组生效；
                    # 非空字段 None 仍跳过。
                    if k in self._ALLOWED_HOST_COLS and (
                        v is not None or k in self._NULLABLE_HOST_COLS
                    ):
                        idx += 1
                        set_clauses.append(f"{k}=${idx}")
                        params.append(v)
                if len(set_clauses) > 1:
                    await conn.execute(
                        f"UPDATE hosts SET {', '.join(set_clauses)} WHERE agent_id=$1", *params
                    )
        except Exception as exc:
            logger.warning("host_pg_update_failed", agent_id=agent_id, error=str(exc))
        # ES mirror：可空字段 None 也写入（ES 设为 null），与 PG 保持一致。
        doc = {
            k: v
            for k, v in fields.items()
            if k in self._ALLOWED_HOST_COLS and (v is not None or k in self._NULLABLE_HOST_COLS)
        }
        if doc:
            try:
                await self._es.update(index=INDEX_HOSTS, id=agent_id, doc=doc)
            except Exception as exc:
                logger.warning("host_es_mirror_failed", agent_id=agent_id, error=str(exc))

    async def delete_host(self, agent_id: str) -> None:
        # PG primary
        try:
            async with await self._pg_conn() as conn:
                await conn.execute("DELETE FROM hosts WHERE agent_id=$1", agent_id)
        except Exception as exc:
            logger.warning("host_pg_delete_failed", agent_id=agent_id, error=str(exc))
        # ES mirror
        try:
            await self._es.delete(index=INDEX_HOSTS, id=agent_id, ignore=[404])  # type: ignore[call-arg]
        except Exception as exc:
            logger.warning("host_es_mirror_failed", agent_id=agent_id, error=str(exc))

    async def mark_offline_expired(self, heartbeat_timeout_sec: int) -> int:
        from datetime import timedelta

        cutoff = datetime.now(UTC) - timedelta(seconds=heartbeat_timeout_sec * 2 + 30)
        # PG primary
        pg_count = 0
        try:
            async with await self._pg_conn() as conn:
                result = await conn.execute(
                    "UPDATE hosts SET status=$1, updated_at=NOW() WHERE status=$2 AND last_heartbeat < $3",
                    "offline",
                    "online",
                    cutoff,
                )
                pg_count = int(result.split(" ")[1]) if result else 0
        except Exception as exc:
            logger.warning("host_pg_mark_offline_failed", error=str(exc))
        # ES mirror (batch search + update)
        resp = await self._es.search(
            index=INDEX_HOSTS,
            query={
                "bool": {
                    "must": [
                        {"term": {"status": "online"}},
                        {"range": {"last_heartbeat": {"lt": cutoff.isoformat()}}},
                    ]
                }
            },
            size=1000,
        )
        for hit in resp["hits"]["hits"]:
            await self.update_host(hit["_id"], status="offline")
        return max(pg_count, len(resp["hits"]["hits"]))

    # -- Tasks -- (ES-only, no change)

    async def save_task(self, task: ScanTask) -> None:
        await self._es.index(index=INDEX_TASKS, id=task.task_id, document=task.model_dump())

    async def get_task(self, task_id: str) -> ScanTask | None:
        resp = await self._es.get(index=INDEX_TASKS, id=task_id, ignore=[404])  # type: ignore[call-arg]
        if not resp.get("found"):
            return None
        return ScanTask(**resp["_source"])

    async def list_tasks(
        self,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ScanTask]:
        must = [{"term": {"status": status}}] if status else []
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        resp = await self._es.search(
            index=INDEX_TASKS,
            query=query,
            sort=[{"created_at": {"order": "desc"}}],
            from_=offset,
            size=limit,
        )
        return [ScanTask(**h["_source"]) for h in resp["hits"]["hits"]]

    async def update_task(self, task_id: str, **fields) -> None:
        doc = {k: v for k, v in fields.items() if v is not None}
        if doc:
            await self._es.update(index=INDEX_TASKS, id=task_id, doc=doc)

    async def delete_task(self, task_id: str) -> None:
        """删除任务及其关联数据（results/vulns/report）。"""
        # 删关联 findings（按 task_id 查再删，vulns 无 task_id 字段索引时用 query delete）
        try:
            await self._es.delete_by_query(
                index=INDEX_VULNS,
                body={"query": {"term": {"task_id": task_id}}},
                refresh=True,
            )
            await self._es.delete_by_query(
                index=INDEX_RESULTS,
                body={"query": {"term": {"task_id": task_id}}},
                refresh=True,
            )
            await self._es.delete(index=INDEX_REPORTS, id=task_id, ignore=[404])  # type: ignore[call-arg]
            await self._es.delete(index=INDEX_TASKS, id=task_id, ignore=[404])  # type: ignore[call-arg]
        except Exception as exc:
            logger.warning("task_delete_failed", task_id=task_id, error=str(exc))

    # -- Results -- (ES-only)

    async def save_result(self, result: ScanResult) -> None:
        await self._es.index(index=INDEX_RESULTS, document=result.model_dump())

    async def list_results(self, task_id: str, agent_id: str | None = None) -> list[ScanResult]:
        must = [{"term": {"task_id": task_id}}]
        if agent_id:
            must.append({"term": {"agent_id": agent_id}})
        resp = await self._es.search(
            index=INDEX_RESULTS,
            query={"bool": {"must": must}},
            sort=[{"ts": "asc"}],
            size=10000,
        )
        return [ScanResult(**h["_source"]) for h in resp["hits"]["hits"]]

    # -- Vulns -- (ES-only)

    async def save_vulns(self, findings: list[VulnFinding]) -> None:
        # ES detected_at 是 date 类型，空字符串会致索引失败（agent 上报空串）。
        # 清理：空 detected_at 设为当前时间；model_dump 后处理。
        from datetime import UTC, datetime

        from elasticsearch.helpers import async_bulk

        now_iso = datetime.now(UTC).isoformat()
        actions = []
        for f in findings:
            doc = f.model_dump()
            if not doc.get("detected_at"):
                doc["detected_at"] = now_iso
            actions.append({"_index": INDEX_VULNS, "_id": f.finding_id, "_source": doc})
        if actions:
            await async_bulk(self._es, actions)

    async def list_vulns(
        self,
        task_id: str | None = None,
        hostname: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[VulnFinding]:
        must = []
        if task_id:
            must.append({"term": {"task_id": task_id}})
        if hostname:
            must.append({"term": {"hostname": hostname}})
        if severity:
            must.append({"term": {"severity": severity}})
        if status:
            must.append({"term": {"status": status}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        resp = await self._es.search(
            index=INDEX_VULNS,
            query=query,
            sort=[{"detected_at": {"order": "desc"}}],
            from_=offset,
            size=limit,
        )
        return [VulnFinding(**h["_source"]) for h in resp["hits"]["hits"]]

    async def get_vuln(self, finding_id: str) -> VulnFinding | None:
        """O(1) 单条漏洞查询（ES _id get）。P2-8 修复：替代 list_vulns(10000)
        全量拉取再内存遍历的 O(n) 写法。"""
        try:
            resp = await self._es.get(index=INDEX_VULNS, id=finding_id, ignore=[404])  # type: ignore[call-arg]
            if resp.get("found"):
                return VulnFinding(**resp["_source"])
        except Exception as exc:
            logger.warning("vuln_get_failed", finding_id=finding_id, error=str(exc))
        return None

    async def update_vuln(self, finding_id: str, **fields) -> None:
        doc = {k: v for k, v in fields.items() if v is not None}
        if doc:
            await self._es.update(index=INDEX_VULNS, id=finding_id, doc=doc)

    # -- Reports -- (ES-only)

    async def save_report(self, report: ScanReport) -> None:
        await self._es.index(index=INDEX_REPORTS, id=report.task_id, document=report.model_dump())

    async def get_report(self, task_id: str) -> ScanReport | None:
        resp = await self._es.get(index=INDEX_REPORTS, id=task_id, ignore=[404])  # type: ignore[call-arg]
        if not resp.get("found"):
            return None
        return ScanReport(**resp["_source"])

    async def close(self) -> None:
        await self._es.close()


_store: VulnscanStore | None = None


def get_vulnscan_store() -> VulnscanStore:
    global _store
    if _store is None:
        _store = VulnscanStore()
    return _store
