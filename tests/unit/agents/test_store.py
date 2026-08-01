"""Unit tests for VulnscanStore (ES operations with mocked ES client)."""

from unittest.mock import AsyncMock

import pytest

from src.agents.models import (
    Host,
    HostStatus,
    ScanModule,
    ScanReport,
    ScanTask,
    VulnFilter,
    VulnFinding,
)


class TestStoreModels:
    def test_host_model_defaults(self):
        host = Host(
            agent_id="agent-1",
            hostname="web01",
            ip="10.0.0.1",
            os="linux",
            arch="amd64",
            kernel="5.15",
        )
        assert host.status == HostStatus.ONLINE
        assert host.agent_version == ""

    def test_scan_task_defaults(self):
        task = ScanTask(task_id="task-1", source="manual")
        assert task.status == "queued"
        assert task.policy.modules == [ScanModule.SYS_VULN, ScanModule.BASELINE]

    def test_vuln_finding_serialization(self):
        finding = VulnFinding(
            finding_id="f-1",
            task_id="t-1",
            agent_id="a-1",
            hostname="web01",
            category=ScanModule.SYS_VULN,
            name="Test CVE",
            severity="high",
            cve="CVE-2024-0001",
        )
        data = finding.model_dump()
        assert data["category"] == "sys_vuln"
        assert data["severity"] == "high"

    def test_scan_report_stats(self):
        report = ScanReport(
            task_id="t-1",
            stats={
                "by_severity": {"critical": 2, "high": 5},
                "by_category": {"sys_vuln": 7},
                "total": 7,
            },
            top_vulns=[{"name": "CVE-2024-0001", "severity": "critical"}],
            recommendations=["Patch immediately"],
        )
        assert report.stats["total"] == 7

    # 2026-07-31 consolidate + auto-fix: new-field defaults.
    def test_vuln_finding_scan_history_default(self):
        finding = VulnFinding(
            finding_id="f-1",
            task_id="t-1",
            agent_id="a-1",
            hostname="web01",
            category=ScanModule.SYS_VULN,
            name="Test CVE",
            severity="high",
            cve="CVE-2024-0001",
        )
        assert finding.scan_history == []
        assert finding.detected_at == ""  # date type; save path fills it

    def test_scan_result_scanned_categories_default(self):
        from src.agents.models import ScanResult

        result = ScanResult(
            task_id="t-1",
            agent_id="a-1",
            hostname="web01",
            findings=[],
            batch=1,
            is_final=True,
        )
        assert result.scanned_categories == []


class TestHostPgMapping:
    async def test_get_host_preserves_rule_version_from_pg(self):
        from datetime import UTC, datetime

        from src.agents.store import VulnscanStore

        now = datetime.now(UTC)
        row = {
            "agent_id": "agent-1",
            "hostname": "web01",
            "ip": "10.0.0.1",
            "os": "linux",
            "arch": "amd64",
            "kernel": "6.1",
            "status": "online",
            "group_name": "prod",
            "agent_version": "0.2.1",
            "rule_version": "2026.07.28-130430",
            "last_heartbeat": now,
            "created_at": now,
        }

        class Connection:
            async def fetchrow(self, _query, _agent_id):
                return row

        class Context:
            async def __aenter__(self):
                return Connection()

            async def __aexit__(self, *_args):
                return None

        async def pg_conn():
            return Context()

        store = object.__new__(VulnscanStore)
        store._pg_conn = pg_conn
        host = await store.get_host("agent-1")
        assert host is not None
        assert host.agent_version == "0.2.1"
        assert host.rule_version == "2026.07.28-130430"


class TestListVulnsQuery:
    """list_vulns must build an ES query from the VulnFilter's SCALAR fields,
    not embed the VulnFilter object itself. A previous refactor changed every
    caller to pass a VulnFilter but left list_vulns taking scalar kwargs, so
    the whole dataclass landed in the task_id term -> ES SerializationError
    500 on GET /vulnscan/results. These tests pin the real query building
    (the api tests mock the store, so they never caught it)."""

    @staticmethod
    def _store_with_mock_es():
        from src.agents.store import VulnscanStore

        store = object.__new__(VulnscanStore)
        es = AsyncMock()
        es.search.return_value = {"hits": {"hits": []}}
        store._es = es
        return store, es

    async def test_task_id_term_is_scalar_not_filter_object(self):
        store, es = self._store_with_mock_es()
        await store.list_vulns(VulnFilter(task_id="t-1", limit=50, offset=10))
        es.search.assert_awaited_once()
        query = es.search.await_args.kwargs.get("query") or es.search.await_args.args[0]
        # V12 5.7: task_id filter is an OR over task_id + last_seen_task_id
        # (the reconcile merge keeps the original owner). The scalar must be
        # a plain string, NOT the VulnFilter dataclass (which ES cannot
        # JSON-serialize).
        should = query["bool"]["must"][0]["bool"]["should"]
        terms = [t["term"] for t in should]
        assert {"task_id": "t-1"} in terms
        assert {"last_seen_task_id": "t-1"} in terms
        for t in terms:
            val = list(t.values())[0]
            assert val == "t-1"
            assert not isinstance(val, VulnFilter)
        # limit/offset flow through to from_/size.
        assert es.search.await_args.kwargs["from_"] == 10
        assert es.search.await_args.kwargs["size"] == 50

    async def test_extended_filters_build_correct_query(self):
        store, es = self._store_with_mock_es()
        await store.list_vulns(
            VulnFilter(
                severity="high",
                status="open",
                cve_keyword="2024",
                hostname_keyword="web",
                name_keyword="xss",
                ai_processed=True,
                date_from="2026-07-01T00:00:00Z",
                date_to="2026-07-29T23:59:59Z",
                hostnames=["web01", "web02"],
            )
        )
        query = es.search.await_args.kwargs["query"]
        must = query["bool"]["must"]
        # Every must clause is a plain dict with primitive values (no
        # VulnFilter leaking in).
        import json

        json.dumps(must)  # raises TypeError if a VulnFilter slipped in
        kinds = {next(iter(c)) for c in must}
        assert {"term", "terms", "wildcard", "range"} <= kinds
        assert {"term"} & kinds  # severity/status/ai_processed are terms

    async def test_empty_filter_is_match_all(self):
        store, es = self._store_with_mock_es()
        await store.list_vulns(VulnFilter())
        query = es.search.await_args.kwargs["query"]
        assert query == {"match_all": {}}

    # 2026-07-31 consolidate: server-side batch fetch for the aggregate step.
    async def test_agent_ids_adds_terms_filter(self):
        store, es = self._store_with_mock_es()
        await store.list_vulns(VulnFilter(agent_ids=["a1", "a2"], limit=500))
        query = es.search.await_args.kwargs["query"]
        terms = query["bool"]["must"][0]["terms"]["agent_id"]
        assert terms == ["a1", "a2"]
        assert es.search.await_args.kwargs["size"] == 500


class TestBulkUpdateVulns:
    """bulk_update_vulns must forward mixed index/update/delete actions to
    async_bulk untouched (aggregate reconcile relies on it)."""

    @staticmethod
    def _store_with_mock_es():
        from src.agents.store import VulnscanStore

        store = object.__new__(VulnscanStore)
        store._es = AsyncMock()
        return store

    async def test_forwards_actions_verbatim(self):
        from unittest.mock import patch

        store = self._store_with_mock_es()
        actions = [
            {"_op_type": "index", "_index": "vulnscan-vulns", "_id": "a", "_source": {"x": 1}},
            {"_op_type": "update", "_index": "vulnscan-vulns", "_id": "b", "doc": {"status": "fixed"}},
            {"_op_type": "delete", "_index": "vulnscan-vulns", "_id": "c"},
        ]
        # store.py imports async_bulk locally at call time, so patch the real
        # module path (elasticsearch.helpers) rather than store.async_bulk.
        with patch("elasticsearch.helpers.async_bulk") as bulk:
            await store.bulk_update_vulns(actions)
            bulk.assert_awaited_once()
            assert bulk.await_args.args[1] == actions

    async def test_noop_on_empty(self):
        from unittest.mock import patch

        store = self._store_with_mock_es()
        with patch("elasticsearch.helpers.async_bulk") as bulk:
            await store.bulk_update_vulns([])
            bulk.assert_not_awaited()


class TestListVulnsAll:
    """Spec-P1-RECON (V12): list_vulns_all scrolls with search_after so
    aggregate reconcile never silently truncates a >10k vuln set."""

    @staticmethod
    def _store_with_mock_es():
        from src.agents.store import VulnscanStore

        store = object.__new__(VulnscanStore)
        es = AsyncMock()
        store._es = es
        return store, es

    @staticmethod
    def _hit(finding_id, detected_at):
        return {
            "_source": {
                "finding_id": finding_id,
                "task_id": "task-1",
                "agent_id": "agent-a",
                "hostname": "web-01",
                "category": "sys_vuln",
                "name": "CVE-2024-0001",
                "cve": "CVE-2024-0001",
                "severity": "high",
                "evidence": "...",
                "fix_advice": "patch",
                "status": "open",
                "detected_at": detected_at,
                "scan_history": [],
            },
            "sort": [detected_at, finding_id],
        }

    async def test_pages_until_short_page(self):
        store, es = self._store_with_mock_es()
        page1 = [self._hit("f-1", "2026-01-01"), self._hit("f-2", "2026-01-02")]
        page2 = [self._hit("f-3", "2026-01-03")]  # short page -> stop
        es.search.side_effect = [
            {"hits": {"hits": page1}},
            {"hits": {"hits": page2}},
        ]
        out = await store.list_vulns_all(VulnFilter(agent_ids=["a1"], limit=2))
        assert [v.finding_id for v in out] == ["f-1", "f-2", "f-3"]
        assert es.search.await_count == 2
        # second call must carry the previous page's raw sort cursor
        kwargs2 = es.search.await_args.kwargs
        assert kwargs2["search_after"] == ["2026-01-02", "f-2"]
        assert "from_" not in kwargs2

    async def test_stops_on_empty_page(self):
        store, es = self._store_with_mock_es()
        # limit=1: first page is full (1 hit) so paging continues, then
        # the next page is empty -> stop.
        es.search.side_effect = [
            {"hits": {"hits": [self._hit("f-1", "2026-01-01")]}},
            {"hits": {"hits": []}},
        ]
        out = await store.list_vulns_all(VulnFilter(agent_ids=["a1"], limit=1))
        assert [v.finding_id for v in out] == ["f-1"]
        assert es.search.await_count == 2

    async def test_single_page_no_search_after(self):
        store, es = self._store_with_mock_es()
        es.search.side_effect = [
            {"hits": {"hits": [self._hit("f-1", "2026-01-01")]}},
        ]
        out = await store.list_vulns_all(VulnFilter(agent_ids=["a1"], limit=5))
        assert len(out) == 1
        # first (and only) call must NOT carry search_after
        assert "search_after" not in es.search.await_args.kwargs


class TestBulkUpdateVulnsRetry:
    """Spec-P1-RECON (V12): bulk_update_vulns chunks large batches and
    retries transient ES errors instead of dropping the writes."""

    @staticmethod
    def _store_with_mock_es():
        from src.agents.store import VulnscanStore

        store = object.__new__(VulnscanStore)
        store._es = AsyncMock()
        return store

    async def test_chunk_size_2000(self):
        from unittest.mock import patch

        store = self._store_with_mock_es()
        actions = [{"_op_type": "index", "_index": "vulnscan-vulns", "_id": "a", "_source": {"x": 1}}]
        with patch("elasticsearch.helpers.async_bulk") as bulk:
            await store.bulk_update_vulns(actions)
            assert bulk.await_args.kwargs["chunk_size"] == 2000

    async def test_retries_then_raises(self):
        from unittest.mock import patch

        store = self._store_with_mock_es()
        actions = [{"_op_type": "index", "_index": "vulnscan-vulns", "_id": "a", "_source": {"x": 1}}]
        with patch(
            "elasticsearch.helpers.async_bulk",
            side_effect=[ConnectionError("es down"), ConnectionError("es down"), ConnectionError("es down")],
        ) as bulk:
            try:
                await store.bulk_update_vulns(actions)
                raise AssertionError("expected bulk to raise after retries")
            except ConnectionError:
                pass
        # exactly 3 attempts
        assert bulk.await_count == 3

    async def test_retries_then_succeeds(self):
        from unittest.mock import patch

        store = self._store_with_mock_es()
        actions = [{"_op_type": "index", "_index": "vulnscan-vulns", "_id": "a", "_source": {"x": 1}}]
        with patch(
            "elasticsearch.helpers.async_bulk",
            side_effect=[ConnectionError("es down"), AsyncMock()],
        ) as bulk:
            await store.bulk_update_vulns(actions)
        assert bulk.await_count == 2


class TestVulnFilterKeywordGuard:
    """V12 阶段 5.5 (Spec-P2-OVERLONG): keyword inputs are capped at the
    query layer so ES max_regex_length can never turn a user typo into a 500."""

    @staticmethod
    def _store_with_mock_es():
        from src.agents.store import VulnscanStore

        store = object.__new__(VulnscanStore)
        store._es = AsyncMock()
        return store

    async def test_overlong_cve_keyword_raises_value_error(self):
        store = self._store_with_mock_es()
        with pytest.raises(ValueError, match="exceeds 200"):
            await store.list_vulns(VulnFilter(cve_keyword="x" * 201))

    async def test_overlong_hostname_keyword_raises(self):
        store = self._store_with_mock_es()
        with pytest.raises(ValueError, match="exceeds 200"):
            await store.list_vulns(VulnFilter(hostname_keyword="y" * 500))

    async def test_overlong_name_keyword_raises(self):
        store = self._store_with_mock_es()
        with pytest.raises(ValueError, match="exceeds 200"):
            await store.list_vulns(VulnFilter(name_keyword="z" * 201))

    async def test_boundary_200_ok(self):
        store = self._store_with_mock_es()
        store._es.search.return_value = {"hits": {"hits": []}}
        await store.list_vulns(VulnFilter(cve_keyword="a" * 200, limit=10))
        # no raise

    async def test_name_query_uses_keyword_subfield(self):
        store = self._store_with_mock_es()
        store._es.search.return_value = {"hits": {"hits": []}}
        await store.list_vulns(VulnFilter(name_keyword="xss", limit=10))
        q = store._es.search.await_args.kwargs["query"]
        wild = q["bool"]["must"][0]["wildcard"]
        assert "name.keyword" in wild
