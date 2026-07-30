"""API tests for /api/v1/vulnscan endpoints.

Covers: tasks/parse, tasks CRUD, task cancel, stream, results, reports, vulns CRUD.
"""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


def _login(role="admin"):
    passwords = {
        "admin": "admin123",
        "analyst": "analyst123",
        "viewer": "viewer123",
        "responder": "responder123",
    }
    resp = client.post("/api/v1/auth/login", json={"username": role, "password": passwords[role]})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth_headers(role="admin"):
    return {"Authorization": f"Bearer {_login(role)}"}


def _mock_store():
    store = AsyncMock()
    store.get_task = AsyncMock(return_value=None)
    store.list_tasks = AsyncMock(return_value=[])
    store.save_task = AsyncMock()
    store.update_task = AsyncMock()
    store.list_vulns = AsyncMock(return_value=[])
    store.get_vuln = AsyncMock(return_value=None)
    store.get_report = AsyncMock(return_value=None)
    store.save_report = AsyncMock()
    store.save_result = AsyncMock()
    return store


# -- tasks/parse --------------------------------------------------------------


class TestParseIntent:
    def test_parse_as_analyst(self):
        headers = _auth_headers("analyst")
        from src.agents.models import ScanIntent

        mock = AsyncMock()
        mock.chat_completion.return_value = ScanIntent(targets=["h1"], modules=[])
        with patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock):
            resp = client.post(
                "/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan h1"}, headers=headers
            )
            assert resp.status_code == 200

    def test_parse_no_auth_401(self):
        resp = client.post("/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan"})
        assert resp.status_code == 401

    def test_parse_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post(
            "/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan"}, headers=headers
        )
        assert resp.status_code == 403


# -- tasks --------------------------------------------------------------------


class TestTasks:
    def test_create_task_as_admin(self):
        headers = _auth_headers("admin")
        with (
            patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs,
            patch("src.api.routers.vulnscan.get_audit_logger") as mock_audit,
        ):
            mock_vs.return_value = _mock_store()
            mock_audit.return_value.log = AsyncMock()
            resp = client.post(
                "/api/v1/vulnscan/tasks",
                json={"source": "manual", "targets": ["host-a"], "modules": ["sys_vuln"]},
                headers=headers,
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "task_id" in data
            assert data["status"] == "queued"

    def test_create_task_no_auth_401(self):
        resp = client.post("/api/v1/vulnscan/tasks", json={"targets": ["h1"]})
        assert resp.status_code == 401

    def test_list_tasks(self):
        headers = _auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/tasks", headers=headers)
            assert resp.status_code == 200
            assert "items" in resp.json()

    def test_get_task_not_found(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.get_task.return_value = None
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/tasks/task-99", headers=headers)
            assert resp.status_code == 404

    def test_cancel_task_not_found(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.get_task.return_value = None
            mock_vs.return_value = store
            resp = client.post("/api/v1/vulnscan/tasks/task-99/cancel", headers=headers)
            assert resp.status_code == 404

    def test_cancel_task_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post("/api/v1/vulnscan/tasks/task-1/cancel", headers=headers)
        assert resp.status_code == 403


# -- stream -------------------------------------------------------------------


class TestStream:
    def test_stream_bad_token_401(self):
        resp = client.get("/api/v1/vulnscan/tasks/task-1/stream", params={"token": "bad"})
        assert resp.status_code == 401


# -- results ------------------------------------------------------------------


class TestResults:
    def test_list_results(self):
        headers = _auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/results", headers=headers)
            assert resp.status_code == 200
            assert "items" in resp.json()

    def test_filter_by_severity(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.get(
                "/api/v1/vulnscan/results", params={"severity": "high"}, headers=headers
            )
            assert resp.status_code == 200


# -- reports ------------------------------------------------------------------


class TestReports:
    def test_get_report_not_found(self):
        headers = _auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.get_report.return_value = None
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/reports/task-99", headers=headers)
            assert resp.status_code == 404

    def test_get_report_no_auth_401(self):
        resp = client.get("/api/v1/vulnscan/reports/task-1")
        assert resp.status_code == 401


# -- vulns --------------------------------------------------------------------


class TestVulns:
    def test_get_vuln_not_found(self):
        headers = _auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.list_vulns.return_value = []
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/vulns/f-99", headers=headers)
            assert resp.status_code == 404

    def test_patch_vuln_invalid_status_422(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.patch(
                "/api/v1/vulnscan/vulns/f-1", json={"status": "invalid"}, headers=headers
            )
            assert resp.status_code == 422

    def test_patch_vuln_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.patch("/api/v1/vulnscan/vulns/f-1", json={"status": "open"}, headers=headers)
        assert resp.status_code == 403


# -- 2026-07-29 UX upgrade: extended filters + fix-time PATCH ---------------


class TestResultsExtendedFilters:
    """New query params on /api/v1/vulnscan/results (cve, cve_keyword,
    hostname_keyword, name_keyword, group, ai_processed, date_from,
    date_to) all reach the store layer with the right kwargs."""

    def test_extended_filters_forwarded_to_store(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.get(
                "/api/v1/vulnscan/results",
                params={
                    "cve": "CVE-2024-0001",
                    "cve_keyword": "2024",
                    "hostname_keyword": "web",
                    "name_keyword": "xss",
                    "ai_processed": "true",
                    "date_from": "2026-07-01T00:00:00Z",
                    "date_to": "2026-07-29T23:59:59Z",
                },
                headers=headers,
            )
            assert resp.status_code == 200
            store.list_vulns.assert_called_once()
            filt = store.list_vulns.await_args.args[0]
            assert filt.cve == "CVE-2024-0001"
            assert filt.cve_keyword == "2024"
            assert filt.hostname_keyword == "web"
            assert filt.name_keyword == "xss"
            assert filt.ai_processed is True
            assert filt.date_from == "2026-07-01T00:00:00Z"
            assert filt.date_to == "2026-07-29T23:59:59Z"

    def test_group_filter_pushes_hostnames_server_side(self):
        """S-P1-4: when the operator passes group=order-svc, the router
        looks up the group's hosts and pushes the hostname set into the ES
        query as a server-side ``terms`` filter (hostnames=...), instead of
        fetching a capped 200-row page and filtering in memory (which
        silently dropped group members beyond the cap)."""
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = _auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.list_hosts = AsyncMock(
                return_value=[
                    Host(
                        agent_id="a1",
                        hostname="order-1",
                        ip="10.0.0.1",
                        os="linux",
                        arch="amd64",
                        kernel="5.x",
                        group="order-svc",
                    ),
                ]
            )
            # Server-side filter returns only the matching vuln.
            v_in = VulnFinding(
                finding_id="f-in",
                task_id="t",
                agent_id="a",
                hostname="order-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
            )
            store.list_vulns.return_value = [v_in]
            mock_vs.return_value = store
            resp = client.get(
                "/api/v1/vulnscan/results",
                params={"group": "order-svc"},
                headers=headers,
            )
        assert resp.status_code == 200
        ids = [it["finding_id"] for it in resp.json()["items"]]
        assert ids == ["f-in"]
        # The hostnames were pushed into the ES query, not post-filtered,
        # and the limit is bumped for the group view to avoid truncation.
        filt = store.list_vulns.await_args.args[0]
        assert filt.hostnames == ["order-1"]
        assert filt.limit == 2000


class TestVulnPatchFixTime:
    """PATCH /vulnscan/vulns/{id} stamps first_fixed_at and last_fixed_at
    when status transitions to fixed/accepted, so the vuln list can
    display SLA / re-open history without joining the audit log."""

    def test_patch_to_fixed_records_fix_time(self):
        from src.agents.models import ScanModule, VulnFinding

        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            existing = VulnFinding(
                finding_id="f-1",
                task_id="t",
                agent_id="a",
                hostname="web-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
            )
            store.get_vuln = AsyncMock(return_value=existing)
            mock_vs.return_value = store
            resp = client.patch(
                "/api/v1/vulnscan/vulns/f-1",
                json={"status": "fixed"},
                headers=headers,
            )
            assert resp.status_code == 200
            assert store.update_vuln.await_count == 1
            kwargs = store.update_vuln.await_args.kwargs
            assert kwargs["status"] == "fixed"
            assert kwargs["first_fixed_at"]
            assert kwargs["last_fixed_at"] == kwargs["first_fixed_at"]

    def test_patch_to_fixed_preserves_first_fixed_at(self):
        """When the vuln was already fixed once before, re-fixing must
        update last_fixed_at but NOT overwrite first_fixed_at (the router
        only forwards first_fixed_at when it is currently empty)."""
        from src.agents.models import ScanModule, VulnFinding

        headers = _auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            existing = VulnFinding(
                finding_id="f-1",
                task_id="t",
                agent_id="a",
                hostname="web-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
                first_fixed_at="2026-07-15T10:00:00+00:00",
                last_fixed_at="2026-07-15T10:00:00+00:00",
            )
            store.get_vuln = AsyncMock(return_value=existing)
            mock_vs.return_value = store
            resp = client.patch(
                "/api/v1/vulnscan/vulns/f-1",
                json={"status": "fixed"},
                headers=headers,
            )
            assert resp.status_code == 200
            kwargs = store.update_vuln.await_args.kwargs
            # first_fixed_at is left untouched (not even in the patch);
            # only last_fixed_at gets refreshed.
            assert "first_fixed_at" not in kwargs
            assert "last_fixed_at" in kwargs
            assert kwargs["last_fixed_at"] != "2026-07-15T10:00:00+00:00"


# -- 2026-07-29 UX upgrade: /vulnscan/host-stats ----------------------




class TestVulnFilter:
    # V10 1.1: 11-kwarg Data Clump -> VulnFilter dataclass.
    # Confirms the dataclass is immutable (frozen=True) and exposes
    # the same fields the old kwargs took.

    def test_vulnfilter_defaults(self):
        from src.agents.models import VulnFilter

        filt = VulnFilter()
        assert filt.task_id is None
        assert filt.hostnames is None
        assert filt.limit == 200
        assert filt.offset == 0

    def test_vulnfilter_is_frozen(self):
        import dataclasses

        from src.agents.models import VulnFilter

        filt = VulnFilter(task_id="t-1")
        try:
            filt.task_id = "t-2"  # type: ignore[misc]
        except dataclasses.FrozenInstanceError:
            return
        raise AssertionError("VulnFilter should be frozen")

    def test_vulnfilter_paged_via_replace(self):
        import dataclasses

        from src.agents.models import VulnFilter

        filt = VulnFilter(task_id="t-1", limit=200)
        page2 = dataclasses.replace(filt, offset=200)
        assert page2.task_id == "t-1"
        assert page2.limit == 200
        assert page2.offset == 200



class TestHostStats:
    """Per-group vuln aggregation endpoint.

    Used by the host-onboarding page to render the business distribution
    chart and by the scan-task list to surface a host's business group.
    The endpoint is read-only and best-effort; we mock the store to keep
    the test independent of the actual ES / PG stack.
    """

    def test_host_stats_returns_per_group_breakdown(self):
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = _auth_headers("analyst")
        # S-P1-3: /host-stats now uses the shared singleton (was VulnscanStore()),
        # so we mock get_vulnscan_store() with a fully-configured store.
        with (
            patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs,
            patch("src.agents.store.VulnscanStore") as mock_cls,
        ):
            store = _mock_store()
            store.list_groups = AsyncMock(
                return_value=[
                    {
                        "name": "order-svc",
                        "member_count": 2,
                        "description": "",
                        "created_at": "",
                        "origin": "managed",
                    },
                    {
                        "name": "billing-svc",
                        "member_count": 1,
                        "description": "",
                        "created_at": "",
                        "origin": "managed",
                    },
                ]
            )

            async def _list_hosts(group=None, **_):
                # V9 3.1: the router now calls list_hosts once with no
                # group filter to build the hostname -> group map. Return
                # every host in that case; the per-group branches are
                # kept for any other call site that uses the filter.
                all_hosts = [
                    Host(
                        agent_id="a1",
                        hostname="order-1",
                        ip="10.0.0.1",
                        os="linux",
                        arch="amd64",
                        kernel="5.x",
                        group="order-svc",
                    ),
                    Host(
                        agent_id="a2",
                        hostname="order-2",
                        ip="10.0.0.2",
                        os="linux",
                        arch="amd64",
                        kernel="5.x",
                        group="order-svc",
                    ),
                    Host(
                        agent_id="a3",
                        hostname="billing-1",
                        ip="10.0.0.3",
                        os="linux",
                        arch="amd64",
                        kernel="5.x",
                        group="billing-svc",
                    ),
                ]
                if group == "order-svc":
                    return [h for h in all_hosts if h.group == "order-svc"]
                if group == "billing-svc":
                    return [h for h in all_hosts if h.group == "billing-svc"]
                return all_hosts

            store.list_hosts = AsyncMock(side_effect=_list_hosts)
            v1 = VulnFinding(
                finding_id="f1",
                task_id="t",
                agent_id="a1",
                hostname="order-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
            )
            v2 = VulnFinding(
                finding_id="f2",
                task_id="t",
                agent_id="a2",
                hostname="order-2",
                category=ScanModule.SYS_VULN,
                name="y",
                severity="critical",
                detected_at="2026-07-01T00:00:00",
            )
            v3 = VulnFinding(
                finding_id="f3",
                task_id="t",
                agent_id="a3",
                hostname="billing-1",
                category=ScanModule.SYS_VULN,
                name="z",
                severity="low",
                detected_at="2026-07-01T00:00:00",
            )
            v4 = VulnFinding(
                finding_id="f4",
                task_id="t",
                agent_id="a9",
                hostname="misc-1",
                category=ScanModule.SYS_VULN,
                name="q",
                severity="medium",
                detected_at="2026-07-01T00:00:00",
            )
            store.list_vulns = AsyncMock(return_value=[v1, v2, v3, v4])
            mock_vs.return_value = store
            # Bust the in-process cache so our mock is actually used.
            import src.api.routers.vulnscan as _vmod

            _vmod._HOST_STATS_CACHE["ts"] = 0.0
            _vmod._HOST_STATS_CACHE["items"] = []
            resp = client.get("/api/v1/vulnscan/host-stats", headers=headers)
            # Regression guard (S-P1-3): the router must NOT construct a
            # fresh VulnscanStore() -- it must reuse the singleton.
            mock_cls.assert_not_called()
        assert resp.status_code == 200
        data = resp.json()
        items = {it["group"]: it for it in data["items"]}
        assert items["order-svc"]["total"] == 2
        assert items["order-svc"]["by_severity"]["high"] == 1
        assert items["order-svc"]["by_severity"]["critical"] == 1
        assert items["billing-svc"]["total"] == 1
        assert items["billing-svc"]["by_severity"]["low"] == 1
        # misc-1 is not in any group, so it must not show up in any bucket
        for grp in ("order-svc", "billing-svc"):
            for v in items[grp]["by_severity"].values():
                assert v < 3


class TestVulnDetailHostMeta:
    """2026-07-29 UX upgrade: GET /vulnscan/vulns/{id} now includes the
    host metadata (group / owner / env / ip / os) so the vuln detail
    drawer can show the asset context without an extra round-trip.

    Behaviour:
    - Preferred lookup is by agent_id.
    - If the agent has been decommissioned (get_host returns None), we
      fall back to a hostname match so the operator still sees context.
    - If neither lookup yields a host, the response shape is unchanged
      (no ``host`` key) for backwards compatibility.
    """

    def test_get_vuln_includes_host_meta_by_agent_id(self):
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = _auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            v = VulnFinding(
                finding_id="f-1",
                task_id="t",
                agent_id="agent-a",
                hostname="order-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
            )
            host = Host(
                agent_id="agent-a",
                hostname="order-1",
                ip="10.0.0.1",
                os="linux",
                arch="amd64",
                kernel="5.x",
                group="order-svc",
                owner="alice",
                env="prod",
            )
            store.get_vuln = AsyncMock(return_value=v)
            store.get_host = AsyncMock(return_value=host)
            store.list_hosts = AsyncMock(return_value=[])
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/vulns/f-1", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding_id"] == "f-1"
        assert body["host"]["agent_id"] == "agent-a"
        assert body["host"]["group"] == "order-svc"
        assert body["host"]["owner"] == "alice"
        assert body["host"]["env"] == "prod"
        # list_hosts must not be called when get_host succeeds
        store.list_hosts.assert_not_called()

    def test_get_vuln_falls_back_to_hostname(self):
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = _auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            v = VulnFinding(
                finding_id="f-1",
                task_id="t",
                agent_id="agent-a",
                hostname="order-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
            )
            host = Host(
                agent_id="agent-b",
                hostname="order-1",
                ip="10.0.0.1",
                os="linux",
                arch="amd64",
                kernel="5.x",
                group="order-svc",
            )
            store.get_vuln = AsyncMock(return_value=v)
            store.get_host = AsyncMock(return_value=None)
            store.list_hosts = AsyncMock(return_value=[host])
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/vulns/f-1", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["host"]["agent_id"] == "agent-b"
        store.list_hosts.assert_called_once()
        assert store.list_hosts.await_args.kwargs.get("hostname") == "order-1"

    def test_get_vuln_omits_host_when_lookup_fails(self):
        from src.agents.models import ScanModule, VulnFinding

        headers = _auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            v = VulnFinding(
                finding_id="f-1",
                task_id="t",
                agent_id="agent-a",
                hostname="order-1",
                category=ScanModule.SYS_VULN,
                name="x",
                severity="high",
                detected_at="2026-07-01T00:00:00",
            )
            store.get_vuln = AsyncMock(return_value=v)
            store.get_host = AsyncMock(return_value=None)
            store.list_hosts = AsyncMock(return_value=[])
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/vulns/f-1", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        # With response_model=_VulnDetailResponse the host field is
        # always present in the schema; when the lookup fails it is
        # serialised as null so the frontend can treat absence and
        # null the same way.
        assert body.get("host") is None
        # The vuln fields themselves are still in the response.
        assert body["finding_id"] == "f-1"

    def test_host_stats_uses_singleton_store(self):
        """V9 3.1: /host-stats must use the shared singleton and must
        NOT instantiate VulnscanStore() per request."""
        headers = _auth_headers("analyst")
        with (
            patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs,
            patch("src.agents.store.VulnscanStore") as mock_cls,
        ):
            store = _mock_store()
            store.list_groups = AsyncMock(return_value=[])
            store.list_hosts = AsyncMock(return_value=[])
            store.list_vulns = AsyncMock(return_value=[])
            mock_vs.return_value = store
            import src.api.routers.vulnscan as _vmod

            _vmod._HOST_STATS_CACHE["ts"] = 0.0
            _vmod._HOST_STATS_CACHE["items"] = []
            client.get("/api/v1/vulnscan/host-stats", headers=headers)
            # Singleton used, fresh constructor NOT called.
            mock_vs.assert_called()
            mock_cls.assert_not_called()

    def test_host_stats_calls_store_a_fixed_number_of_times(self):
        """V9 3.1: the endpoint makes O(1) store calls regardless of
        how many groups exist (was N+1, one list_hosts per group)."""
        headers = _auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.list_groups = AsyncMock(
                return_value=[
                    {
                        "name": f"g-{i}",
                        "member_count": 0,
                        "description": "",
                        "created_at": "",
                        "origin": "managed",
                    }
                    for i in range(20)
                ]
            )
            store.list_hosts = AsyncMock(return_value=[])
            store.list_vulns = AsyncMock(return_value=[])
            mock_vs.return_value = store
            import src.api.routers.vulnscan as _vmod

            _vmod._HOST_STATS_CACHE["ts"] = 0.0
            _vmod._HOST_STATS_CACHE["items"] = []
            client.get("/api/v1/vulnscan/host-stats", headers=headers)
            # 1 list_groups + 1 list_hosts + 1 list_vulns = 3 calls, regardless of 20 groups.
            assert store.list_groups.await_count == 1
            assert store.list_hosts.await_count == 1
            assert store.list_vulns.await_count == 1


    def test_target_groups_resolution_uses_cache(self):
        """V9 3.2: target_groups resolution must hit list_hosts at most
        once across burst task creates (30s in-process cache)."""
        import src.api.routers.vulnscan as _vmod
        # Reset cache so the test is independent.
        _vmod._HOST_STATS_CACHE.pop("host_to_group", None)
        _vmod._HOST_STATS_CACHE.pop("ts_target_groups", None)
        from src.agents.models import Host
        headers = _auth_headers("admin")
        with (
            patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs,
            patch("src.api.routers.vulnscan.get_audit_logger") as mock_audit,
        ):
            store = _mock_store()
            store.list_hosts = AsyncMock(return_value=[
                Host(agent_id="a1", hostname="host-a", ip="10.0.0.1", os="linux", arch="amd64", kernel="5.x", group="prod"),
            ])
            mock_vs.return_value = store
            mock_audit.return_value.log = AsyncMock()
            # First call: populates the cache.
            client.post(
                "/api/v1/vulnscan/tasks",
                json={"source": "manual", "targets": ["host-a"], "modules": ["sys_vuln"]},
                headers=headers,
            )
            first_count = store.list_hosts.await_count
            # Second call within TTL: should reuse the cache, NOT call list_hosts again.
            client.post(
                "/api/v1/vulnscan/tasks",
                json={"source": "manual", "targets": ["host-a"], "modules": ["sys_vuln"]},
                headers=headers,
            )
            second_count = store.list_hosts.await_count
            assert second_count == first_count, "second create must reuse the cache"
