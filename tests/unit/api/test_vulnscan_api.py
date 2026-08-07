"""API tests for /api/v1/vulnscan endpoints.

Covers: tasks/parse, tasks CRUD, task cancel, stream, results, reports, vulns CRUD.
"""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)



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
    def test_parse_as_analyst(self, auth_headers):
        headers = auth_headers("analyst")
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

    def test_parse_as_viewer_403(self, auth_headers):
        headers = auth_headers("viewer")
        resp = client.post(
            "/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan"}, headers=headers
        )
        assert resp.status_code == 403


# -- tasks --------------------------------------------------------------------


class TestTasks:
    def test_create_task_as_admin(self, auth_headers):
        headers = auth_headers("admin")
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

    def test_list_tasks(self, auth_headers):
        headers = auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.count_tasks = AsyncMock(return_value=0)
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/tasks", headers=headers)
            assert resp.status_code == 200
            body = resp.json()
            assert "items" in body
            # V12 5.8: server-side pagination + true total (the old endpoint
            # silently truncated at the store default of 50 tasks).
            assert "total" in body
            assert body["page"] == 1
            assert body["page_size"] == 20

    def test_list_tasks_pagination_passed_to_store(self, auth_headers):
        headers = auth_headers("analyst")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.count_tasks = AsyncMock(return_value=0)
            mock_vs.return_value = store
            resp = client.get(
                "/api/v1/vulnscan/tasks?page=3&page_size=50", headers=headers
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["page"] == 3
            assert body["page_size"] == 50
            # store.list_tasks must have received the page bounds
            calls = store.list_tasks.call_args_list
            assert calls, "list_tasks not called"
            kw = calls[-1].kwargs
            assert kw.get("limit") == 50
            assert kw.get("offset") == 100

    def test_get_task_not_found(self, auth_headers):
        headers = auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.get_task.return_value = None
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/tasks/task-99", headers=headers)
            assert resp.status_code == 404

    def test_cancel_task_not_found(self, auth_headers):
        headers = auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.get_task.return_value = None
            mock_vs.return_value = store
            resp = client.post("/api/v1/vulnscan/tasks/task-99/cancel", headers=headers)
            assert resp.status_code == 404

    def test_cancel_task_as_viewer_403(self, auth_headers):
        headers = auth_headers("viewer")
        resp = client.post("/api/v1/vulnscan/tasks/task-1/cancel", headers=headers)
        assert resp.status_code == 403

    def test_batch_delete_admin(self, auth_headers):
        headers = auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            # t1/t2 exist, t3 does not -> deleted=2, not_found=["t3"].
            store.get_task.side_effect = lambda tid: {"task_id": tid} if tid in ("t1", "t2") else None
            mock_vs.return_value = store
            resp = client.post(
                "/api/v1/vulnscan/tasks/batch-delete",
                json={"task_ids": ["t1", "t2", "t3"]},
                headers=headers,
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"] == 2
        assert body["not_found"] == ["t3"]
        assert body["failed"] == []
        # delete_task called once per existing task.
        assert store.delete_task.await_count == 2

    def test_batch_delete_viewer_403(self, auth_headers):
        headers = auth_headers("viewer")
        resp = client.post(
            "/api/v1/vulnscan/tasks/batch-delete",
            json={"task_ids": ["t1"]},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_batch_delete_empty_422(self, auth_headers):
        headers = auth_headers("admin")
        resp = client.post(
            "/api/v1/vulnscan/tasks/batch-delete",
            json={"task_ids": []},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_batch_delete_over_200_422(self, auth_headers):
        """V13 P2-4: unbounded batches stall past the gateway timeout; cap."""
        headers = auth_headers("admin")
        resp = client.post(
            "/api/v1/vulnscan/tasks/batch-delete",
            json={"task_ids": [f"t{i}" for i in range(201)]},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_create_task_rejects_overlong_targets(self, auth_headers):
        """V13 P2-5: target list is bounded before it reaches the agents."""
        headers = auth_headers("admin")
        resp = client.post(
            "/api/v1/vulnscan/tasks",
            json={"targets": [f"host-{i}" for i in range(501)]},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_create_task_rejects_bad_ports(self, auth_headers):
        """V13 P2-5: nuclei_ports outside 1-65535 is rejected, not passed
        through to the agent's command line."""
        headers = auth_headers("admin")
        resp = client.post(
            "/api/v1/vulnscan/tasks",
            json={"targets": ["host-a"], "engine": "nuclei", "nuclei_ports": [0, 70000, "22"]},
            headers=headers,
        )
        assert resp.status_code == 422

    def test_create_task_accepts_valid_ports(self, auth_headers):
        headers = auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            mock_vs.return_value = _mock_store()
            resp = client.post(
                "/api/v1/vulnscan/tasks",
                json={
                    "targets": ["host-a"],
                    "engine": "nuclei",
                    "nuclei_ports": [22, 443, 8080],
                },
                headers=headers,
            )
        assert resp.status_code == 200


# -- stream -------------------------------------------------------------------


class TestStream:
    def test_stream_bad_token_401(self):
        resp = client.get("/api/v1/vulnscan/tasks/task-1/stream", params={"token": "bad"})
        assert resp.status_code == 401


# -- results ------------------------------------------------------------------


class TestResults:
    def test_list_results(self, auth_headers):
        headers = auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/results", headers=headers)
            assert resp.status_code == 200
            assert "items" in resp.json()

    def test_filter_by_severity(self, auth_headers):
        headers = auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.get(
                "/api/v1/vulnscan/results", params={"severity": "high"}, headers=headers
            )
            assert resp.status_code == 200


# -- reports ------------------------------------------------------------------


class TestReports:
    def test_get_report_not_found(self, auth_headers):
        headers = auth_headers("viewer")
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
    def test_get_vuln_not_found(self, auth_headers):
        headers = auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            store.list_vulns.return_value = []
            mock_vs.return_value = store
            resp = client.get("/api/v1/vulnscan/vulns/f-99", headers=headers)
            assert resp.status_code == 404

    def test_patch_vuln_invalid_status_422(self, auth_headers):
        headers = auth_headers("admin")
        with patch("src.api.routers.vulnscan.get_vulnscan_store") as mock_vs:
            store = _mock_store()
            mock_vs.return_value = store
            resp = client.patch(
                "/api/v1/vulnscan/vulns/f-1", json={"status": "invalid"}, headers=headers
            )
            assert resp.status_code == 422

    def test_patch_vuln_as_viewer_403(self, auth_headers):
        headers = auth_headers("viewer")
        resp = client.patch("/api/v1/vulnscan/vulns/f-1", json={"status": "open"}, headers=headers)
        assert resp.status_code == 403


# -- 2026-07-29 UX upgrade: extended filters + fix-time PATCH ---------------


class TestResultsExtendedFilters:
    """New query params on /api/v1/vulnscan/results (cve, cve_keyword,
    hostname_keyword, name_keyword, group, ai_processed, date_from,
    date_to) all reach the store layer with the right kwargs."""

    def test_extended_filters_forwarded_to_store(self, auth_headers):
        headers = auth_headers("admin")
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

    def test_group_filter_pushes_hostnames_server_side(self, auth_headers):
        """S-P1-4: when the operator passes group=order-svc, the router
        looks up the group's hosts and pushes the hostname set into the ES
        query as a server-side ``terms`` filter (hostnames=...), instead of
        fetching a capped 200-row page and filtering in memory (which
        silently dropped group members beyond the cap)."""
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = auth_headers("analyst")
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

    def test_patch_to_fixed_records_fix_time(self, auth_headers):
        from src.agents.models import ScanModule, VulnFinding

        headers = auth_headers("admin")
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

    def test_patch_to_fixed_preserves_first_fixed_at(self, auth_headers):
        """When the vuln was already fixed once before, re-fixing must
        update last_fixed_at but NOT overwrite first_fixed_at (the router
        only forwards first_fixed_at when it is currently empty)."""
        from src.agents.models import ScanModule, VulnFinding

        headers = auth_headers("admin")
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

    def test_host_stats_returns_per_group_breakdown(self, auth_headers):
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = auth_headers("analyst")
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

    def test_get_vuln_includes_host_meta_by_agent_id(self, auth_headers):
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = auth_headers("analyst")
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

    def test_get_vuln_falls_back_to_hostname(self, auth_headers):
        from src.agents.models import Host, ScanModule, VulnFinding

        headers = auth_headers("analyst")
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

    def test_get_vuln_omits_host_when_lookup_fails(self, auth_headers):
        from src.agents.models import ScanModule, VulnFinding

        headers = auth_headers("viewer")
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

    def test_host_stats_uses_singleton_store(self, auth_headers):
        """V9 3.1: /host-stats must use the shared singleton and must
        NOT instantiate VulnscanStore() per request."""
        headers = auth_headers("analyst")
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

    def test_host_stats_calls_store_a_fixed_number_of_times(self, auth_headers):
        """V9 3.1: the endpoint makes O(1) store calls regardless of
        how many groups exist (was N+1, one list_hosts per group)."""
        headers = auth_headers("analyst")
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


    def test_target_groups_resolution_uses_cache(self, auth_headers):
        """V9 3.2: target_groups resolution must hit list_hosts at most
        once across burst task creates (30s in-process cache)."""
        import src.api.routers.vulnscan as _vmod
        # Reset cache so the test is independent.
        _vmod._HOST_STATS_CACHE.pop("host_to_group", None)
        _vmod._HOST_STATS_CACHE.pop("ts_target_groups", None)
        from src.agents.models import Host
        headers = auth_headers("admin")
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


class TestTaskFindingsEndpoint:
    """V12 5.7 (问题1 修复): /tasks/{id}/findings reads the RESULTS index so a
    task whose vulns were merged into an older record still sees its own
    scan findings on the monitor page."""

    def test_task_findings_returns_results_findings(self, auth_headers):
        from unittest.mock import AsyncMock, patch

        from src.agents.models import ScanModule, ScanResult, VulnFinding

        store = AsyncMock()
        f1 = VulnFinding(
            finding_id="f-1", task_id="t-1", agent_id="a-1", hostname="h-1",
            category=ScanModule.SYS_VULN, name="CVE-2026-0001", cve="CVE-2026-0001",
            severity="high",
        )
        f2 = VulnFinding(
            finding_id="f-2", task_id="t-1", agent_id="a-1", hostname="h-1",
            category=ScanModule.SYS_VULN, name="CVE-2026-0002", cve="CVE-2026-0002",
            severity="medium",
        )
        r1 = ScanResult(task_id="t-1", agent_id="a-1", hostname="h-1",
                        findings=[f1.model_dump()], batch=1, is_final=False)
        r2 = ScanResult(task_id="t-1", agent_id="a-1", hostname="h-1",
                        findings=[f2.model_dump()], batch=2, is_final=True)
        store.list_results = AsyncMock(return_value=[r1, r2])

        headers = auth_headers("viewer")
        with patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store):
            resp = client.get("/api/v1/vulnscan/tasks/t-1/findings", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 2
        assert [i["finding_id"] for i in body["items"]] == ["f-1", "f-2"]
        store.list_results.assert_awaited_once_with("t-1")


# -- 需求③ (2026-08-06): /vulnscan/host-vuln-summary 主机维度聚合 ------------


class TestHostVulnSummary:
    """主机清单顶层视图端点。

    与 /host-stats（组维度）不同，本端点按 agent_id 分桶，漏洞情况按
    原始 severity 统计。store.host_vuln_summary_buckets 返回原始桶，
    路由负责 PG JOIN（list_hosts）与排序分页。

    鉴权说明：本环境无可用 PG（auth_headers fixture 的 /auth/me 会
    连 PG），这里用 dependency_overrides 直接注入用户对象，使测试
    不依赖外部服务。
    """

    def _auth(self, role):
        from src.api.auth.jwt import UserInDB
        from src.api.auth.routes import get_current_user

        user = UserInDB(username=f"t-{role}", hashed_password="x", role=role, token_version=0)
        app.dependency_overrides[get_current_user] = lambda: user
        return {"Authorization": "Bearer t"}

    def _cleanup(self):
        app.dependency_overrides.clear()

    def _mock_store_with_buckets(self, buckets, hosts):
        store = _mock_store()
        store.list_hosts = AsyncMock(return_value=hosts)
        store.host_vuln_summary_buckets = AsyncMock(return_value=buckets)
        return store

    def _host(self, agent_id, hostname, ip, group):
        from src.agents.models import Host

        return Host(
            agent_id=agent_id,
            hostname=hostname,
            ip=ip,
            os="Ubuntu 22.04",
            arch="amd64",
            kernel="5.15",
            group=group,
        )

    def test_host_vuln_summary_aggregation(self):
        from src.api.routers.vulnscan import _HOST_VULN_SUMMARY_CACHE

        _HOST_VULN_SUMMARY_CACHE.clear()
        headers = self._auth("viewer")
        buckets = [
            {
                "agent_id": "a1",
                "total": 9,
                "severity_counts": {"critical": 1, "high": 5, "medium": 3, "low": 0},
                "status_counts": {"open": 7, "fixed": 2},
                "last_scan_at": "2026-08-06T09:00:00+00:00",
            },
            {
                "agent_id": "a2",
                "total": 2,
                "severity_counts": {"high": 2},
                "status_counts": {"open": 2},
                "last_scan_at": "2026-08-06T08:00:00+00:00",
            },
        ]
        hosts = [self._host("a1", "web-01", "10.0.0.5", "生产"), self._host("a2", "db-01", "10.0.0.6", "生产")]
        store = self._mock_store_with_buckets(buckets, hosts)
        try:
            with patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store):
                resp = client.get("/api/v1/vulnscan/host-vuln-summary", headers=headers)
        finally:
            self._cleanup()
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cached"] is False
        assert body["total"] == 2
        # 按漏洞数降序：a1(9) 在前
        assert [i["agent_id"] for i in body["items"]] == ["a1", "a2"]
        first = body["items"][0]
        assert first["hostname"] == "web-01"
        assert first["ip"] == "10.0.0.5"
        assert first["os"] == "Ubuntu 22.04"
        assert first["group"] == "生产"
        assert first["severity_counts"] == {"critical": 1, "high": 5, "medium": 3, "low": 0}
        assert first["total"] == 9
        assert first["open_count"] == 7
        assert first["fixed_count"] == 2
        assert first["last_scan_at"] == "2026-08-06T09:00:00+00:00"
        # PG JOIN：agent_id 批量查 hosts
        store.list_hosts.assert_awaited_once()

    def test_host_vuln_summary_uses_raw_severity(self):
        """severity_counts 透传原始 severity 聚合结果（非 ai_severity）。"""
        from src.api.routers.vulnscan import _HOST_VULN_SUMMARY_CACHE

        _HOST_VULN_SUMMARY_CACHE.clear()
        headers = self._auth("viewer")
        buckets = [
            {
                "agent_id": "a1",
                "total": 1,
                "severity_counts": {"high": 1},  # 原始 severity
                "status_counts": {"open": 1},
                "last_scan_at": "",
            },
        ]
        store = self._mock_store_with_buckets(buckets, [self._host("a1", "web-01", "10.0.0.5", "生产")])
        try:
            with patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store):
                resp = client.get("/api/v1/vulnscan/host-vuln-summary", headers=headers)
        finally:
            self._cleanup()
        assert resp.status_code == 200, resp.text
        item = resp.json()["items"][0]
        assert item["severity_counts"] == {"high": 1}
        # 响应契约：主机清单不含 ai_severity 维度
        assert "ai_severity" not in item

    def test_host_vuln_summary_passes_filters_down(self):
        """group/severity/status/hostname_keyword 筛选下推 store。"""
        from src.api.routers.vulnscan import _HOST_VULN_SUMMARY_CACHE

        _HOST_VULN_SUMMARY_CACHE.clear()
        headers = self._auth("analyst")
        hosts = [self._host("a1", "web-01", "10.0.0.5", "生产"), self._host("a2", "db-01", "10.0.0.6", "测试")]
        store = self._mock_store_with_buckets([], hosts)

        async def _list_hosts_group_filtered(group=None, **_):
            # 模拟 PG：group 筛选下只返回该组主机
            return [h for h in hosts if group is None or h.group == group]

        store.list_hosts = AsyncMock(side_effect=_list_hosts_group_filtered)
        try:
            with patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store):
                resp = client.get(
                    "/api/v1/vulnscan/host-vuln-summary",
                    params={"group": "生产", "severity": "high", "status": "open", "hostname_keyword": "web"},
                    headers=headers,
                )
        finally:
            self._cleanup()
        assert resp.status_code == 200, resp.text
        # group 筛选经 PG 变为 agent_id terms：只传该组主机
        store.list_hosts.assert_awaited_once()
        call_kwargs = store.list_hosts.await_args.kwargs
        assert call_kwargs.get("group") == "生产"
        store.host_vuln_summary_buckets.assert_awaited_once_with(
            group_agent_ids=["a1"],
            hostname_keyword="web",
            severity="high",
            status="open",
            host_limit=500,
        )

    def test_host_vuln_summary_cache(self):
        """30s TTL 内同参数二次请求命中缓存（store 不再被调）。"""
        from src.api.routers.vulnscan import _HOST_VULN_SUMMARY_CACHE

        _HOST_VULN_SUMMARY_CACHE.clear()
        headers = self._auth("viewer")
        buckets = [
            {
                "agent_id": "a1",
                "total": 1,
                "severity_counts": {"high": 1},
                "status_counts": {"open": 1},
                "last_scan_at": "2026-08-06T09:00:00+00:00",
            },
        ]
        store = self._mock_store_with_buckets(buckets, [self._host("a1", "web-01", "10.0.0.5", "生产")])
        try:
            with patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store):
                r1 = client.get("/api/v1/vulnscan/host-vuln-summary", headers=headers)
                r2 = client.get("/api/v1/vulnscan/host-vuln-summary", headers=headers)
        finally:
            self._cleanup()
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.json()["cached"] is False
        assert r2.json()["cached"] is True
        assert r2.json()["items"] == r1.json()["items"]
        store.host_vuln_summary_buckets.assert_awaited_once()
        _HOST_VULN_SUMMARY_CACHE.clear()


class TestVulnFilterAgentId:
    """需求③ 钻取：VulnFilter.agent_id 在 ES 查询中生成 term 过滤。"""

    def test_vulnfilter_has_agent_id(self):
        from src.agents.models import VulnFilter

        assert VulnFilter(agent_id="a1").agent_id == "a1"

    def test_vulns_query_agent_id_term(self):
        from src.agents.models import VulnFilter
        from src.agents.store import VulnscanStore

        query = VulnscanStore._vulns_query(VulnFilter(agent_id="a1"))
        must = query["bool"]["must"]
        assert {"term": {"agent_id": "a1"}} in must

    def test_vulns_query_agent_id_coexists_with_agent_ids(self):
        from src.agents.models import VulnFilter
        from src.agents.store import VulnscanStore

        query = VulnscanStore._vulns_query(VulnFilter(agent_id="a1", agent_ids=["a2", "a3"]))
        must = query["bool"]["must"]
        assert {"term": {"agent_id": "a1"}} in must
        assert {"terms": {"agent_id": ["a2", "a3"]}} in must
