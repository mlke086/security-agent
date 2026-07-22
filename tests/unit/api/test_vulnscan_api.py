"""API tests for /api/v1/vulnscan endpoints.

Covers: tasks/parse, tasks CRUD, task cancel, stream, results, reports, vulns CRUD.
"""
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


def _login(role="admin"):
    passwords = {"admin": "admin123", "analyst": "analyst123", "viewer": "viewer123", "responder": "responder123"}
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
            resp = client.post("/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan h1"}, headers=headers)
            assert resp.status_code == 200

    def test_parse_no_auth_401(self):
        resp = client.post("/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan"})
        assert resp.status_code == 401

    def test_parse_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post("/api/v1/vulnscan/tasks/parse", json={"intent_text": "scan"}, headers=headers)
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
            resp = client.post("/api/v1/vulnscan/tasks", json={
                "source": "manual", "targets": ["host-a"], "modules": ["sys_vuln"]
            }, headers=headers)
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
            resp = client.get("/api/v1/vulnscan/results", params={"severity": "high"}, headers=headers)
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
            resp = client.patch("/api/v1/vulnscan/vulns/f-1", json={"status": "invalid"}, headers=headers)
            assert resp.status_code == 422

    def test_patch_vuln_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.patch("/api/v1/vulnscan/vulns/f-1", json={"status": "open"}, headers=headers)
        assert resp.status_code == 403
