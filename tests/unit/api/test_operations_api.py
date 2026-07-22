"""API tests for /api/v1/operations (events, approvals, metrics) and /api/v1/rules endpoints."""
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


# -- events -------------------------------------------------------------------

class TestEvents:
    def test_list_events_as_viewer(self):
        headers = _auth_headers("viewer")
        with patch("src.api.routers.operations.get_event_store") as mock_es:
            store = AsyncMock()
            store.list_events.return_value = []
            store.total_count.return_value = 0
            mock_es.return_value = store
            resp = client.get("/api/v1/events", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert "items" in data
            assert "total" in data

    def test_list_events_no_auth_401(self):
        resp = client.get("/api/v1/events")
        assert resp.status_code == 401

    def test_get_event_not_found(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.operations.get_event_store") as mock_es:
            store = AsyncMock()
            store.get_event.return_value = None
            mock_es.return_value = store
            resp = client.get("/api/v1/events/ev-99", headers=headers)
            assert resp.status_code == 404

    def test_get_event_trace_not_found(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.operations.get_event_store") as mock_es:
            store = AsyncMock()
            store.get_event.return_value = None
            mock_es.return_value = store
            resp = client.get("/api/v1/events/ev-99/trace", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["trace"] == []


# -- approvals ----------------------------------------------------------------

class TestApprovals:
    def test_list_approvals_as_admin(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.operations._list_pending_approvals", AsyncMock(return_value=[])):
            resp = client.get("/api/v1/approvals", headers=headers)
            assert resp.status_code == 200
            assert "items" in resp.json()

    def test_list_approvals_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.get("/api/v1/approvals", headers=headers)
        assert resp.status_code == 403

    def test_approve_event_as_admin(self):
        headers = _auth_headers("admin")
        with (
            patch("src.api.routers.operations.get_event_store") as mock_es,
            patch("src.api.routers.operations.resolve_approval_by_event_id", AsyncMock()),
            patch("src.api.routers.operations.get_audit_logger") as mock_audit,
        ):
            store = AsyncMock()
            store.get_event.return_value = AsyncMock()
            store.get_event.return_value.model_dump.return_value = {}
            store.add_approval = AsyncMock()
            store.update_event = AsyncMock()
            mock_es.return_value = store
            mock_audit.return_value.log = AsyncMock()
            resp = client.post("/api/v1/events/ev-1/approve", params={"action": "approved"}, headers=headers)
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

    def test_approve_event_not_found(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.operations.get_event_store") as mock_es:
            store = AsyncMock()
            store.get_event.return_value = None
            mock_es.return_value = store
            resp = client.post("/api/v1/events/ev-99/approve", headers=headers)
            assert resp.status_code == 404

    def test_approve_event_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post("/api/v1/events/ev-1/approve", headers=headers)
        assert resp.status_code == 403


# -- metrics ------------------------------------------------------------------

class TestMetrics:
    def test_get_metrics_as_admin(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.operations.get_event_store") as mock_es:
            store = AsyncMock()
            store.metrics.return_value = {
                "total_events": 10, "by_verdict": {}, "by_priority": {},
                "pending_approvals": 0, "avg_duration_ms": 100,
            }
            mock_es.return_value = store
            resp = client.get("/api/v1/metrics", headers=headers)
            assert resp.status_code == 200
            assert "total_events" in resp.json()

    def test_get_metrics_no_auth_401(self):
        resp = client.get("/api/v1/metrics")
        assert resp.status_code == 401

    def test_timeline_as_admin(self):
        headers = _auth_headers("admin")
        with patch("src.api.routers.operations.get_event_store") as mock_es:
            store = AsyncMock()
            store.list_events.return_value = []
            mock_es.return_value = store
            resp = client.get("/api/v1/metrics/timeline", headers=headers)
            assert resp.status_code == 200
            assert "timeline" in resp.json()


# -- rules --------------------------------------------------------------------

class TestRules:
    def test_get_version(self):
        headers = _auth_headers("viewer")
        with patch("src.api.routers.rules.current_rule_version", AsyncMock(return_value="v1.0")):
            resp = client.get("/api/v1/rules/version", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["version"] == "v1.0"

    def test_get_version_no_auth_401(self):
        resp = client.get("/api/v1/rules/version")
        assert resp.status_code == 401

    def test_sync_rules_as_admin(self):
        headers = _auth_headers("admin")
        from unittest.mock import MagicMock
        mock_pack = MagicMock()
        mock_pack.rules = []
        with (
            patch("src.api.routers.rules.sync_rules", AsyncMock(return_value="v2")),
            patch("src.api.routers.rules.get_rule_pack", AsyncMock(return_value=mock_pack)),
            patch("src.api.routers.rules.get_audit_logger") as mock_audit,
        ):
            mock_audit.return_value.log = AsyncMock()
            resp = client.post("/api/v1/rules/sync", json={"source": "nvd"}, headers=headers)
            assert resp.status_code == 200
            assert resp.json()["version"] == "v2"

    def test_sync_rules_as_viewer_403(self):
        headers = _auth_headers("viewer")
        resp = client.post("/api/v1/rules/sync", json={}, headers=headers)
        assert resp.status_code == 403

    def test_download_pack_not_found(self):
        # P1-API-02 (2026-07-20): the endpoint now requires admin/analyst
        # auth, so authenticate before exercising the 404 branch.
        headers = _auth_headers("admin")
        with patch("src.api.routers.rules.get_rule_pack", AsyncMock(return_value=None)):
            resp = client.get("/api/v1/rules/pack/v99", headers=headers)
            assert resp.status_code == 404

    def test_download_pack_unauthenticated_401(self):
        # P1-API-02 (2026-07-20): pack download requires admin/analyst.
        resp = client.get("/api/v1/rules/pack/v1")
        assert resp.status_code == 401

    def test_download_pack_as_viewer_403(self):
        # P1-API-02 (2026-07-20): pack download rejects viewer.
        headers = _auth_headers("viewer")
        resp = client.get("/api/v1/rules/pack/v1", headers=headers)
        assert resp.status_code == 403
