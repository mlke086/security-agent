"""End-to-end verification for the Phase 4 response-action pipeline.

Exercises:
  - POST /api/v1/agents/{id}/actions/{name}  (RBAC + dispatch)
  - GET  /api/v1/agents/actions/{id}        (status polling)
  - unknown action -> 400
  - bad params     -> 400
  - viewer denied  -> 403
  - analyst denied -> 403
  - admin allowed  -> 200 (action_id returned; no agent connected so the
                       gateway falls through to Redis pub/sub with 0
                       subscribers, which is fine -- we only check the
                       response shape)
"""

from __future__ import annotations

import os

os.environ.setdefault("NACOS_SERVER", "")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("ES_HOSTS", "http://192.168.80.101:9200")
os.environ.setdefault("REDIS_HOST", "192.168.80.101")
os.environ.setdefault("LOG_LEVEL", "WARNING")

import pytest

# ---------- fixtures ----------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from src.api.main import app

    with TestClient(app) as c:
        yield c


def _login(c, username: str, password: str) -> dict:
    r = c.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"{username} login failed: {r.text}"
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="module")
def admin_headers(client):
    return _login(client, "admin", "admin123")


@pytest.fixture(scope="module")
def responder_headers(client):
    return _login(client, "responder", "responder123")


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer123")


@pytest.fixture(scope="module")
def analyst_headers(client):
    return _login(client, "analyst", "analyst123")


# ---------- tests --------------------------------------------------------------


def test_01_unknown_action_400(client, admin_headers):
    r = client.post(
        "/api/v1/agents/agent-x/actions/format_disk",
        json={"params": {"target": "/dev/sda"}},
        headers=admin_headers,
    )
    assert r.status_code == 400, r.text
    assert "unsupported action" in r.text


def test_02_bad_params_400(client, admin_headers):
    # kill_process requires pid > 0
    r = client.post(
        "/api/v1/agents/agent-x/actions/kill_process",
        json={"params": {"pid": 0}},
        headers=admin_headers,
    )
    assert r.status_code == 400, r.text
    assert "pid" in r.text.lower() or "greater_than_equal" in r.text


def test_03_viewer_denied(client, viewer_headers):
    r = client.post(
        "/api/v1/agents/agent-x/actions/kill_process",
        json={"params": {"pid": 1234}},
        headers=viewer_headers,
    )
    assert r.status_code in (401, 403), r.text


def test_04_analyst_denied(client, analyst_headers):
    """Analyst is read-only on the alerts side; response actions require responder/admin."""
    r = client.post(
        "/api/v1/agents/agent-x/actions/kill_process",
        json={"params": {"pid": 1234}},
        headers=analyst_headers,
    )
    assert r.status_code in (401, 403), r.text


def test_05_responder_allowed(client, responder_headers):
    r = client.post(
        "/api/v1/agents/agent-x/actions/kill_process",
        json={"params": {"pid": 1234, "signal": "SIGTERM"}, "reason": "e2e test"},
        headers=responder_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"] == "kill_process"
    assert body["agent_id"] == "agent-x"
    assert body["status"] == "dispatched"
    assert body["action_id"]


def test_06_admin_quarantine_allowed(client, admin_headers):
    r = client.post(
        "/api/v1/agents/agent-x/actions/quarantine_file",
        json={"params": {"path": "/var/www/html/shell.php"}, "reason": "honeypot"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["action"] == "quarantine_file"


def test_07_admin_kill_process_allowed(client, admin_headers):
    r = client.post(
        "/api/v1/agents/agent-x/actions/kill_process",
        json={"params": {"pid": 9999, "signal": "SIGKILL"}},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    action_id = r.json()["action_id"]
    # Status slot should be findable immediately after dispatch.
    s = client.get(f"/api/v1/agents/actions/{action_id}", headers=admin_headers)
    assert s.status_code == 200, s.text
    body = s.json()
    assert body["action_id"] == action_id
    assert body["status"] in ("dispatched", "succeeded", "failed", "unknown")


def test_08_quarantine_relative_path_rejected(client, admin_headers):
    r = client.post(
        "/api/v1/agents/agent-x/actions/quarantine_file",
        json={"params": {"path": "relative/path.txt"}},
        headers=admin_headers,
    )
    assert r.status_code == 400, r.text


def test_09_action_status_unknown_for_nonexistent_id(client, admin_headers):
    s = client.get("/api/v1/agents/actions/does-not-exist-zzz", headers=admin_headers)
    assert s.status_code == 200
    assert s.json()["status"] == "unknown"


def test_10_viewer_can_read_status(client, admin_headers, viewer_headers):
    """Viewer is allowed to poll action status (read-only)."""
    r = client.post(
        "/api/v1/agents/agent-x/actions/kill_process",
        json={"params": {"pid": 4321}},
        headers=admin_headers,
    )
    assert r.status_code == 200
    action_id = r.json()["action_id"]
    s = client.get(f"/api/v1/agents/actions/{action_id}", headers=viewer_headers)
    assert s.status_code == 200, s.text
