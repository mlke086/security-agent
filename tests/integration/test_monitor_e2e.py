"""End-to-end verification for the Phase 5 monitor pipeline.

Exercises:
  - GET /api/v1/agents/{id}/monitor        (returns most-recent snapshots)
  - empty / unknown agent -> empty list (not an error)
  - RBAC: viewer/analyst/admin all allowed (read-only)
  - mock-stored event shows up in the response (no need for a real agent)

The WS path (agent -> gateway -> ES) is exercised separately in a future
PR; for the MVP we monkey-patch the MonitorStore so the endpoint test
stays offline-safe on dev boxes without an ES sidecar.
"""
from __future__ import annotations

import os
from typing import Any

# env must be set before any src.* import
os.environ.setdefault("NACOS_SERVER", "")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("ES_HOSTS", "http://192.168.80.101:9200")
os.environ.setdefault("REDIS_HOST", "192.168.80.101")
os.environ.setdefault("LOG_LEVEL", "WARNING")

import pytest


# ---------- stub MonitorStore (offline-safe) -------------------------------

class _StubMonitorStore:
    """Replaces MonitorStore so the endpoint test does not need ES."""

    def __init__(self) -> None:
        self.events: dict[str, list[dict[str, Any]]] = {}

    async def list_events(self, agent_id: str, limit: int = 50) -> list[dict[str, Any]]:
        return list(self.events.get(agent_id, []))[:limit]


@pytest.fixture(scope="module")
def stub_store():
    return _StubMonitorStore()


@pytest.fixture(scope="module")
def client(stub_store, monkeypatch_session):
    from fastapi.testclient import TestClient
    from src.api.main import app

    # Patch the monitor_store singleton BEFORE TestClient sends any
    # request so /monitor reads from the stub.
    from src.agents import monitor_store as _ms_mod
    _ms_mod._store = stub_store
    try:
        with TestClient(app) as c:
            yield c
    finally:
        _ms_mod._store = None


# session-scoped monkeypatch placeholder; we don't actually need it
# here but the fixture keeps client() composable with the other e2e
# suites that do.
@pytest.fixture(scope="module")
def monkeypatch_session():
    return None


def _login(c, username: str, password: str) -> dict:
    r = c.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"{username} login failed: {r.text}"
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture(scope="module")
def admin_headers(client):
    return _login(client, "admin", "admin123")


@pytest.fixture(scope="module")
def analyst_headers(client):
    return _login(client, "analyst", "analyst123")


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer123")


# ---------- tests -----------------------------------------------------------

def test_01_endpoint_registered(client, admin_headers):
    r = client.get("/api/v1/agents/agent-x/monitor", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agent_id"] == "agent-x"
    assert body["items"] == []
    assert body["count"] == 0
    assert body["limit"] == 20


def test_02_returns_seeded_events(client, admin_headers, stub_store):
    stub_store.events["agent-y"] = [
        {
            "agent_id": "agent-y",
            "hostname": "web-01",
            "collected_at": "2026-07-28T10:00:00Z",
            "received_at": "2026-07-28T10:00:01Z",
            "interval_sec": 30,
            "total_count": 142,
            "truncated": False,
            "process_count": 142,
        },
        {
            "agent_id": "agent-y",
            "hostname": "web-01",
            "collected_at": "2026-07-28T10:00:30Z",
            "received_at": "2026-07-28T10:00:31Z",
            "interval_sec": 30,
            "total_count": 145,
            "truncated": False,
            "process_count": 145,
        },
    ]
    r = client.get("/api/v1/agents/agent-y/monitor", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert body["items"][0]["total_count"] == 142
    assert body["items"][0]["hostname"] == "web-01"


def test_03_limit_caps_response(client, admin_headers, stub_store):
    stub_store.events["agent-z"] = [
        {"agent_id": "agent-z", "total_count": i, "process_count": i,
         "collected_at": f"2026-07-28T10:00:{i:02d}Z", "received_at": f"2026-07-28T10:00:{i:02d}Z",
         "interval_sec": 30, "truncated": False, "hostname": "h"}
        for i in range(50)
    ]
    r = client.get("/api/v1/agents/agent-z/monitor?limit=5", headers=admin_headers)
    body = r.json()
    assert body["count"] == 5
    assert body["limit"] == 5


def test_04_limit_bounds(client, admin_headers):
    # limit=0 should be rejected by Query(ge=1)
    r = client.get("/api/v1/agents/agent-x/monitor?limit=0", headers=admin_headers)
    assert r.status_code == 422
    # limit=5000 over the cap
    r = client.get("/api/v1/agents/agent-x/monitor?limit=5000", headers=admin_headers)
    assert r.status_code == 422


def test_05_analyst_can_read(client, analyst_headers, stub_store):
    stub_store.events["agent-ax"] = [
        {"agent_id": "agent-ax", "total_count": 1, "process_count": 1,
         "collected_at": "2026-07-28T10:00:00Z", "received_at": "2026-07-28T10:00:01Z",
         "interval_sec": 30, "truncated": False, "hostname": "h"}
    ]
    r = client.get("/api/v1/agents/agent-ax/monitor", headers=analyst_headers)
    assert r.status_code == 200


def test_06_viewer_can_read(client, viewer_headers, stub_store):
    stub_store.events["agent-vx"] = [
        {"agent_id": "agent-vx", "total_count": 1, "process_count": 1,
         "collected_at": "2026-07-28T10:00:00Z", "received_at": "2026-07-28T10:00:01Z",
         "interval_sec": 30, "truncated": False, "hostname": "h"}
    ]
    r = client.get("/api/v1/agents/agent-vx/monitor", headers=viewer_headers)
    assert r.status_code == 200


def test_07_unauthenticated_rejected(client):
    r = client.get("/api/v1/agents/agent-x/monitor")
    assert r.status_code in (401, 403)


def test_08_unknown_agent_returns_empty(client, admin_headers):
    r = client.get("/api/v1/agents/never-seen/monitor", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["count"] == 0
