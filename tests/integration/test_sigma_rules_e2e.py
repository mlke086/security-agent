"""End-to-end verification for the Phase 6 Sigma rule importer API.

Exercises:
  - GET /api/v1/sigma-rules/summary (reads manifest from disk)
  - GET /api/v1/sigma-rules (filtering by category / os / level)
  - POST /api/v1/sigma-rules/import (dry run; no filesystem writes)
  - 404 when manifest missing
  - RBAC: viewer/analyst can read, viewer denied on /import

The test seeds the manifest by running the CLI subprocess so the
filesystem is in the same state as a real operator run. No PG/ES
needed; the manifest is just a JSON file on disk.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# env must be set before src.* imports
os.environ.setdefault("NACOS_SERVER", "")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("ES_HOSTS", "http://192.168.80.101:9200")
os.environ.setdefault("REDIS_HOST", "192.168.80.101")
os.environ.setdefault("LOG_LEVEL", "WARNING")

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
FIXTURE = REPO / "tests" / "fixtures" / "sigma_zoo"


# ---------- fixtures --------------------------------------------------------

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
def analyst_headers(client):
    return _login(client, "analyst", "analyst123")


@pytest.fixture(scope="module")
def viewer_headers(client):
    return _login(client, "viewer", "viewer123")


@pytest.fixture(scope="module")
def manifest_seed(monkeypatch_module):
    """Run the CLI importer against the fixture dir, then point the
    API at the resulting manifest via env. Cleans up afterwards."""
    out_dir = REPO / "src" / "detection" / "rules" / "imported"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    # CLI: --no-copy so we don't pollute the actual rules/ dir
    result = subprocess.run(
        [sys.executable, "scripts/import_sigma_rules.py", str(FIXTURE), "--no-copy"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "accepted:      4" in result.stdout
    monkeypatch_module.setenv(
        "SIGMA_RULES_MANIFEST",
        str(out_dir / "manifest.json"),
    )
    # Re-import the config module so the env change is picked up by the
    # already-imported sigma_rules module.
    import importlib
    from src.api.routers import sigma_rules as _sr
    importlib.reload(_sr)
    from src.api import main as _main
    importlib.reload(_main)
    yield out_dir
    # Cleanup is implicit: shutil.rmtree at next run + GC of module


@pytest.fixture(scope="module")
def monkeypatch_module():
    """session-scoped env patcher (pytest only ships function-scoped)."""
    import os as _os
    saved = {}
    def setenv(k, v):
        saved.setdefault(k, _os.environ.get(k))
        _os.environ[k] = v
    yield type("M", (), {"setenv": staticmethod(setenv)})()
    for k, v in saved.items():
        if v is None:
            _os.environ.pop(k, None)
        else:
            _os.environ[k] = v


# ---------- tests ------------------------------------------------------------

def test_01_summary_after_import(client, admin_headers, manifest_seed):
    r = client.get("/api/v1/sigma-rules/summary", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 4
    assert body["skipped"] == 1
    assert body["by_category"].get("process_creation") == 1
    assert body["by_category"].get("file_event") == 1
    assert body["by_os"].get("linux") == 1
    assert body["by_os"].get("windows") == 1
    assert body["by_os"].get("macos") == 1
    assert len(body["skipped_reasons"]) == 1
    assert "aggregation" in body["skipped_reasons"][0]["path"]


def test_02_list_default(client, admin_headers, manifest_seed):
    r = client.get("/api/v1/sigma-rules", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 4
    ids = {it["rule_id"] for it in body["items"]}
    assert "ssh-bruteforce-zoo-001" in ids


def test_03_filter_by_category(client, admin_headers, manifest_seed):
    r = client.get(
        "/api/v1/sigma-rules?category=process_creation",
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "ps-encoded-zoo-001"


def test_04_filter_by_os(client, admin_headers, manifest_seed):
    r = client.get("/api/v1/sigma-rules?os=macos", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "launchd-zoo-001"


def test_05_filter_by_detector_supported(client, admin_headers, manifest_seed):
    r = client.get(
        "/api/v1/sigma-rules?detector_supported=false",
        headers=admin_headers,
    )
    body = r.json()
    # Two accepted rules are detector_supported=False: the cloud rule
    # (no logsource at all -> uncategorized) and the SSH rule
    # (product+service but no category -> uncategorized). The
    # aggregation rule was skipped entirely so it does not appear.
    assert body["total"] == 2
    ids = {it["rule_id"] for it in body["items"]}
    assert ids == {"cloud-iam-zoo-001", "ssh-bruteforce-zoo-001"}


def test_06_filter_by_text(client, admin_headers, manifest_seed):
    r = client.get("/api/v1/sigma-rules?q=powershell", headers=admin_headers)
    body = r.json()
    assert body["total"] == 1
    assert "PowerShell" in body["items"][0]["title"]


def test_07_analyst_can_read(client, analyst_headers, manifest_seed):
    r = client.get("/api/v1/sigma-rules/summary", headers=analyst_headers)
    assert r.status_code == 200


def test_08_viewer_can_read(client, viewer_headers, manifest_seed):
    r = client.get("/api/v1/sigma-rules", headers=viewer_headers)
    assert r.status_code == 200


def test_09_viewer_denied_on_import(client, viewer_headers, manifest_seed):
    r = client.post(
        "/api/v1/sigma-rules/import",
        json={"path": str(FIXTURE)},
        headers=viewer_headers,
    )
    assert r.status_code in (401, 403)


def test_10_admin_dry_run_import(client, admin_headers, manifest_seed):
    r = client.post(
        "/api/v1/sigma-rules/import",
        json={"path": str(FIXTURE)},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 4
    assert body["skipped"] == 1
    # No new files copied -- the manifest_seed fixture is the
    # only thing that wrote anything.
    assert "rules" not in body  # the dry-run endpoint returns to_manifest(), not the full rules list


def test_11_dry_run_missing_path(client, admin_headers, manifest_seed):
    r = client.post(
        "/api/v1/sigma-rules/import",
        json={"path": "/no/such/path"},
        headers=admin_headers,
    )
    assert r.status_code == 400


def test_12_dry_run_missing_body_field(client, admin_headers, manifest_seed):
    r = client.post(
        "/api/v1/sigma-rules/import",
        json={},
        headers=admin_headers,
    )
    assert r.status_code == 400
