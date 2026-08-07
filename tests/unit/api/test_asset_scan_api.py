"""Unit tests for asset-scan API routes (需求②).

鉴权用 dependency_overrides 注入用户（不依赖 PG，与 vulnscan 新测试
同模式）；enqueue/redis 用 mock。
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


def _auth(role="admin"):
    from src.api.auth.jwt import UserInDB
    from src.api.auth.routes import get_current_user

    user = UserInDB(username=f"t-{role}", hashed_password="x", role=role, token_version=0)
    app.dependency_overrides[get_current_user] = lambda: user
    return {"Authorization": "Bearer t"}


def _cleanup():
    app.dependency_overrides.clear()


class TestCreateTaskValidation:
    """P2-VULN-05 同款防护：入队前参数校验。"""

    def _post(self, body, role="admin"):
        resp = client.post("/api/v1/asset-scan/tasks", json=body, headers=_auth(role))
        _cleanup()
        return resp

    def test_valid_targets_ok(self):
        with patch(
            "src.api.routers.asset_scan.enqueue_asset_task",
            AsyncMock(return_value=type("E", (), {"task_id": "t-1"})()),
        ):
            resp = self._post({"targets": ["10.0.0.0/24", "10.0.1.5"], "engine": "full"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "queued"

    def test_empty_targets_422(self):
        assert self._post({"targets": []}).status_code == 422
        assert self._post({}).status_code == 422

    def test_invalid_ip_422(self):
        resp = self._post({"targets": ["10.0.0.999"]})
        assert resp.status_code == 422
        assert "无效 IP" in resp.text

    def test_invalid_cidr_422(self):
        resp = self._post({"targets": ["10.0.0.0/33"]})
        assert resp.status_code == 422

    def test_too_wide_cidr_422(self):
        # /16 超过 /22 上限（防误扫大段）
        resp = self._post({"targets": ["10.0.0.0/16"]})
        assert resp.status_code == 422
        assert "过宽" in resp.text

    def test_bad_ports_422(self):
        resp = self._post({"targets": ["10.0.0.1"], "ports": [70000, -1, "80"]})
        assert resp.status_code == 422

    def test_bad_engine_422(self):
        resp = self._post({"targets": ["10.0.0.1"], "engine": "quantum"})
        assert resp.status_code == 422

    def test_bad_modules_422(self):
        resp = self._post({"targets": ["10.0.0.1"], "modules": ["hack"]})
        assert resp.status_code == 422

    def test_viewer_forbidden_403(self):
        resp = self._post({"targets": ["10.0.0.1"]}, role="viewer")
        assert resp.status_code == 403

    def test_enqueue_passes_fields(self):
        with patch(
            "src.api.routers.asset_scan.enqueue_asset_task",
            AsyncMock(return_value=type("E", (), {"task_id": "t-2"})()),
        ) as mock_enq:
            self._post({"targets": ["10.0.0.0/24"], "ports": [80, 443],
                        "engine": "fast", "modules": ["discovery", "cve"]})
        mock_enq.assert_awaited_once()
        kw = mock_enq.await_args.kwargs
        assert kw["targets"] == ["10.0.0.0/24"]
        assert kw["ports"] == [80, 443]
        assert kw["engine"] == "fast"
        assert kw["actor"] == "t-admin"


class TestTaskOps:
    @pytest.mark.asyncio
    async def test_cancel_writes_tombstone(self):
        from src.api.routers import asset_scan as router_mod

        fake_redis = AsyncMock()
        with (
            patch.object(router_mod.aioredis, "from_url", return_value=fake_redis),
            patch.object(router_mod.aioredis.Redis, "aclose", AsyncMock()),
        ):
            resp = client.post("/api/v1/asset-scan/tasks/t-1/cancel", headers=_auth())
            _cleanup()
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelling"
        fake_redis.set.assert_awaited_once()
        key = fake_redis.set.await_args.args[0]
        assert key.startswith("assetscan:queue:cancel:")

    def test_stream_requires_token(self):
        # Query 必填缺失 → 422；无效 token → 401
        resp = client.get("/api/v1/asset-scan/tasks/t-1/stream")
        assert resp.status_code == 422
        resp2 = client.get("/api/v1/asset-scan/tasks/t-1/stream", params={"token": "bad"})
        assert resp2.status_code == 401

    def test_delete_requires_admin(self):

        store = AsyncMock()
        store.get_task = AsyncMock(return_value={"task_id": "t-1"})
        with patch("src.asset_scan.store.get_asset_store", return_value=store):
            resp = client.delete("/api/v1/asset-scan/tasks/t-1", headers=_auth("analyst"))
            _cleanup()
        assert resp.status_code == 403  # analyst 无权删除
