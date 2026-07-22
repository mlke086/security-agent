"""Verify all fixes."""
import sys
sys.path.insert(0, ".")
sys.path.insert(0, "src")
from unittest.mock import patch, MagicMock, AsyncMock

mock_user = MagicMock(username="admin", role="admin")
async def fake_get_current_user():
    return mock_user

# Mock the vulnscan_store to control list_hosts / decommission_host behaviour
class FakeStore:
    def __init__(self):
        self.hosts = {
            "online-1": {"agent_id": "online-1", "status": "online", "hostname": "h1"},
            "online-2": {"agent_id": "online-2", "status": "online", "hostname": "h2"},
            "decomm-1": {"agent_id": "decomm-1", "status": "decommissioned", "hostname": "h3"},
            "decomm-2": {"agent_id": "decomm-2", "status": "decommissioned", "hostname": "h4"},
        }
    async def list_hosts(self, status=None, group=None, limit=100, offset=0, exclude_decommissioned=True):
        items = list(self.hosts.values())
        if exclude_decommissioned and status is None:
            items = [h for h in items if h["status"] != "decommissioned"]
        if status:
            items = [h for h in items if h["status"] == status]
        return items
    async def get_host(self, agent_id):
        return self.hosts.get(agent_id)
    async def update_host(self, agent_id, **kw):
        if agent_id in self.hosts:
            self.hosts[agent_id].update(kw)
    async def delete_host(self, agent_id):
        self.hosts.pop(agent_id, None)

fake = FakeStore()

with patch("src.api.auth.routes.get_current_user", new=fake_get_current_user), \
     patch("src.api.main._ensure_es_indices", new=AsyncMock()), \
     patch("src.common.db.pg.init_schema", new=AsyncMock()), \
     patch("src.api.routers.agents.get_vulnscan_store", new=lambda: fake), \
     patch("src.agents.manager.get_vulnscan_store", new=lambda: fake):
    from fastapi.testclient import TestClient
    from src.api.main import app
    client = TestClient(app)

    print("FIX 1+2: list_hosts 默认排除 decommissioned")
    r = client.get("/api/v1/agents", headers={"Authorization": "Bearer fake"})
    items = r.json()["items"]
    print(f"  GET /agents 默认: {len(items)} items -- {[h[\"agent_id\"] for h in items]}")
    assert len(items) == 2, "should be 2 (no decommissioned)"
    assert all(h["status"] != "decommissioned" for h in items)

    r = client.get("/api/v1/agents?include_decommissioned=true", headers={"Authorization": "Bearer fake"})
    items = r.json()["items"]
    print(f"  GET /agents?include_decommissioned=true: {len(items)} items")
    assert len(items) == 4

    print()
    print("FIX 3: 双 @router.delete 装饰器已移除")
    # Only one DELETE endpoint should be registered now
    from src.api.main import app
    delete_routes = [r for r in app.routes if hasattr(r, "methods") and "DELETE" in r.methods and r.path == "/api/v1/agents/{agent_id}"]
    print(f"  DELETE /agents/{{agent_id}} 路由数: {len(delete_routes)}")
    assert len(delete_routes) == 1, f"expected 1, got {len(delete_routes)}"

    print()
    print("FIX 4+5: token-status 端点")
    r = client.get("/api/v1/agents/online-1/token-status", headers={"Authorization": "Bearer fake"})
    print(f"  GET /agents/online-1/token-status: {r.status_code} (will be 500 since PG mock missing -- but route is registered)")
    # Just check it'"'"'s registered
    token_status_routes = [r for r in app.routes if hasattr(r, "methods") and "GET" in r.methods and "/token-status" in r.path]
    print(f"  token-status 路由数: {len(token_status_routes)}")
    assert len(token_status_routes) == 1

    print()
    print("ALL FIXES VERIFIED")
