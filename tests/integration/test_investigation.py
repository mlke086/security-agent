"""S2-4: Investigation / pipeline integration tests.

Aligned to the current API contract:
  - /api/v1/events requires a JWT (RBAC: admin/analyst) -> submit with a token.
  - POST always returns status="processing"; the terminal status
    (completed | pending_approval | ignored | error) is read back via GET
    after submitting with ?sync=true so the LangGraph pipeline runs to completion
    within the request.

Events that route to vuln_check are skipped: vuln_hunter end-to-end needs the
sandbox image (not yet built - see 后续计划V2 S2) and would loop on sandbox errors.
"""

import os

import pytest
from fastapi.testclient import TestClient

# Defensive: conftest sets these too, but keep the module importable standalone.
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("STORE_BACKEND", "memory")

from src.api.main import app  # noqa: E402

client = TestClient(app)

TERMINAL_STATUSES = {"completed", "pending_approval", "ignored", "error"}

_VULN_SKIP = pytest.mark.skip(
    reason="vuln_hunter end-to-end requires sandbox image (后续计划V2 S2)"
)

# Labeled test events. `skip` marks cases that route to vuln_check.
_TEST_EVENTS = [
    {
        "name": "honeypot_command",
        "event": {
            "sanitized_text": "Honeypot captured whoami && id from 45.33.32.156 on external interface",
            "iocs": {"ip": ["45.33.32.156"], "command": ["whoami", "id"]},
            "source": "honeypot",
        },
    },
    {
        "name": "exploit_attempt",
        "event": {
            "sanitized_text": "CVE-2024-1234 exploit attempt on prod-api-01 from 10.0.0.5 targeting Apache Struts",
            "iocs": {"ip": ["10.0.0.5"], "cve": ["CVE-2024-1234"]},
            "source": "waf",
        },
        "skip": True,
    },
    {
        "name": "port_scan",
        "event": {
            "sanitized_text": "Port scan from 203.0.113.5 on ports 22,80,443 on internal network",
            "iocs": {"ip": ["203.0.113.5"]},
            "source": "ids",
        },
    },
    {
        "name": "lateral_movement",
        "event": {
            "sanitized_text": "SMB lateral movement from compromised host 192.168.1.50 to 10.0.0.10 using PsExec",
            "iocs": {"ip": ["192.168.1.50", "10.0.0.10"]},
            "source": "edr",
        },
        "skip": True,
    },
    {
        "name": "phishing_email",
        "event": {
            "sanitized_text": "Phishing email detected: malicious.doc from attacker@evil.com to user@company.com with macro downloader",
            "iocs": {"domain": ["evil.com"], "email": ["attacker@evil.com"]},
            "source": "email_gateway",
        },
    },
]


def _token(role: str = "analyst") -> str:
    passwords = {
        "admin": "admin123",
        "analyst": "analyst123",
        "viewer": "viewer123",
        "responder": "responder123",
    }
    resp = client.post(
        "/api/v1/auth/login", json={"username": role, "password": passwords[role]}
    )
    assert resp.status_code == 200, f"login failed for {role}: {resp.text}"
    return resp.json()["access_token"]


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestInvestigationIntegration:
    """Integration tests for the pipeline + API contract."""

    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_graph_compilation(self):
        from src.orchestration.main_graph.graph import get_compiled_graph
        graph = get_compiled_graph()
        assert graph is not None
        nodes = list(graph.nodes.keys())
        for n in ["entry", "orchestrator", "investigate", "vuln_check", "aggregator", "ignore"]:
            assert n in nodes, f"Missing node: {n}"

    def test_investigation_subgraph_compiles(self):
        from src.orchestration.subgraphs.investigation.graph import build_investigation_subgraph
        assert build_investigation_subgraph() is not None

    def test_vuln_hunter_subgraph_compiles(self):
        from src.orchestration.subgraphs.vuln_hunter.graph import build_vuln_hunter_subgraph
        assert build_vuln_hunter_subgraph() is not None

    @pytest.mark.skip(reason="langgraph 0.2.28 has no 'interrupt'; upgrade needed (Sprint 3)")
    def test_responder_subgraph_compiles(self):
        from src.orchestration.subgraphs.responder.graph import build_responder_subgraph
        assert build_responder_subgraph() is not None

    @pytest.mark.parametrize("case", _TEST_EVENTS, ids=lambda c: c["name"])
    def test_event_pipeline(self, case):
        """Submit each test event synchronously and verify it reaches a terminal status."""
        if case.get("skip"):
            pytest.skip(reason="routes to vuln_check; sandbox image not built")
        token = _token("analyst")
        resp = client.post(
            "/api/v1/events?sync=true", json=case["event"], headers=_headers(token)
        )
        assert resp.status_code == 200, f"{case['name']} failed: {resp.text}"
        data = resp.json()
        assert "event_id" in data, f"{case['name']}: no event_id in {data}"
        assert data["status"] == "processing", f"{case['name']}: {data['status']}"

        # sync=true runs the pipeline to completion before returning; read back terminal status.
        detail = client.get(f"/api/v1/events/{data['event_id']}", headers=_headers(token))
        assert detail.status_code == 200, detail.text
        status = detail.json().get("status")
        assert status in TERMINAL_STATUSES, f"{case['name']}: non-terminal status={status}"

    def test_all_events_processed(self):
        """Submit all non-skipped events and verify each reaches a terminal status."""
        token = _token("analyst")
        cases = [c for c in _TEST_EVENTS if not c.get("skip")]
        for case in cases:
            resp = client.post(
                "/api/v1/events?sync=true", json=case["event"], headers=_headers(token)
            )
            assert resp.status_code == 200, f"{case['name']}: {resp.text}"
            eid = resp.json()["event_id"]
            detail = client.get(f"/api/v1/events/{eid}", headers=_headers(token)).json()
            assert detail.get("status") in TERMINAL_STATUSES, f"{case['name']}: {detail.get('status')}"

    def test_submit_requires_auth(self):
        """Posting without a token must be rejected (RBAC)."""
        resp = client.post(
            "/api/v1/events?sync=true",
            json={"sanitized_text": "x", "iocs": {}},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.skip(reason="Requires running Milvus+Neo4j with loaded data")
    def test_graphrag_retrieval(self):
        import asyncio

        from src.knowledge.graphrag.engine import GraphRAGEngine

        async def _test():
            engine = GraphRAGEngine()
            result = await engine.search(
                query_vector=[0.0] * 1024,
                ioc_values=["45.33.32.156"],
                top_k=3,
            )
            await engine.close()
            assert "fused_ids" in result
            assert "vector_hits" in result
            assert "graph_relations" in result

        asyncio.run(_test())

    def test_tool_registry(self):
        """Verify all tools are registered and callable."""
        from src.knowledge.tools import get_tool, list_tools
        tools = list_tools()
        assert len(tools) >= 3
        for name in ["virustotal", "otx", "notify_wechat", "notify_dingtalk"]:
            assert get_tool(name) is not None, f"Missing tool: {name}"
