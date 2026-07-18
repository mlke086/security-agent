"""Sprint 1 — Acceptance test: end-to-end pipeline with real subgraphs."""

import sys
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)
passed = 0
total = 0


def check(label, ok):
    global passed, total
    total += 1
    status = "OK" if ok else "FAIL"
    print(f"  [{status}] {label}")
    if ok:
        passed += 1
    else:
        print(f"         ^^^ FAILURE DETECTED")


print("=" * 50)
print("Sprint 1 — Acceptance Test (M1)")
print("=" * 50)

# 1. Health check
resp = client.get("/health")
check("Health check", resp.status_code == 200 and resp.json() == {"status": "ok"})

# 2. Submit honeypot event → investigate path
event = {
    "sanitized_text": "Honeypot captured whoami && id from 45.33.32.156",
    "iocs": {"ip": ["45.33.32.156"], "command": ["whoami", "id"]},
    "source": "honeypot",
}
resp = client.post("/api/v1/events", json=event)
check("Event submit → 200", resp.status_code == 200)
data = resp.json()
check("Event has event_id", "event_id" in data)
check("Event status = processed", data["status"] == "processed")
event_id = data["event_id"]

# 3. Event status endpoint
resp = client.get(f"/api/v1/events/{event_id}")
check("Event status endpoint", resp.status_code == 200)

# 4. Submit vulnerability event → vuln_check path
vuln_event = {
    "sanitized_text": "CVE-2024-1234 exploit attempt on prod-api-01 with malicious payload",
    "iocs": {"ip": ["10.0.0.5"], "cve": ["CVE-2024-1234"]},
    "source": "waf",
}
resp = client.post("/api/v1/events", json=vuln_event)
check("Vulnerability event submit", resp.status_code == 200)
vuln_data = resp.json()
check("Vuln event has event_id", "event_id" in vuln_data)

# 5. Submit low-priority event → ignore path
noise_event = {
    "sanitized_text": "Port scan from 192.168.1.5 on internal network",
    "iocs": {"ip": ["192.168.1.5"]},
    "source": "ids",
}
resp = client.post("/api/v1/events", json=noise_event)
check("Noise event submit (-> ignore path)", resp.status_code == 200)

# 6. Graph compilation verification
from src.orchestration.main_graph.graph import get_compiled_graph
graph = get_compiled_graph()
nodes = [n for n in graph.nodes.keys()]
check("Graph has investigate node", "investigate" in nodes)
check("Graph has vuln_check node", "vuln_check" in nodes)
check("Graph has entry node", "entry" in nodes)
check("Graph has orchestrator node", "orchestrator" in nodes)
check("Graph has aggregator node", "aggregator" in nodes)
check("Graph has ignore node", "ignore" in nodes)

# 7. Investigation subgraph compilation
from src.orchestration.subgraphs.investigation.graph import build_investigation_subgraph
inv_sub = build_investigation_subgraph()
check("Investigation subgraph compiled", inv_sub is not None)

# 8. MemoryManager available
from src.orchestration.memory import get_memory_manager
mm = get_memory_manager()
check("MemoryManager created", mm is not None)

# 9. Tool registry available
from src.knowledge.tools import get_tool, list_tools
tools = list_tools()
check("Tool registry has tools", len(tools) > 0)
check("VirusTotal tool registered", get_tool("virustotal") is not None)
check("OTX tool registered", get_tool("otx") is not None)
check("Notify WeChat tool registered", get_tool("notify_wechat") is not None)

# 10. Ingestion scripts exist (syntax check only)
from pathlib import Path
s1 = Path("scripts/import_attack_stix.py").exists()
s2 = Path("scripts/ingest_knowledge.py").exists()
check("import_attack_stix.py exists", s1)
check("ingest_knowledge.py exists", s2)

print(f"\n{'='*50}")
print(f"Results: {passed}/{total} checks passed")
if passed == total:
    print("SPRINT 1 — ALL ACCEPTANCE TESTS PASSED!")
else:
    print(f"WARNING: {total - passed} checks failed")
    sys.exit(1)
