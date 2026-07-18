"""Generate E2E test file with correct indentation."""
import os
 
content = r'''"""S3-5: End-to-end scenario tests covering all 5 routing paths."""
import sys
from fastapi.testclient import TestClient
from src.api.main import app
 
client = TestClient(app)
results = {"passed": 0, "failed": 0, "total": 0}
 
 
def check(scenario: str, detail: str, ok: bool) -> None:
     results["total"] += 1
     tag = "OK" if ok else "FAIL"
     print(f"  [{tag}] [{scenario}] {detail}")
     if ok:
         results["passed"] += 1
     else:
         results["failed"] += 1
 
 
def get_token(username: str = "admin", password: str = "admin123") -> str:
     resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
     return resp.json()["access_token"]
 
 
def headers(token: str) -> dict:
     return {"Authorization": f"Bearer {token}"}
 
 
print("=" * 55)
print("Sprint 3 — E2E Scenario Tests (5 scenarios)")
print("=" * 55)
 
# Scenario 1
print("\n--- Scenario 1: Honeypot → Investigate → Verdict ---")
resp = client.post("/api/v1/events", json={"sanitized_text": "Honeypot captured whoami from 45.33.32.156", "iocs": {"ip": ["45.33.32.156"], "command": ["whoami"]}, "source": "honeypot"})
check("1", "Submit honeypot event", resp.status_code == 200)
data = resp.json()
check("1", "Event has event_id", "event_id" in data)
check("1", "Event processed successfully", data["status"] == "processed")
eid1 = data["event_id"]
resp = client.get(f"/api/v1/events/{eid1}")
check("1", "Event status endpoint", resp.status_code == 200)
 
# Scenario 2
print("\n--- Scenario 2: CVE → vuln_check → Result ---")
resp = client.post("/api/v1/events", json={"sanitized_text": "CVE-2024-1234 exploit attempt on prod-api-01", "iocs": {"ip": ["10.0.0.5"], "cve": ["CVE-2024-1234"]}, "source": "waf"})
check("2", "Submit CVE event", resp.status_code == 200)
data = resp.json()
check("2", "CVE event processed", data["status"] == "processed")
check("2", "CVE event has event_id", "event_id" in data)
 
# Scenario 3
print("\n--- Scenario 3: Noise → Ignore ---")
resp = client.post("/api/v1/events", json={"sanitized_text": "Port scan from 203.0.113.5 on internal network", "iocs": {"ip": ["203.0.113.5"]}, "source": "ids"})
check("3", "Submit noise event", resp.status_code == 200)
data = resp.json()
check("3", "Noise event processed", data["status"] == "processed")
 
# Scenario 4
print("\n--- Scenario 4: Approval Workflow ---")
token = get_token("admin", "admin123")
resp = client.post(f"/api/v1/events/{eid1}/approve?action=approved&note=test", headers=headers(token))
check("4", "Approve event", resp.status_code == 200)
resp = client.get(f"/api/v1/events/{eid1}/trace", headers=headers(token))
check("4", "Get event trace", resp.status_code == 200)
trace = resp.json()
check("4", "Trace contains approvals", trace.get("approval_count", 0) > 0)
check("4", "Trace shows event_id", trace.get("event_id") == eid1)
resp = client.get("/api/v1/metrics", headers=headers(token))
check("4", "Get metrics", resp.status_code == 200)
metrics = resp.json()
check("4", "Metrics has total_events", "total_events" in metrics)
check("4", "Metrics has approved count", metrics.get("events_by_status", {}).get("approved", 0) > 0)
 
# Scenario 5
print("\n--- Scenario 5: Auth Flow ---")
resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
check("5", "Admin login succeeds", resp.status_code == 200)
data = resp.json()
check("5", "Login returns access_token", "access_token" in data)
check("5", "Login returns role=admin", data.get("role") == "admin")
resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
check("5", "Invalid login returns 401", resp.status_code == 401)
resp = client.get("/api/v1/auth/me", headers=headers(token))
check("5", "/me with token returns 200", resp.status_code == 200)
check("5", "/me returns correct username", resp.json().get("username") == "admin")
resp = client.get("/api/v1/auth/me")
check("5", "/me without token returns 401", resp.status_code == 401)
viewer_token = get_token("viewer", "viewer123")
resp = client.post(f"/api/v1/events/{eid1}/approve?action=approved", headers=headers(viewer_token))
check("5", "Viewer cannot approve (403)", resp.status_code == 403)
resp = client.get("/api/v1/metrics", headers=headers(token))
check("5", "Admin can access metrics", resp.status_code == 200)
 
# Summary
print(f"\n{'=' * 55}")
p, f, t = results["passed"], results["failed"], results["total"]
print(f"Results: {p}/{t} passed, {f} failed")
if f == 0:
     print("ALL E2E SCENARIOS PASSED!")
else:
     print(f"WARNING: {f} scenarios failed")
     sys.exit(1)
'''
 
path = 'V:/project/security-agent/tests/e2e/test_scenarios.py'
with open(path, 'w', encoding='utf-8') as f:
     f.write(content)
print(f'Created: {path}')
