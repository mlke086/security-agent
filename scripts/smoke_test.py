"""S0-6: Smoke test — submit test event through the stub pipeline."""

import sys

# We use FastAPI TestClient so we don't need a running server
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

# First, health check
resp = client.get("/health")
assert resp.status_code == 200, f"Health check failed: {resp.status_code}"
assert resp.json() == {"status": "ok"}
print("  [OK] Health check")

# Submit test event
test_event = {
    "sanitized_text": "Honeypot captured whoami && id from 45.33.32.156 on external interface eth0",
    "iocs": {"ip": ["45.33.32.156"], "command": ["whoami", "id"]},
    "source": "honeypot",
}
resp = client.post("/api/v1/events", json=test_event)
assert resp.status_code == 200, f"Event submit failed: {resp.status_code}"
data = resp.json()
assert data["status"] == "processed", f"Unexpected status: {data}"
event_id = data["event_id"]
print(f"  [OK] Event submitted: id={event_id}")

# Get event status
resp = client.get(f"/api/v1/events/{event_id}")
assert resp.status_code == 200
print(f"  [OK] Event status: {resp.json()}")

print("\n==================== S0-6 SMOKE TEST PASSED ====================")
