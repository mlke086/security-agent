"""Demo seed router — inject sample events for demonstration."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends

from src.api.auth.routes import require_role
from src.api.store import TraceStep, get_event_store

router = APIRouter(tags=["demo"])


_SAMPLE_TEXTS = [
    ("Honeypot captured whoami && id from 203.0.113.5 on external interface eth0",
     {"ip": ["203.0.113.5"], "command": ["whoami", "id"]}, "honeypot",
     "true_positive", 0.92, "high",
     ["Honeypot rule match; IOC 203.0.113.5 known malicious"]),
    ("CVE-2024-1234 exploit attempt: suspicious JNDI lookup from internal host 10.0.1.50 to attacker C2 198.51.100.2",
     {"ip": ["10.0.1.50", "198.51.100.2"]}, "ids",
     "true_positive", 0.88, "high",
     ["Known exploit pattern, IOC 198.51.100.2 associated with APT29"]),
    ("Port scan from 192.168.1.5 on internal network targeting 100+ hosts on port 22",
     {"ip": ["192.168.1.5"]}, "ids",
     "false_positive", 0.15, "low",
     ["Noisy scan, no exploit evidence"]),
    ("Failed admin/admin login on vpn-gw from 10.0.0.1 followed by 500 more attempts",
     {"ip": ["10.0.0.1"]}, "waf",
     "true_positive", 0.75, "medium",
     ["Brute force pattern detected, rate limiting triggered"]),
    ("Lateral movement via RDP from compromised workstation 10.0.1.100 to DC 10.0.1.10",
     {"ip": ["10.0.1.100", "10.0.1.10"]}, "edr",
     "true_positive", 0.95, "high",
     ["Lateral movement detected, IOC 10.0.1.100 reported for credential theft"]),
]


@router.post("/api/v1/demo/seed")
async def seed_demo_data(current_user=Depends(require_role("admin"))):
    store = get_event_store()
    count = 0
    for text, iocs, source, verdict, confidence, priority, evidence in _SAMPLE_TEXTS:
        event_id = f"demo-{uuid.uuid4().hex[:12]}"
        await store.create_event(event_id, text, iocs, source)
        await store.update_event(event_id,
            final_verdict=verdict, confidence=confidence, priority=priority,
            mitre_ttps=["T1059", "T1078"], duration_ms=3500)

        # Build a demo trace
        t = datetime.now(UTC).isoformat()
        await store.add_trace_step(event_id, TraceStep(
            node="entry", action="received", summary=f"Event received from {source}", timestamp=t, details={"source": source}))
        await store.add_trace_step(event_id, TraceStep(
            node="orchestrator", action="triage", summary=f"priority={priority} tags={evidence}", timestamp=t,
            details={"priority": priority, "tags": ["security_event"], "reasoning": evidence[0] if evidence else ""}))
        await store.add_trace_step(event_id, TraceStep(
            node="investigate", action="cti_analysis", summary=f"verdict={verdict} confidence={confidence:.2f}", timestamp=t,
            details={"iocs": iocs, "verdict": verdict, "confidence": confidence, "evidence": evidence}))
        await store.add_trace_step(event_id, TraceStep(
            node="aggregator", action="aggregate", summary=f"Aggregated with verdict={verdict}", timestamp=t,
            details={"final_verdict": verdict, "confidence_score": confidence}))

        if verdict == "true_positive" and confidence >= 0.8:
            ap_id = f"ap-{uuid.uuid4().hex[:8]}"
            await store.update_event(event_id, status="pending_approval", pending_approval_id=ap_id)
            await store.add_trace_step(event_id, TraceStep(
                node="respond", action="playbook_match", summary="Matched playbook for high-confidence event", timestamp=t,
                details={"operation_level": "L3", "playbook": "cve_exploit"}))

            from src.orchestration.subgraphs.responder.hitl_handler import _add_pending_approval
            await _add_pending_approval(ap_id, event_id, "L3")
        else:
            await store.update_event(event_id, status="completed", finished_at=t)

        count += 1

    return {"status": "ok", "injected": count}
