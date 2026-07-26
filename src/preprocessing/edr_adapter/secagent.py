"""Identity / pass-through adapter for our own in-house alerts (Phase 2)."""
from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter

class SecAgentAdapter(EDRAdapter):
    source = AlertSource.SECAGENT

    def _vendor_id(self):
        return str(self.raw.get("alert_id") or self.raw.get("id") or "")

    def _title(self):
        return str(self.raw.get("title") or "SecAgent alert")

    def _description(self):
        return str(self.raw.get("description") or "")

    def _severity(self):
        sev = str(self.raw.get("severity", "medium")).lower()
        if sev in ("critical", "high", "medium", "low", "info"):
            return AlertSeverity(sev)
        return AlertSeverity.MEDIUM

    def _occurred_at(self):
        return self.raw.get("occurred_at") or self.raw.get("timestamp") or super()._occurred_at()

    def _hostname(self): return str(self.raw.get("hostname") or "")
    def _host_ip(self): return str(self.raw.get("host_ip") or "")
    def _agent_id(self): return str(self.raw.get("agent_id") or "")
    def _rule_id(self): return str(self.raw.get("rule_id") or "")
    def _mitre(self): return list(self.raw.get("mitre_attack", []) or [])
    def _iocs(self):
        iocs = self.raw.get("iocs", {}) or {}
        return AlertIOC(
            ips=list(iocs.get("ips", []) or []),
            domains=list(iocs.get("domains", []) or []),
            hashes=list(iocs.get("hashes", []) or []),
            urls=list(iocs.get("urls", []) or []),
        )