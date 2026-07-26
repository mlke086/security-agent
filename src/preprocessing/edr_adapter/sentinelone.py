"""SentinelOne threat alert."""
from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter

class SentinelOneAdapter(EDRAdapter):
    source = AlertSource.SENTINELONE

    def _vendor_id(self):
        a = self.raw.get("alertInfo", {}) or self.raw
        return str(a.get("alertId") or a.get("id") or "")

    def _title(self):
        a = self.raw.get("alertInfo", {}) or {}
        return str(a.get("name") or self.raw.get("title") or "SentinelOne alert")

    def _severity(self):
        a = self.raw.get("alertInfo", {})
        sev = str(a.get("severity", "")).upper()
        if sev == "CRITICAL": return AlertSeverity.CRITICAL
        if sev == "HIGH": return AlertSeverity.HIGH
        if sev == "MEDIUM": return AlertSeverity.MEDIUM
        if sev == "LOW": return AlertSeverity.LOW
        if sev == "INFO": return AlertSeverity.INFO
        return AlertSeverity.MEDIUM

    def _hostname(self):
        a = self.raw.get("agentDetectionInfo", {}) or {}
        return str(a.get("agentName") or a.get("machineName") or "")

    def _agent_id(self):
        a = self.raw.get("agentDetectionInfo", {}) or {}
        return str(a.get("agentId") or "")

    def _iocs(self):
        t = self.raw.get("threatInfo", {}) or {}
        hashes = [t["sha256"]] if t.get("sha256") else []
        ips = [t["ip"]] if t.get("ip") else []
        return AlertIOC(hashes=hashes, ips=ips)