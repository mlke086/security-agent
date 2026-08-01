"""CrowdStrike Falcon detection event."""

from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter


class CrowdStrikeAdapter(EDRAdapter):
    source = AlertSource.CROWDSTRIKE

    def _vendor_id(self):
        return str(self.raw.get("detection_id") or str(self.raw.get("id") or ""))

    def _title(self):
        return str(self.raw.get("name") or self.raw.get("title") or "CrowdStrike alert")

    def _severity(self):
        sev = str(self.raw.get("severity", "")).lower()
        if sev == "critical":
            return AlertSeverity.CRITICAL
        if sev == "high":
            return AlertSeverity.HIGH
        if sev == "medium":
            return AlertSeverity.MEDIUM
        if sev == "low":
            return AlertSeverity.LOW
        if sev == "informational":
            return AlertSeverity.INFO
        return AlertSeverity.MEDIUM

    def _rule_id(self):
        qf = self.raw.get("quarantine_files_sha256", [])
        if isinstance(qf, list) and qf:
            return str(qf[0])
        return str(self.raw.get("tactic") or "")

    def _hostname(self):
        d = self.raw.get("device", {})
        return str(d.get("hostname") or "")

    def _host_ip(self):
        d = self.raw.get("device", {})
        return str(d.get("local_ip") or "")

    def _iocs(self):
        ips = []
        ext = self.raw.get("device", {}).get("external_ip")
        if ext:
            ips = [ext]
        hashes = list(self.raw.get("quarantine_files_sha256", []) or [])
        return AlertIOC(ips=ips, hashes=hashes)
