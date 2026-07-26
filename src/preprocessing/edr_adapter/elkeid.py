"""Elkeid adapter (bytedance/Elkeid plugin alerts)."""
from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter


class ElkeidAdapter(EDRAdapter):
    source = AlertSource.ELKEID

    def _vendor_id(self):
        return str(self.raw.get("alert_id") or self.raw.get("id") or "")

    def _title(self):
        data = self.raw.get("data", {})
        return str(data.get("rule_name") or self.raw.get("title") or "(no rule)")

    def _description(self):
        data = self.raw.get("data", {})
        return str(data.get("description") or "")

    def _severity(self):
        lvl = int(self.raw.get("data", {}).get("level", 3))
        if lvl >= 5: return AlertSeverity.CRITICAL
        if lvl >= 4: return AlertSeverity.HIGH
        if lvl >= 3: return AlertSeverity.MEDIUM
        if lvl >= 2: return AlertSeverity.LOW
        return AlertSeverity.INFO

    def _occurred_at(self):
        return self.raw.get("time") or self.raw.get("timestamp") or super()._occurred_at()

    def _hostname(self):
        h = self.raw.get("host", {})
        return str(h.get("hostname") or h.get("name") or "")

    def _host_ip(self):
        h = self.raw.get("host", {})
        return str(h.get("ip") or "")

    def _agent_id(self):
        return str(self.raw.get("host", {}).get("agent_id") or "")

    def _rule_id(self):
        return str(self.raw.get("data", {}).get("rule_id") or "")

    def _mitre(self):
        return list(self.raw.get("data", {}).get("tactic", []) or [])

    def _iocs(self):
        d = self.raw.get("data", {})
        return AlertIOC(
            ips=[d["srcip"]] if d.get("srcip") else [],
            domains=[d["domain"]] if d.get("domain") else [],
            hashes=[d["sha256"]] if d.get("sha256") else [],
        )

    def _source_url(self):
        return str(self.raw.get("dashboard_url") or "")