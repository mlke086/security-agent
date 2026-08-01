"""Wazuh adapter (manager alerts JSON)."""

from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter


class WazuhAdapter(EDRAdapter):
    source = AlertSource.WAZUH

    def _vendor_id(self):
        return str(self.raw.get("id") or "")

    def _title(self):
        rule = self.raw.get("rule", {})
        return "Wazuh: " + str(rule.get("description", "(no rule description)"))

    def _description(self):
        rule = self.raw.get("rule", {})
        return str(rule.get("description", ""))

    def _severity(self):
        level = int(self.raw.get("rule", {}).get("level", 5))
        if level >= 12:
            return AlertSeverity.CRITICAL
        if level >= 10:
            return AlertSeverity.HIGH
        if level >= 7:
            return AlertSeverity.MEDIUM
        if level >= 4:
            return AlertSeverity.LOW
        return AlertSeverity.INFO

    def _occurred_at(self):
        return self.raw.get("timestamp") or super()._occurred_at()

    def _hostname(self):
        a = self.raw.get("agent", {})
        return str(a.get("name", ""))

    def _agent_id(self):
        a = self.raw.get("agent", {})
        return str(a.get("id", ""))

    def _rule_id(self):
        rule = self.raw.get("rule", {})
        return str(rule.get("id", ""))

    def _rule_name(self):
        rule = self.raw.get("rule", {})
        return str(rule.get("description", ""))

    def _category(self):
        groups = self.raw.get("rule", {}).get("groups")
        if isinstance(groups, list) and groups:
            return str(groups[0])
        return ""

    def _mitre(self):
        mitre = self.raw.get("rule", {}).get("mitre", {})
        ids = mitre.get("id", [])
        return list(ids or [])

    def _iocs(self):
        data = self.raw.get("data") or {}
        return AlertIOC(
            ips=[v for v in (data.get("srcip"), data.get("dstip")) if v],
            hashes=[v for v in (data.get("md5"), data.get("sha1"), data.get("sha256")) if v],
            urls=[v for v in (data.get("url"),) if v],
        )

    def _tags(self):
        groups = self.raw.get("rule", {}).get("groups", [])
        return [t for t in groups if isinstance(t, str)]

    def _source_url(self):
        a = self.raw.get("agent", {})
        ip = a.get("ip", "")
        if not ip:
            return ""
        # Build URL via concat to avoid quote issues
        return "http://" + ip + ":56001/app/wz-home"
