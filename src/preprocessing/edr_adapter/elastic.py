"""Elastic Security / Kibana detection alert."""
from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter

class ElasticAdapter(EDRAdapter):
    source = AlertSource.ELASTIC

    def _vendor_id(self):
        return str(self.raw.get("id") or self.raw.get("alert_id") or "")

    def _title(self):
        sig = self.raw.get("signal", {})
        return str(sig.get("title") or self.raw.get("title") or "Elastic alert")

    def _severity(self):
        sig = self.raw.get("signal", {})
        sev = str(sig.get("severity", "")).lower()
        if sev in ("critical", "high"):
            return AlertSeverity(sev)
        if sev == "medium": return AlertSeverity.MEDIUM
        if sev == "low": return AlertSeverity.LOW
        return AlertSeverity.INFO

    def _rule_id(self):
        sig = self.raw.get("signal", {})
        return str(sig.get("rule_id") or "")

    def _rule_name(self):
        sig = self.raw.get("signal", {})
        return str(sig.get("name") or "")

    def _mitre(self):
        sig = self.raw.get("signal", {})
        tactic = sig.get("tactics", {})
        techs = sig.get("techniques", [])
        if isinstance(tactic, dict):
            tactic = tactic.get("id", [])
        if not isinstance(tactic, list):
            tactic = [tactic] if tactic else []
        return list(tactic) + list(techs or [])