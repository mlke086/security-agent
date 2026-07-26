"""EDR adapter base + registry. Subclasses set source and override the hooks."""
import hashlib
from datetime import datetime, UTC
from src.agents.models import Alert, AlertIOC, AlertSeverity, AlertSource


class EDRAdapter:
    source = AlertSource.UNKNOWN  # subclasses must override

    def __init__(self, raw):
        self.raw = raw or {}

    def to_alert(self):
        return Alert(
            alert_id=self._id(),
            source=self.source,
            title=self._title(),
            description=self._description(),
            severity=self._severity(),
            occurred_at=self._occurred_at(),
            received_at=datetime.now(UTC).isoformat(),
            hostname=self._hostname(),
            host_ip=self._host_ip(),
            agent_id=self._agent_id(),
            rule_id=self._rule_id(),
            rule_name=self._rule_name(),
            category=self._category(),
            mitre_attack=self._mitre(),
            iocs=self._iocs(),
            tags=self._tags(),
            source_url=self._source_url(),
            raw=self.raw,
        )

    def _id(self):
        vendor = self._vendor_id()
        if vendor:
            return self.source.value + chr(58) + vendor
        canonical = repr(sorted(self.raw.items())).encode(chr(34) + chr(34) + chr(34) + chr(34))
        digest = hashlib.sha256(canonical).hexdigest()[:32]
        return self.source.value + chr(58) + chr(115) + chr(104) + chr(97) + chr(50) + chr(53) + chr(54) + chr(58) + digest

    def _vendor_id(self): return ""
    def _title(self):
        return self.raw.get("title") or self.raw.get("description") or "(no title)"
    def _description(self):
        return str(self.raw.get("description") or self.raw.get("summary") or "")
    def _severity(self): return AlertSeverity.MEDIUM
    def _occurred_at(self):
        return self.raw.get("timestamp") or self.raw.get("timestamp_utc") or datetime.now(UTC).isoformat()
    def _hostname(self): return ""
    def _host_ip(self): return ""
    def _agent_id(self): return ""
    def _rule_id(self): return ""
    def _rule_name(self): return ""
    def _category(self): return ""
    def _mitre(self): return []
    def _iocs(self): return AlertIOC()
    def _tags(self): return []
    def _source_url(self): return ""


class EDRAlertNormalizer:
    ADAPTERS = {}

    @classmethod
    def register(cls, source, adapter_cls):
        cls.ADAPTERS[source] = adapter_cls

    @classmethod
    def normalize(cls, raw, source):
        if isinstance(source, str):
            try:
                source = AlertSource(source)
            except ValueError:
                source = AlertSource.UNKNOWN
        adapter_cls = cls.ADAPTERS.get(source)
        if adapter_cls is None:
            raise ValueError("no adapter for source=" + str(source))
        return adapter_cls(raw).to_alert()
