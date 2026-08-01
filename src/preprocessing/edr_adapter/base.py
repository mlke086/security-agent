"""EDR adapter base + registry."""

import hashlib
from datetime import UTC, datetime
from typing import Any

from src.agents.models import Alert, AlertIOC, AlertSeverity, AlertSource


class EDRAdapter:
    """Base class for EDR/3rd-party alert normalizers.

    Subclasses set class-level `source` and override the private hooks
    to convert their vendor JSON into the common Alert model.
    """

    source: AlertSource  # subclasses override

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw or {}

    def to_alert(self) -> Alert:
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

    def _id(self) -> str:
        vendor = self._vendor_id()
        if vendor:
            return self.source.value + ":" + vendor
        canonical = repr(sorted(self.raw.items())).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()[:32]
        return self.source.value + ":sha256:" + digest

    def _vendor_id(self) -> str:
        return ""

    def _title(self) -> str:
        return self.raw.get("title") or self.raw.get("description") or "(no title)"

    def _description(self) -> str:
        return str(self.raw.get("description") or self.raw.get("summary") or "")

    def _severity(self) -> AlertSeverity:
        return AlertSeverity.MEDIUM

    def _occurred_at(self) -> str:
        return (
            self.raw.get("timestamp")
            or self.raw.get("timestamp_utc")
            or datetime.now(UTC).isoformat()
        )

    def _hostname(self) -> str:
        return ""

    def _host_ip(self) -> str:
        return ""

    def _agent_id(self) -> str:
        return ""

    def _rule_id(self) -> str:
        return ""

    def _rule_name(self) -> str:
        return ""

    def _category(self) -> str:
        return ""

    def _mitre(self) -> list:
        return []

    def _iocs(self) -> AlertIOC:
        return AlertIOC()

    def _tags(self) -> list:
        return []

    def _source_url(self) -> str:
        return ""


class EDRAlertNormalizer:
    """Registry facade (legacy -- prefer edr_adapter.normalize)."""

    ADAPTERS: dict = {}

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
