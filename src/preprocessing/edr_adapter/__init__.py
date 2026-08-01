"""EDR / 3rd-party alert normalizers (Phase 1 of monitoring plan)."""

from src.agents.models import Alert, AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter, EDRAlertNormalizer
from src.preprocessing.edr_adapter.crowdstrike import CrowdStrikeAdapter
from src.preprocessing.edr_adapter.elastic import ElasticAdapter
from src.preprocessing.edr_adapter.elkeid import ElkeidAdapter
from src.preprocessing.edr_adapter.secagent import SecAgentAdapter
from src.preprocessing.edr_adapter.sentinelone import SentinelOneAdapter
from src.preprocessing.edr_adapter.syslog import SyslogAdapter
from src.preprocessing.edr_adapter.wazuh import WazuhAdapter

_REGISTRY: dict = {
    AlertSource.WAZUH: WazuhAdapter,
    AlertSource.ELKEID: ElkeidAdapter,
    AlertSource.SYSLOG: SyslogAdapter,
    AlertSource.ELASTIC: ElasticAdapter,
    AlertSource.CROWDSTRIKE: CrowdStrikeAdapter,
    AlertSource.SENTINELONE: SentinelOneAdapter,
    AlertSource.SECAGENT: SecAgentAdapter,
    AlertSource.UNKNOWN: SyslogAdapter,  # UNKNOWN falls back to Syslog (raw text)
}


def normalize(raw, source):
    """Public entry point: pick adapter by source, return Alert."""
    if isinstance(source, str):
        try:
            source = AlertSource(source)
        except ValueError:
            source = AlertSource.UNKNOWN
    adapter_cls = _REGISTRY.get(source, SyslogAdapter)
    return adapter_cls(raw).to_alert()


__all__ = [
    "Alert",
    "AlertIOC",
    "AlertSeverity",
    "AlertSource",
    "EDRAdapter",
    "EDRAlertNormalizer",
    "normalize",
    "WazuhAdapter",
    "ElkeidAdapter",
    "SyslogAdapter",
    "ElasticAdapter",
    "CrowdStrikeAdapter",
    "SentinelOneAdapter",
    "SecAgentAdapter",
]
