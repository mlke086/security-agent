"""Smoke tests for the EDR alert normalizers (Phase 1).

The full per-adapter tests are TBD; these cover the registry path
and severity mapping which is the highest-risk normalization logic.
"""

from src.agents.models import AlertSeverity, AlertSource
from src.preprocessing.edr_adapter import normalize
from src.preprocessing.edr_adapter.wazuh import WazuhAdapter


class TestWazuhSeverity:
    """Wazuh rule level maps to our 5-bucket severity."""

    def test_level_12_is_critical(self):
        raw = dict(id="x", rule=dict(level=12, description="x"))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.CRITICAL

    def test_level_10_is_high(self):
        raw = dict(id="x", rule=dict(level=10, description="x"))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.HIGH

    def test_level_7_is_medium(self):
        raw = dict(id="x", rule=dict(level=7, description="x"))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.MEDIUM

    def test_level_4_is_low(self):
        raw = dict(id="x", rule=dict(level=4, description="x"))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.LOW

    def test_level_2_is_info(self):
        raw = dict(id="x", rule=dict(level=2, description="x"))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.INFO


class TestNormalizeRegistry:
    """The registry must route source -> adapter, with safe defaults."""

    def test_string_source_normalized(self):
        # Source passed as a string (e.g. from a webhook header) is coerced
        # to the AlertSource enum.
        raw = dict(id="x", rule=dict(level=5, description="y"))
        alert = normalize(raw, "wazuh")
        assert alert.source == AlertSource.WAZUH

    def test_unknown_string_source_falls_back_to_syslog(self):
        alert = normalize(dict(msg="hi"), "somerandombogus")
        assert alert.source == AlertSource.SYSLOG

    def test_unknown_enum_source_still_routes(self):
        # UNKNOWN is not in the registry, so the function uses the
        # Syslog fallback. The result is still a valid Alert.
        alert = normalize(dict(msg="hi"), AlertSource.UNKNOWN)
        assert alert.severity in list(AlertSeverity)


class TestSyslogIocs:
    """V13 P1-2: syslog IP IOC extraction (the old pattern used a plain
    string literal where "\\b" is the backspace character, so IPs were
    never extracted)."""

    def _adapter(self, msg: str):
        from src.preprocessing.edr_adapter.syslog import SyslogAdapter

        return SyslogAdapter(dict(msg=msg, hostname="h"))

    def test_extracts_ip_from_plain_message(self):
        alert = self._adapter("sshd failed password for root from 203.0.113.7 port 22").to_alert()
        assert "203.0.113.7" in alert.iocs.ips

    def test_extracts_multiple_ips_and_dedupes(self):
        alert = self._adapter(
            "connection from 203.0.113.7 and 198.51.100.9 and 203.0.113.7"
        ).to_alert()
        assert sorted(alert.iocs.ips) == ["198.51.100.9", "203.0.113.7"]

    def test_no_ip_no_iocs(self):
        alert = self._adapter("sshd: no such user").to_alert()
        assert alert.iocs.ips == []


class TestVendorLevelDefense:
    """V13 P2-1: non-numeric vendor levels must fall back to defaults
    instead of raising (which would DLQ the whole alert)."""

    def test_wazuh_string_level_falls_back(self):
        from src.preprocessing.edr_adapter.wazuh import WazuhAdapter

        alert = WazuhAdapter(dict(id="x", rule=dict(level="high", description="x"))).to_alert()
        assert alert.severity == AlertSeverity.LOW  # default 5 maps to LOW

    def test_wazuh_none_level_falls_back(self):
        from src.preprocessing.edr_adapter.wazuh import WazuhAdapter

        alert = WazuhAdapter(dict(id="x", rule=dict(level=None, description="x"))).to_alert()
        assert alert.severity == AlertSeverity.LOW

    def test_elkeid_string_level_falls_back(self):
        from src.preprocessing.edr_adapter.elkeid import ElkeidAdapter

        alert = ElkeidAdapter(dict(alert_id="a", data=dict(level="high"))).to_alert()
        assert alert.severity == AlertSeverity.MEDIUM  # default 3

    def test_numeric_levels_still_map(self):
        from src.preprocessing.edr_adapter.elkeid import ElkeidAdapter

        alert = ElkeidAdapter(dict(alert_id="a", data=dict(level=5))).to_alert()
        assert alert.severity == AlertSeverity.CRITICAL
