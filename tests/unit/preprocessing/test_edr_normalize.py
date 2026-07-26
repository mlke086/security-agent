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
        raw = dict(id='x', rule=dict(level=12, description='x'))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.CRITICAL

    def test_level_10_is_high(self):
        raw = dict(id='x', rule=dict(level=10, description='x'))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.HIGH

    def test_level_7_is_medium(self):
        raw = dict(id='x', rule=dict(level=7, description='x'))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.MEDIUM

    def test_level_4_is_low(self):
        raw = dict(id='x', rule=dict(level=4, description='x'))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.LOW

    def test_level_2_is_info(self):
        raw = dict(id='x', rule=dict(level=2, description='x'))
        assert WazuhAdapter(raw).to_alert().severity == AlertSeverity.INFO


class TestNormalizeRegistry:
    """The registry must route source -> adapter, with safe defaults."""

    def test_string_source_normalized(self):
        # Source passed as a string (e.g. from a webhook header) is coerced
        # to the AlertSource enum.
        raw = dict(id='x', rule=dict(level=5, description='y'))
        alert = normalize(raw, 'wazuh')
        assert alert.source == AlertSource.WAZUH

    def test_unknown_string_source_falls_back_to_syslog(self):
        alert = normalize(dict(msg='hi'), 'somerandombogus')
        assert alert.source == AlertSource.SYSLOG

    def test_unknown_enum_source_still_routes(self):
        # UNKNOWN is not in the registry, so the function uses the
        # Syslog fallback. The result is still a valid Alert.
        alert = normalize(dict(msg='hi'), AlertSource.UNKNOWN)
        assert alert.severity in list(AlertSeverity)