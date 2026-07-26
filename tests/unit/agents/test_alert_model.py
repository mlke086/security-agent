"""Unit tests for the Alert Pydantic model (Phase 0 of monitoring plan)."""
import pytest
from pydantic import ValidationError
from src.agents.models import (
    Alert,
    AlertIOC,
    AlertIngestRequest,
    AlertIngestResponse,
    AlertSeverity,
    AlertSource,
    AlertStatus,
)


class TestAlertSeverity:
    def test_all_severities(self):
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.INFO.value == "info"


class TestAlertSource:
    def test_phase1_sources_present(self):
        # Phase 1 wires Wazuh, Elkeid, Syslog
        assert AlertSource.WAZUH.value == "wazuh"
        assert AlertSource.ELKEID.value == "elkeid"
        assert AlertSource.SYSLOG.value == "syslog"

    def test_phase4_sources_present(self):
        # Phase 4 adds the rest
        assert AlertSource.ELASTIC.value == "elastic"
        assert AlertSource.CROWDSTRIKE.value == "crowdstrike"
        assert AlertSource.SENTINELONE.value == "sentinelone"

    def test_secagent_source_for_phase2(self):
        assert AlertSource.SECAGENT.value == "secagent"


class TestAlertIOC:
    def test_default_empty_lists(self):
        ioc = AlertIOC()
        assert ioc.ips == []
        assert ioc.domains == []
        assert ioc.hashes == []
        assert ioc.urls == []
        assert ioc.emails == []
        assert ioc.users == []

    def test_with_data(self):
        ioc = AlertIOC(
            ips=["10.0.0.1", "192.168.1.1"],
            domains=["evil.example.com"],
            hashes=["abc123def456"],
        )
        assert ioc.ips == ["10.0.0.1", "192.168.1.1"]
        assert ioc.domains == ["evil.example.com"]
        assert ioc.hashes == ["abc123def456"]


class TestAlertMinimal:
    """The Alert model with only required fields."""

    def test_minimal_valid(self):
        a = Alert(
            alert_id="wazuh-001",
            source=AlertSource.WAZUH,
            title="SSH brute force",
            severity=AlertSeverity.HIGH,
            occurred_at="2026-07-26T12:00:00Z",
            received_at="2026-07-26T12:00:05Z",
        )
        assert a.alert_id == "wazuh-001"
        assert a.source == AlertSource.WAZUH
        assert a.title == "SSH brute force"
        assert a.severity == AlertSeverity.HIGH
        assert a.status == AlertStatus.NEW  # default
        assert a.iocs == AlertIOC()  # default
        assert a.mitre_attack == []
        assert a.tags == []
        assert a.hostname == ""
        assert a.host_ip == ""
        assert a.raw == {}

    def test_missing_required_fields_raises(self):
        with pytest.raises(ValidationError):
            Alert()  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            Alert(alert_id="x", source=AlertSource.WAZUH)  # missing title etc.

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            Alert(
                alert_id="x",
                source=AlertSource.WAZUH,
                title="t",
                severity="super-critical",  # type: ignore[arg-type]
                occurred_at="2026-01-01T00:00:00Z",
                received_at="2026-01-01T00:00:00Z",
            )


class TestAlertFull:
    def test_all_fields(self):
        a = Alert(
            alert_id="elkeid-002",
            source=AlertSource.ELKEID,
            title="Suspicious process: netcat",
            description="Process netcat with -e flag observed",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.IN_PROGRESS,
            occurred_at="2026-07-26T11:30:00Z",
            received_at="2026-07-26T11:30:10Z",
            hostname="db-01.prod.local",
            host_ip="10.20.30.40",
            agent_id="agent-7f3c",
            rule_id="PROC-NCAT-E",
            rule_name="Suspicious process creation",
            category="execution",
            mitre_attack=["T1059.004"],
            iocs=AlertIOC(
                ips=["10.20.30.40"],
                domains=["c2.example.com"],
                hashes=["deadbeef"],
            ),
            tags=["linux", "shell", "c2"],
            source_url="https://elkeid.example/alerts/002",
            raw={"raw_field": "preserved"},
        )
        assert a.status == AlertStatus.IN_PROGRESS
        assert a.mitre_attack == ["T1059.004"]
        assert a.iocs.ips == ["10.20.30.40"]
        assert a.tags == ["linux", "shell", "c2"]
        assert a.raw == {"raw_field": "preserved"}


class TestAlertIngestRequest:
    def test_default_source_unknown(self):
        req = AlertIngestRequest(payload={"id": "x", "rule": {}})
        assert req.source == AlertSource.UNKNOWN

    def test_explicit_source(self):
        req = AlertIngestRequest(
            source=AlertSource.WAZUH,
            payload={"id": "x", "rule": {"level": 12}},
        )
        assert req.source == AlertSource.WAZUH
        assert req.payload == {"id": "x", "rule": {"level": 12}}

    def test_payload_required(self):
        with pytest.raises(ValidationError):
            AlertIngestRequest(source=AlertSource.WAZUH)  # type: ignore[call-arg]


class TestAlertIngestResponse:
    def test_construction(self):
        resp = AlertIngestResponse(
            alert_id="wazuh-001",
            received_at="2026-07-26T12:00:05Z",
            severity=AlertSeverity.HIGH,
        )
        assert resp.alert_id == "wazuh-001"
        assert resp.severity == AlertSeverity.HIGH