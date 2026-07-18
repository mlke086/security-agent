"""Unit tests for VulnscanStore (ES operations with mocked ES client)."""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from src.agents.models import Host, HostStatus, ScanTask, ScanPolicy, VulnFinding, ScanReport, ScanModule


class TestStoreModels:
    def test_host_model_defaults(self):
        host = Host(agent_id="agent-1", hostname="web01", ip="10.0.0.1", os="linux", arch="amd64", kernel="5.15")
        assert host.status == HostStatus.ONLINE
        assert host.agent_version == ""

    def test_scan_task_defaults(self):
        task = ScanTask(task_id="task-1", source="manual")
        assert task.status == "queued"
        assert task.policy.modules == [ScanModule.SYS_VULN, ScanModule.BASELINE]

    def test_vuln_finding_serialization(self):
        finding = VulnFinding(
            finding_id="f-1", task_id="t-1", agent_id="a-1", hostname="web01",
            category=ScanModule.SYS_VULN, name="Test CVE", severity="high", cve="CVE-2024-0001",
        )
        data = finding.model_dump()
        assert data["category"] == "sys_vuln"
        assert data["severity"] == "high"

    def test_scan_report_stats(self):
        report = ScanReport(
            task_id="t-1",
            stats={"by_severity": {"critical": 2, "high": 5}, "by_category": {"sys_vuln": 7}, "total": 7},
            top_vulns=[{"name": "CVE-2024-0001", "severity": "critical"}],
            recommendations=["Patch immediately"],
        )
        assert report.stats["total"] == 7
