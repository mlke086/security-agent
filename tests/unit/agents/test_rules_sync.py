"""Unit tests for rules_sync module."""
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from src.agents.models import RuleCheck, RuleItem, RulePack
from src.agents.rules_sync import (
    _sign_pack,
    _transform_cves_to_rules,
    diff_versions,
    verify_pack_signature,
)


class TestRuleTransform:
    def test_transform_cve_to_rule(self):
        cve_items = [{
            "id": "CVE-2024-1234",
            "descriptions": [{"value": "Buffer overflow in OpenSSH"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
            },
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*",
                "versionEndExcluding": "9.0"
            }]}]}],
        }]
        rules = _transform_cves_to_rules(cve_items)
        assert len(rules) == 1
        assert rules[0]["id"] == "CVE-2024-1234"
        assert rules[0]["severity"] == "critical"
        assert rules[0]["check"]["type"] == "package_version"
        assert rules[0]["check"]["name"] == "openssh"
        assert rules[0]["check"]["value"] == "9.0"

    def test_low_score_cve_filtered(self):
        """CVEs below CVSS 4.0 should be filtered by _fetch_nvd_cves (not tested here
        since _transform_cves_to_rules receives already-filtered items)."""
        cve_items = []
        rules = _transform_cves_to_rules(cve_items)
        assert rules == []


class TestSignPack:
    async def test_sign_and_verify(self):
        pack = RulePack(
            version="2026.07.14",
            rules=[RuleItem(
                id="CVE-2024-0001", category="sys_vuln", cve="CVE-2024-0001",
                name="Test", severity="critical",
                check=RuleCheck(type="package_version", name="test", op="lt", value="1.0"),
            )],
            published_at=datetime.now(UTC).isoformat(),
        )
        # Set signature
        data = pack.model_dump_json(exclude={"signature"})
        pack.signature = _sign_pack(data)

        # Verify
        result = await verify_pack_signature(pack)
        assert result is True

    async def test_tampered_pack_fails_verification(self):
        pack = RulePack(
            version="2026.07.14",
            rules=[],
            published_at=datetime.now(UTC).isoformat(),
        )
        data = pack.model_dump_json(exclude={"signature"})
        pack.signature = _sign_pack(data)

        # Tamper
        pack.version = "evil-version"
        result = await verify_pack_signature(pack)
        assert result is False


class TestVersionDiff:
    async def test_diff_when_behind(self):
        with patch("src.agents.rules_sync._redis") as mock_redis,              patch("src.agents.rules_sync.get_rule_pack") as mock_pack:
            mock_redis.return_value = AsyncMock()
            mock_redis.return_value.get = AsyncMock(return_value="2026.07.14")
            mock_pack.return_value = RulePack(version="2026.07.14", rules=[], published_at="")

            diff = await diff_versions("2026.07.01")
            assert diff is not None
            assert diff["version"] == "2026.07.14"

    async def test_diff_when_current(self):
        with patch("src.agents.rules_sync._redis") as mock_redis:
            mock_redis.return_value = AsyncMock()
            mock_redis.return_value.get = AsyncMock(return_value="2026.07.14")

            diff = await diff_versions("2026.07.14")
            assert diff is None
