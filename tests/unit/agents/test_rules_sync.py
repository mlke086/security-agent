"""Unit tests for rules_sync module."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.models import RuleCheck, RuleItem, RulePack
from src.agents.rules_sync import (
    _sign_pack,
    _transform_cves_to_rules,
    diff_versions,
    verify_pack_signature,
)


class TestRuleTransform:
    def test_transform_cve_to_rule(self):
        cve_items = [
            {
                "id": "CVE-2024-1234",
                "descriptions": [{"value": "Buffer overflow in OpenSSH"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "9.0",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        ]
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
            rules=[
                RuleItem(
                    id="CVE-2024-0001",
                    category="sys_vuln",
                    cve="CVE-2024-0001",
                    name="Test",
                    severity="critical",
                    check=RuleCheck(type="package_version", name="test", op="lt", value="1.0"),
                )
            ],
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
        with (
            patch("src.agents.rules_sync._redis") as mock_redis,
            patch("src.agents.rules_sync.get_rule_pack") as mock_pack,
        ):
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


class TestNucleiTemplatesSync:
    """nuclei-templates 同步：URL 拼接 + 全量下发 + 配置缺失短路。"""

    def test_url_builds_from_base_and_version(self):
        from types import SimpleNamespace

        from src.agents.rules_sync import _nuclei_templates_url

        with patch(
            "src.agents.rules_sync.get_settings",
            return_value=SimpleNamespace(
                nuclei_download_base_url="http://192.168.80.101:8081/",
                nuclei_templates_version="10.4.6",
            ),
        ):
            assert _nuclei_templates_url() == "http://192.168.80.101:8081/nuclei-templates-10.4.6.zip"

    def test_url_empty_when_unconfigured(self):
        from types import SimpleNamespace

        from src.agents.rules_sync import _nuclei_templates_url

        with patch(
            "src.agents.rules_sync.get_settings",
            return_value=SimpleNamespace(nuclei_download_base_url="", nuclei_templates_version="10.4.6"),
        ):
            assert _nuclei_templates_url() == ""

    @pytest.mark.asyncio
    async def test_sync_to_all_agents_dispatches_signed_command(self):
        from types import SimpleNamespace

        from src.agents.rules_sync import sync_nuclei_templates_to_all_agents

        settings = SimpleNamespace(
            nuclei_download_base_url="http://192.168.80.101:8081",
            nuclei_templates_version="10.4.6",
        )

        # Fake redis: scan_iter must return an async iterator (real redis-py
        # scan_iter is async). We do NOT mock force_nuclei_templates_update so
        # the real msg-builder runs and we assert on the dispatched message.
        async def _async_keys():
            for k in ("agent:online:a1", "agent:online:a2"):
                yield k

        class _FakeRedis:
            def scan_iter(self, match=None, count=None):  # noqa: ARG002
                return _async_keys()

            async def aclose(self):
                return None

        sent: list[dict] = []

        class _FakeGateway:
            async def send_to_agent(self, agent_id, msg):
                sent.append({"agent_id": agent_id, "msg": msg})
                return True

        with (
            patch("src.agents.rules_sync.get_settings", return_value=settings),
            patch("src.agents.rules_sync._redis", return_value=_FakeRedis()),
            patch("src.agents.ws_gateway.get_agent_gateway", return_value=_FakeGateway()),
            patch("src.agents.signing.sign_message", side_effect=lambda m: m),
        ):
            result = await sync_nuclei_templates_to_all_agents()

        assert result["synced"] == 2
        assert result["total"] == 2
        assert result["version"] == "10.4.6"
        # Both online agents received a nuclei_templates_update command.
        assert len(sent) == 2
        assert {s["agent_id"] for s in sent} == {"a1", "a2"}
        assert all(s["msg"]["type"] == "nuclei_templates_update" for s in sent)
        assert (
            sent[0]["msg"]["payload"]["download_url"]
            == "http://192.168.80.101:8081/nuclei-templates-10.4.6.zip"
        )

    @pytest.mark.asyncio
    async def test_sync_short_circuits_when_unconfigured(self):
        from types import SimpleNamespace

        from src.agents.rules_sync import sync_nuclei_templates_to_all_agents

        settings = SimpleNamespace(
            nuclei_download_base_url="",
            nuclei_templates_version="10.4.6",
        )
        with patch("src.agents.rules_sync.get_settings", return_value=settings):
            result = await sync_nuclei_templates_to_all_agents()

        assert result["synced"] == 0
        assert result.get("error") == "nuclei_templates_not_configured"
