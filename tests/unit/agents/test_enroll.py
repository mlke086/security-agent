"""Unit tests for enrollment module (PG-backed token generation, validation, script rendering)."""
from unittest.mock import patch

from src.agents.enroll import create_enroll_token, get_install_script_content, validate_enroll_token


class TestEnrollToken:
    """Tests use real PG (schema created by conftest init_schema)."""

    async def test_create_and_validate_token(self):
        """Token should be creatable and validatable within TTL."""
        token, expires = await create_enroll_token(group="prod", ttl_hours=24, uses=1)
        assert len(token) > 30
        result = await validate_enroll_token(token)
        assert result is not None
        assert result["group"] == "prod"

    async def test_token_uses_decrement(self):
        """Multi-use token: uses decrement; after last use token is deleted."""
        token, _ = await create_enroll_token(group="test", ttl_hours=24, uses=3)
        r1 = await validate_enroll_token(token)
        assert r1 is not None  # uses 3->2
        r2 = await validate_enroll_token(token)
        assert r2 is not None  # uses 2->1
        r3 = await validate_enroll_token(token)
        assert r3 is not None  # uses 1->0, deleted
        r4 = await validate_enroll_token(token)
        assert r4 is None  # token deleted

    async def test_token_expired(self):
        """Expired token should return None and be deleted."""
        token, _ = await create_enroll_token(group="expired", ttl_hours=-1, uses=1)
        result = await validate_enroll_token(token)
        assert result is None

    async def test_invalid_token_returns_none(self):
        """Nonexistent token should return None."""
        result = await validate_enroll_token("nonexistent-token-xyz")
        assert result is None


class TestInstallScript:
    def test_linux_script_contains_systemd(self):
        """Linux install script should reference systemd."""
        with patch("src.agents.enroll.get_settings") as mock_settings:
            mock_settings.return_value.agent_console_external_url = "https://console:8000"
            script = get_install_script_content("test-token", "linux")
            assert "systemctl" in script
            assert "$CONFIG_DIR/config.json" in script or "/etc/secagent/config.json" in script

    def test_windows_script_contains_service(self):
        """Windows install script should register as Windows Service."""
        with patch("src.agents.enroll.get_settings") as mock_settings:
            mock_settings.return_value.agent_console_external_url = "https://console:8000"
            script = get_install_script_content("test-token", "windows")
            assert "New-Service" in script
            assert "ProgramData" in script
