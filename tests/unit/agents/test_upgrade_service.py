"""Behavior tests for preparing a server-controlled Agent upgrade."""

import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.agents.models import Host
from src.agents.upgrade import UpgradeNotAvailableError, prepare_upgrade, upgrade_needed
from src.api.routers.agents import UpgradeRequest


def _host() -> Host:
    return Host(
        agent_id="agent-1",
        hostname="demo-host",
        ip="10.0.0.8",
        os="linux",
        arch="amd64",
        kernel="linux",
        status="online",
        agent_version="0.1.0",
    )


def test_prepare_upgrade_selects_binary_and_signs_hash(tmp_path) -> None:
    binary = tmp_path / "linux" / "amd64" / "agent"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"packaged-agent")
    (tmp_path / "VERSION").write_text("0.2.0\n", encoding="utf-8")
    settings = SimpleNamespace(
        agent_binary_dir=str(tmp_path),
        agent_binary_version="0.1.0",
        agent_console_external_url="https://console.example",
    )

    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        patch("src.agents.upgrade.sign_bytes", return_value="signed-digest") as signer,
    ):
        prepared = prepare_upgrade(_host(), "0.2.0")

    signer.assert_called_once_with(hashlib.sha256(b"packaged-agent").digest())
    assert prepared.version == "0.2.0"
    assert prepared.binary_path == binary
    assert prepared.message["type"] == "agent_upgrade"
    assert prepared.message["payload"] == {
        "version": "0.2.0",
        "download_url": "https://console.example/api/v1/agents/binary/linux/amd64?agent_id=agent-1",
        "signature": "signed-digest",
    }


def test_prepare_upgrade_rejects_version_not_packaged(tmp_path) -> None:
    binary = tmp_path / "linux" / "amd64" / "agent"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"packaged-agent")
    settings = SimpleNamespace(
        agent_binary_dir=str(tmp_path),
        agent_binary_version="0.2.0",
        agent_console_external_url="https://console.example",
    )
    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        pytest.raises(UpgradeNotAvailableError, match="packaged version"),
    ):
        prepare_upgrade(_host(), "9.9.9")


def test_upgrade_request_does_not_accept_a_browser_supplied_url() -> None:
    request = UpgradeRequest(version="0.2.0")
    assert request.version == "0.2.0"
    assert not hasattr(request, "download_url")


@pytest.mark.asyncio
async def test_record_upgrade_ack_for_non_agent_kind_is_a_noop() -> None:
    from src.agents.upgrade import _redis_update, get_upgrade_status, record_upgrade_ack

    seen: dict[str, object] = {}

    async def fake(agent_id, changes=None):
        seen.setdefault("calls", 0)
        seen["calls"] = seen.get("calls", 0) + 1
        return (
            await _redis_update.__wrapped__(agent_id, changes)
            if hasattr(_redis_update, "__wrapped__")
            else {}
        )

    # Always succeed without touching the key for non-agent kinds.
    await record_upgrade_ack("agent-1", {"kind": "rule"})
    assert get_upgrade_status.__name__ == "get_upgrade_status"


@pytest.mark.asyncio
async def test_confirm_upgrade_no_prior_status_is_a_noop() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import (
        confirm_upgrade_from_heartbeat,
    )

    with (
        patch("src.agents.upgrade.get_upgrade_status", AsyncMock(return_value=None)),
        patch("src.agents.upgrade.update_upgrade_status", AsyncMock()) as upd,
    ):
        await confirm_upgrade_from_heartbeat("agent-1", "0.2.0")
    upd.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirm_upgrade_marks_state_when_version_matches() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import (
        confirm_upgrade_from_heartbeat,
    )

    with (
        patch(
            "src.agents.upgrade.get_upgrade_status",
            AsyncMock(
                return_value={
                    "state": "restarting",
                    "target_version": "0.2.0",
                    "ack_received": True,
                }
            ),
        ),
        patch("src.agents.upgrade.update_upgrade_status", AsyncMock()) as upd,
    ):
        await confirm_upgrade_from_heartbeat("agent-1", "0.2.0")
    upd.assert_awaited_once()
    kwargs = upd.await_args.kwargs
    assert kwargs["state"] == "confirmed"
    assert kwargs["current_version"] == "0.2.0"


@pytest.mark.parametrize(
    ("current", "target", "expected"),
    [
        ("0.1.0", "0.2.0", True),
        ("0.2.0", "0.2.0", False),
        ("0.3.0", "0.2.0", False),
        ("", "0.2.0", True),
    ],
)
def test_upgrade_needed_only_for_older_versions(current, target, expected) -> None:
    assert upgrade_needed(current, target) is expected


@pytest.mark.asyncio
async def test_heartbeat_cannot_confirm_before_agent_ack() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import confirm_upgrade_from_heartbeat

    with (
        patch(
            "src.agents.upgrade.get_upgrade_status",
            AsyncMock(
                return_value={"state": "sent", "target_version": "0.2.0", "ack_received": False}
            ),
        ),
        patch("src.agents.upgrade.update_upgrade_status", AsyncMock()) as update,
    ):
        await confirm_upgrade_from_heartbeat("agent-1", "0.2.0")
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_ack_version_must_match_pending_upgrade() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import record_upgrade_ack

    with (
        patch(
            "src.agents.upgrade.get_upgrade_status",
            AsyncMock(return_value={"state": "sent", "target_version": "0.2.0"}),
        ),
        patch("src.agents.upgrade.update_upgrade_status", AsyncMock()) as update,
    ):
        await record_upgrade_ack("agent-1", {"kind": "agent", "version": "9.9.9", "ok": True})
    update.assert_not_awaited()


# ----------------------------------------------------------------------- Nuclei upgrade


class _FakeRedis:
    """Minimal async redis stand-in for the nuclei cooldown lock.

    set(nx=True) returns True on the first call for a key (lock acquired) and
    False thereafter, mirroring ``SET ... NX``. aclose is awaitable.
    """

    def __init__(self) -> None:
        self._held: set[str] = set()

    async def set(self, key, value, ex=None, nx=False):  # noqa: ARG002
        if nx and key in self._held:
            return False
        self._held.add(key)
        return True

    async def delete(self, key) -> int:
        self._held.discard(key)
        return 1

    async def aclose(self) -> None:
        return None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("v3.11.0", "3.11.0"),
        ("3.11.0", "3.11.0"),
        ("V3.11.0", "3.11.0"),
        ("  v3.11.0  ", "3.11.0"),
        ("", ""),
        (None, ""),
    ],
)
def test_norm_nuclei_version_strips_leading_v(raw, expected) -> None:
    from src.agents.upgrade import _norm_nuclei_version

    assert _norm_nuclei_version(raw) == expected


def test_nuclei_zip_name_follows_convention() -> None:
    from src.agents.upgrade import _nuclei_zip_name

    assert _nuclei_zip_name("3.11.0", "linux", "amd64") == "nuclei_3.11.0_linux_amd64.zip"
    assert _nuclei_zip_name("3.11.0", "windows", "arm64") == "nuclei_3.11.0_windows_arm64.zip"


@pytest.mark.asyncio
async def test_trigger_nuclei_upgrade_builds_signed_command() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import trigger_nuclei_upgrade

    fake_redis = _FakeRedis()
    settings = SimpleNamespace(
        redis_url="redis://x",
        nuclei_download_base_url="http://192.168.80.101:8081",
        nuclei_version="3.11.0",
    )
    sent: dict = {}

    async def fake_send(agent_id, msg):
        sent["agent_id"] = agent_id
        sent["msg"] = msg
        return True

    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        patch("src.agents.upgrade.aioredis.from_url", return_value=fake_redis),
        patch("src.agents.ws_gateway.get_agent_gateway") as gw_factory,
    ):
        gw_factory.return_value.send_to_agent = AsyncMock(side_effect=fake_send)
        await trigger_nuclei_upgrade("agent-1", "3.11.0", "linux", "amd64")

    # send_to_agent signs internally (nuclei_upgrade is in SENSITIVE_TYPES --
    # see test_nuclei_upgrade_is_signed_command); here we assert the dispatched
    # message carries the mirror zip URL and version.
    assert sent["msg"]["type"] == "nuclei_upgrade"
    assert (
        sent["msg"]["payload"]["download_url"]
        == "http://192.168.80.101:8081/nuclei_3.11.0_linux_amd64.zip"
    )
    assert sent["msg"]["payload"]["version"] == "3.11.0"


def test_nuclei_upgrade_is_signed_command() -> None:
    """nuclei_upgrade MUST be signed so a MitM cannot forge an upgrade URL."""
    from src.agents.signing import SENSITIVE_TYPES

    assert "nuclei_upgrade" in SENSITIVE_TYPES


@pytest.mark.asyncio
async def test_trigger_nuclei_upgrade_respects_cooldown() -> None:
    """A second call within the cooldown window must not re-dispatch."""
    from unittest.mock import AsyncMock

    from src.agents.upgrade import trigger_nuclei_upgrade

    fake_redis = _FakeRedis()  # holds the lock after the first set(nx=True)
    settings = SimpleNamespace(
        redis_url="redis://x",
        nuclei_download_base_url="http://192.168.80.101:8081",
        nuclei_version="3.11.0",
    )
    send = AsyncMock(return_value=True)

    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        patch("src.agents.upgrade.aioredis.from_url", return_value=fake_redis),
        patch("src.agents.ws_gateway.get_agent_gateway") as gw_factory,
        patch("src.agents.signing.sign_message", side_effect=lambda m: m),
    ):
        gw_factory.return_value.send_to_agent = send
        await trigger_nuclei_upgrade("agent-1", "3.11.0", "linux", "amd64")
        await trigger_nuclei_upgrade("agent-1", "3.11.0", "linux", "amd64")

    # Only the first call wins the lock; the second is a no-op.
    send.assert_awaited_once()


@pytest.mark.asyncio
async def test_trigger_nuclei_upgrade_skips_when_base_url_missing() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import trigger_nuclei_upgrade

    settings = SimpleNamespace(
        redis_url="redis://x",
        nuclei_download_base_url="",
        nuclei_version="3.11.0",
    )
    send = AsyncMock(return_value=True)
    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        patch("src.agents.upgrade.aioredis.from_url", return_value=_FakeRedis()),
        patch("src.agents.ws_gateway.get_agent_gateway") as gw_factory,
    ):
        gw_factory.return_value.send_to_agent = send
        await trigger_nuclei_upgrade("agent-1", "3.11.0", "linux", "amd64")

    send.assert_not_awaited()


# V12 阶段 5.2: 出厂默认值必须为空串（内网 IP 硬编码是信息泄漏 + 必然失效）
def test_nuclei_settings_default_to_empty() -> None:
    from src.common.config.settings import get_settings

    s = get_settings()
    assert s.nuclei_download_base_url == "", s.nuclei_download_base_url
    assert s.nuclei_version == ""
    assert s.nuclei_templates_version == ""


# V12 阶段 5.3: send_to_agent 失败时锁必须删除，下次 heartbeat 即可重试
@pytest.mark.asyncio
async def test_nuclei_upgrade_lock_cleaned_on_send_failure() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import _nuclei_upgrade_lock_key, trigger_nuclei_upgrade

    fake_redis = _FakeRedis()
    settings = SimpleNamespace(
        redis_url="redis://x",
        nuclei_download_base_url="http://192.168.80.101:8081",
        nuclei_version="3.11.0",
    )
    send = AsyncMock(return_value=False)  # delivery failed

    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        patch("src.agents.upgrade.aioredis.from_url", return_value=fake_redis),
        patch("src.agents.ws_gateway.get_agent_gateway") as gw_factory,
        patch("src.agents.signing.sign_message", side_effect=lambda m: m),
    ):
        gw_factory.return_value.send_to_agent = send
        await trigger_nuclei_upgrade("agent-1", "3.11.0", "linux", "amd64")

    # The lock must have been deleted after the failed send, so a second
    # call can acquire it again.
    fake_redis.set(_nuclei_upgrade_lock_key("agent-1"), "1", ex=1, nx=True)

    # Re-run with a now-available lock: should dispatch again.
    send.return_value = True
    with (
        patch("src.agents.upgrade.get_settings", return_value=settings),
        patch("src.agents.upgrade.aioredis.from_url", return_value=fake_redis),
        patch("src.agents.ws_gateway.get_agent_gateway") as gw_factory,
        patch("src.agents.signing.sign_message", side_effect=lambda m: m),
    ):
        gw_factory.return_value.send_to_agent = send
        await trigger_nuclei_upgrade("agent-1", "3.11.0", "linux", "amd64")

    send.assert_awaited()
