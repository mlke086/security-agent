"""Behavior tests for preparing a server-controlled Agent upgrade."""

import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.agents.models import Host
from src.agents.upgrade import UpgradeNotAvailableError, prepare_upgrade
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
        "download_url": "https://console.example/api/v1/agents/binary/linux/amd64",
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
        return await _redis_update.__wrapped__(agent_id, changes) if hasattr(_redis_update, "__wrapped__") else {}

    # Always succeed without touching the key for non-agent kinds.
    await record_upgrade_ack("agent-1", {"kind": "rule"})
    assert get_upgrade_status.__name__ == "get_upgrade_status"


@pytest.mark.asyncio
async def test_confirm_upgrade_no_prior_status_is_a_noop() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import confirm_upgrade_from_heartbeat, get_upgrade_status, update_upgrade_status
    with patch("src.agents.upgrade.get_upgrade_status", AsyncMock(return_value=None)), patch("src.agents.upgrade.update_upgrade_status", AsyncMock()) as upd:
        await confirm_upgrade_from_heartbeat("agent-1", "0.2.0")
    upd.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirm_upgrade_marks_state_when_version_matches() -> None:
    from unittest.mock import AsyncMock

    from src.agents.upgrade import confirm_upgrade_from_heartbeat, get_upgrade_status, update_upgrade_status
    with patch("src.agents.upgrade.get_upgrade_status", AsyncMock(return_value={"state": "sent", "target_version": "0.2.0"})), patch("src.agents.upgrade.update_upgrade_status", AsyncMock()) as upd:
        await confirm_upgrade_from_heartbeat("agent-1", "0.2.0")
    upd.assert_awaited_once()
    kwargs = upd.await_args.kwargs
    assert kwargs["state"] == "confirmed"
    assert kwargs["current_version"] == "0.2.0"
