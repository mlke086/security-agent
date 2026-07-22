"""Unit tests for agent manager: heartbeat, register, offline, CRUD."""
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.manager import (
    decommission_host,
    get_host,
    heartbeat,
    list_hosts,
    mark_offline_expired,
    register_online,
)

# -- register_online ----------------------------------------------------------

class TestRegisterOnline:
    @pytest.mark.asyncio
    async def test_register_sets_redis_keys_and_updates_es(self):
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_redis.set = AsyncMock()
        mock_store = AsyncMock()
        mock_store.update_host = AsyncMock()

        with (
            patch("src.agents.manager._redis", return_value=mock_redis),
            patch("src.agents.manager.get_vulnscan_store", return_value=mock_store),
            patch("src.agents.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.agent_heartbeat_interval = 60
            await register_online("agent-1", "worker-1")
            mock_redis.setex.assert_called()
            mock_redis.set.assert_called_with("agent:conn:agent-1", "worker-1")
            # register_online now also refreshes last_heartbeat so the next
            # mark_offline_expired sweep does not re-flag a freshly connected
            # agent offline using a stale heartbeat.
            assert mock_store.update_host.call_count == 1
            _, kwargs = mock_store.update_host.call_args
            assert kwargs["status"] == "online"
            assert kwargs["last_heartbeat"]  # an iso8601 ts, not empty


# -- heartbeat ----------------------------------------------------------------

class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_refreshes_ttl(self):
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_store = AsyncMock()
        mock_store.update_host = AsyncMock()

        with (
            patch("src.agents.manager._redis", return_value=mock_redis),
            patch("src.agents.manager.get_vulnscan_store", return_value=mock_store),
            patch("src.agents.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.agent_heartbeat_interval = 60
            await heartbeat("agent-1", {"ts": "2026-01-01T00:00:00Z"})
            mock_redis.setex.assert_called_once()
            mock_store.update_host.assert_called_with("agent-1", last_heartbeat="2026-01-01T00:00:00Z")

    @pytest.mark.asyncio
    async def test_heartbeat_updates_version_fields(self):
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_store = AsyncMock()
        mock_store.update_host = AsyncMock()

        with (
            patch("src.agents.manager._redis", return_value=mock_redis),
            patch("src.agents.manager.get_vulnscan_store", return_value=mock_store),
            patch("src.agents.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.agent_heartbeat_interval = 60
            await heartbeat("agent-1", {
                "ts": "2026-01-01T00:00:00Z",
                "agent_version": "0.2.0",
                "rule_version": "v3",
            })
            mock_store.update_host.assert_called_with(
                "agent-1",
                last_heartbeat="2026-01-01T00:00:00Z",
                agent_version="0.2.0",
                rule_version="v3",
            )


# -- mark_offline_expired ----------------------------------------------------

class TestMarkOfflineExpired:
    @pytest.mark.asyncio
    async def test_mark_offline_returns_count(self):
        mock_store = AsyncMock()
        mock_store.mark_offline_expired.return_value = 3

        with (
            patch("src.agents.manager.get_vulnscan_store", return_value=mock_store),
            patch("src.agents.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.agent_heartbeat_interval = 60
            count = await mark_offline_expired()
            assert count == 3

    @pytest.mark.asyncio
    async def test_mark_offline_zero(self):
        mock_store = AsyncMock()
        mock_store.mark_offline_expired.return_value = 0

        with (
            patch("src.agents.manager.get_vulnscan_store", return_value=mock_store),
            patch("src.agents.manager.get_settings") as mock_settings,
        ):
            mock_settings.return_value.agent_heartbeat_interval = 60
            count = await mark_offline_expired()
            assert count == 0


# -- list_hosts / get_host ---------------------------------------------------

class TestHostQueries:
    @pytest.mark.asyncio
    async def test_list_hosts_with_filters(self):
        mock_store = AsyncMock()
        mock_store.list_hosts.return_value = []

        with patch("src.agents.manager.get_vulnscan_store", return_value=mock_store):
            result = await list_hosts(status_filter="online", group="prod")
            assert result == []
            mock_store.list_hosts.assert_called_with(status="online", group="prod")

    @pytest.mark.asyncio
    async def test_get_host_found(self):
        from src.agents.models import Host
        host = Host(agent_id="a1", hostname="h1", ip="10.0.0.1", os="linux", arch="amd64", kernel="5.15")
        mock_store = AsyncMock()
        mock_store.get_host.return_value = host

        with patch("src.agents.manager.get_vulnscan_store", return_value=mock_store):
            result = await get_host("a1")
            assert result is host

    @pytest.mark.asyncio
    async def test_get_host_not_found(self):
        mock_store = AsyncMock()
        mock_store.get_host.return_value = None

        with patch("src.agents.manager.get_vulnscan_store", return_value=mock_store):
            result = await get_host("nonexistent")
            assert result is None


# -- decommission ------------------------------------------------------------

class TestDecommission:
    @pytest.mark.asyncio
    async def test_decommission_cleans_up(self):
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_store = AsyncMock()
        mock_store.update_host = AsyncMock()

        with (
            patch("src.agents.manager._redis", return_value=mock_redis),
            patch("src.agents.manager.get_vulnscan_store", return_value=mock_store),
        ):
            await decommission_host("agent-1")
            mock_store.update_host.assert_called_with("agent-1", status="decommissioned")
            mock_redis.delete.assert_called_once()
