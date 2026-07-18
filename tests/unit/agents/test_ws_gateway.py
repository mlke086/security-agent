"""Unit tests for WS gateway (agent communication)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.ws_gateway import AgentGateway


@pytest.fixture
def gateway():
    return AgentGateway()


@pytest.fixture
def mock_ws():
    ws = AsyncMock()
    ws.state = MagicMock()
    ws.state._agent_id = "agent-1"
    ws.state._pubsub = AsyncMock()
    ws.state._pubsub.unsubscribe = AsyncMock()
    ws.state._pubsub.close = AsyncMock()
    return ws


# -- authenticate ------------------------------------------------------------

class TestAuthenticate:
    @pytest.mark.asyncio
    async def test_authenticate_valid_token(self, gateway):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "valid-token-123"
        with patch.object(gateway, "_redis", return_value=mock_redis):
            result = await gateway.authenticate("agent-1", "valid-token-123")
            assert result is True
            mock_redis.get.assert_called_with("agent:token:agent-1")

    @pytest.mark.asyncio
    async def test_authenticate_wrong_token(self, gateway):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = "correct-token"
        with patch.object(gateway, "_redis", return_value=mock_redis):
            result = await gateway.authenticate("agent-1", "wrong-token")
            assert result is False

    @pytest.mark.asyncio
    async def test_authenticate_no_token_stored(self, gateway):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        with patch.object(gateway, "_redis", return_value=mock_redis):
            result = await gateway.authenticate("agent-1", "any-token")
            assert result is False


# -- connect / disconnect ----------------------------------------------------

class TestConnect:
    @pytest.mark.asyncio
    async def test_connect_registers_agent(self, gateway, mock_ws):
        mock_redis = AsyncMock()
        mock_redis.pubsub = MagicMock(return_value=mock_ws.state._pubsub)

        with (
            patch.object(gateway, "_redis", return_value=mock_redis),
            patch("src.agents.ws_gateway.register_online", AsyncMock()),
        ):
            await gateway.connect(mock_ws, "agent-1")
            mock_ws.accept.assert_called_once()
            assert mock_ws.state._agent_id == "agent-1"

    @pytest.mark.asyncio
    async def test_disconnect_cleans_up(self, gateway, mock_ws):
        import src.agents.ws_gateway as gw_mod
        gw_mod._conns["agent-1"] = mock_ws
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock()

        with patch.object(gateway, "_redis", return_value=mock_redis):
            await gateway.disconnect(mock_ws)
            assert "agent-1" not in gw_mod._conns


# -- handle_message ----------------------------------------------------------

class TestHandleMessage:
    @pytest.mark.asyncio
    async def test_handle_heartbeat(self, gateway, mock_ws):
        raw = '{"type":"heartbeat","payload":{"cpu":10,"mem":20}}'
        with patch("src.agents.ws_gateway.process_heartbeat", AsyncMock()) as mock_hb:
            await gateway.handle_message(mock_ws, raw)
            mock_hb.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_scan_result(self, gateway, mock_ws):
        raw = '{"type":"scan_result","payload":{"task_id":"t1","hostname":"h1","findings":[],"batch":1,"is_final":true,"ts":""}}'
        mock_store = AsyncMock()
        mock_store.save_result = AsyncMock()
        with patch("src.agents.ws_gateway.get_vulnscan_store", return_value=mock_store):
            await gateway.handle_message(mock_ws, raw)
            mock_store.save_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_scan_step_publishes_progress(self, gateway, mock_ws):
        raw = '{"type":"scan_step","payload":{"task_id":"t1","step":"collect","status":"done"}}'
        with patch.object(gateway, "_pub_task_progress") as mock_pub:
            await gateway.handle_message(mock_ws, raw)
            mock_pub.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_task_ack_publishes_progress(self, gateway, mock_ws):
        raw = '{"type":"task_ack","payload":{"task_id":"t1"}}'
        with patch.object(gateway, "_pub_task_progress") as mock_pub:
            await gateway.handle_message(mock_ws, raw)
            mock_pub.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_update_ack_logs(self, gateway, mock_ws):
        raw = '{"type":"update_ack","payload":{"version":"v2"}}'
        await gateway.handle_message(mock_ws, raw)

    @pytest.mark.asyncio
    async def test_handle_unknown_type(self, gateway, mock_ws):
        raw = '{"type":"weird","payload":{}}'
        await gateway.handle_message(mock_ws, raw)

    @pytest.mark.asyncio
    async def test_handle_invalid_json(self, gateway, mock_ws):
        raw = "not json at all"
        await gateway.handle_message(mock_ws, raw)


# -- send_to_agent / broadcast -----------------------------------------------

class TestSendToAgent:
    @pytest.mark.asyncio
    async def test_send_to_connected_agent(self, gateway):
        import src.agents.ws_gateway as gw_mod
        mock_ws = AsyncMock()
        mock_ws.send_json = AsyncMock()
        gw_mod._conns["agent-1"] = mock_ws

        msg = {"type": "scan_command", "payload": {}}
        with patch("src.agents.ws_gateway.sign_message", return_value=msg):
            result = await gateway.send_to_agent("agent-1", msg)
            assert result is True
            mock_ws.send_json.assert_called_once_with(msg)

    @pytest.mark.asyncio
    async def test_send_to_disconnected_publishes_redis(self, gateway):
        import src.agents.ws_gateway as gw_mod
        gw_mod._conns.clear()
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()

        msg = {"type": "scan_command", "payload": {}}
        with (
            patch("src.agents.ws_gateway.sign_message", return_value=msg),
            patch.object(gateway, "_redis", return_value=mock_redis),
        ):
            result = await gateway.send_to_agent("agent-1", msg)
            assert result is False
            mock_redis.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_counts_sent_and_failed(self, gateway):
        msg = {"type": "scan_command", "payload": {}}
        mock_send = AsyncMock(side_effect=[True, False, True])
        with (
            patch("src.agents.ws_gateway.sign_message", return_value=msg),
            patch.object(gateway, "send_to_agent", mock_send),
        ):
            result = await gateway.broadcast(["a", "b", "c"], msg)
            assert result == {"sent": 2, "failed": 1}


# -- worker_id ---------------------------------------------------------------

class TestWorkerId:
    def test_worker_id_is_string(self, gateway):
        assert isinstance(gateway.worker_id, str)
        assert len(gateway.worker_id) > 0
