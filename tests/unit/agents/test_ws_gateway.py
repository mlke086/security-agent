"""Unit tests for WS gateway (agent communication)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.models import ScanResult
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
#
# authenticate() validates the agent token against PG via
# src.agents.enroll.validate_agent_token (P0-VS-1 moved it off Redis because
# the Redis key writer was missing and every lookup returned None).


class TestAuthenticate:
    @pytest.mark.asyncio
    async def test_authenticate_valid_token(self, gateway):
        with patch("src.agents.enroll.validate_agent_token", AsyncMock(return_value=True)):
            result = await gateway.authenticate("agent-1", "valid-token-123")
            assert result is True

    @pytest.mark.asyncio
    async def test_authenticate_wrong_token(self, gateway):
        with patch("src.agents.enroll.validate_agent_token", AsyncMock(return_value=False)):
            result = await gateway.authenticate("agent-1", "wrong-token")
            assert result is False

    @pytest.mark.asyncio
    async def test_authenticate_empty_token_short_circuits(self, gateway):
        """No PG lookup when agent_id or token is missing."""
        with patch("src.agents.enroll.validate_agent_token", AsyncMock()) as m:
            assert await gateway.authenticate("", "tok") is False
            assert await gateway.authenticate("agent-1", "") is False
            m.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_pg_failure_returns_false(self, gateway):
        """A PG error must not crash the WS handshake -- return False instead."""
        with patch(
            "src.agents.enroll.validate_agent_token",
            AsyncMock(side_effect=RuntimeError("pg down")),
        ):
            result = await gateway.authenticate("agent-1", "tok")
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
    async def test_handle_host_metrics_persists(self, gateway, mock_ws):
        """需求①: host_metrics 分支写入 metrics_store。

        agent_id 由已认证连接盖章（不信任线上值）；hostname 从 payload
        读出后传给 store（store 侧白名单过滤，不落 ES 数值字段）。
        """
        raw = (
            '{"type":"host_metrics","payload":{"cpu_percent":42.3,"mem_percent":68.1,'
            '"net_in_kbps":128.5,"hostname":"web-01"}}'
        )
        mock_metrics_store = AsyncMock()
        mock_metrics_store.save_metrics = AsyncMock()
        with patch(
            "src.agents.metrics_store.get_metrics_store", return_value=mock_metrics_store
        ):
            await gateway.handle_message(mock_ws, raw)
        mock_metrics_store.save_metrics.assert_awaited_once()
        args, kwargs = mock_metrics_store.save_metrics.await_args
        assert args[0] == "agent-1"  # 连接盖章的 agent_id
        assert args[1] == "web-01"  # payload 中的 hostname
        assert args[2]["cpu_percent"] == 42.3
        assert args[2]["mem_percent"] == 68.1

    @pytest.mark.asyncio
    async def test_handle_host_metrics_never_raises(self, gateway, mock_ws):
        """需求①: 存储失败绝不能拖垮 WS 连接（fire-and-forget）。"""
        raw = '{"type":"host_metrics","payload":{"cpu_percent":1.0}}'

        class _Boom:
            async def save_metrics(self, *a, **k):
                raise RuntimeError("es down")

        with patch("src.agents.metrics_store.get_metrics_store", return_value=_Boom()):
            await gateway.handle_message(mock_ws, raw)  # 不应抛异常

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
        mock_redis.publish = AsyncMock(return_value=1)
        mock_redis.get = AsyncMock(return_value="worker")  # owner present

        msg = {"type": "scan_command", "payload": {}}
        with (
            patch("src.agents.ws_gateway.sign_message", return_value=msg),
            patch.object(gateway, "_redis", return_value=mock_redis),
        ):
            result = await gateway.send_to_agent("agent-1", msg)
            assert result is True
            mock_redis.publish.assert_called_once()
            # V13 P1-1: the shared redis client is process-lifetime and must
            # NOT be closed per call -- this assertion used to lock the old
            # (broken) per-call aclose behaviour.
            mock_redis.aclose.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_to_disconnected_without_subscriber_fails(self, gateway):
        import src.agents.ws_gateway as gw_mod

        gw_mod._conns.clear()
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock(return_value=0)
        msg = {"type": "scan_command", "payload": {}}
        with (
            patch("src.agents.ws_gateway.sign_message", return_value=msg),
            patch.object(gateway, "_redis", return_value=mock_redis),
        ):
            assert await gateway.send_to_agent("agent-1", msg) is False

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


# -- scan_result field adaptation (the E2E blocker) -------------------------
#
# Mirrors agent/internal/scan/engine.go `Finding` -- the shape the agent
# actually puts on the wire. Critically it carries NO finding_id/task_id/
# agent_id/hostname and uses `fix` (not `fix_advice`). The old _handle_scan_result
# passed this straight into ScanResult(findings=...), which raised a pydantic
# ValidationError, bubbled up to the WS receive loop, and disconnected the
# agent -- so the scan_result was lost and ES stayed empty.
AGENT_FINDING = {
    "category": "sys_vuln",
    "cve": "CVE-2024-1234",
    "name": "openssh vulnerable",
    "severity": "high",
    "evidence": "Package openssh version 8.0 lt 9.0",
    "fix": "upgrade openssh to 9.0+",
    "match_type": "package_version",
}


class TestScanResultAdaptation:
    @pytest.mark.asyncio
    async def test_agent_shaped_findings_adapted_not_rejected(self, gateway, mock_ws):
        raw = json.dumps(
            {
                "type": "scan_result",
                "payload": {
                    "task_id": "t1",
                    "hostname": "host-1",
                    "findings": [AGENT_FINDING],
                    "batch": 1,
                    "is_final": True,
                    "ts": "2026-07-19T00:00:00Z",
                },
            }
        )
        mock_store = AsyncMock()
        mock_store.save_result = AsyncMock()
        with patch("src.agents.ws_gateway.get_vulnscan_store", return_value=mock_store):
            await gateway.handle_message(mock_ws, raw)  # must NOT raise
        mock_store.save_result.assert_called_once()
        saved: ScanResult = mock_store.save_result.call_args.args[0]
        assert len(saved.findings) == 1
        f = saved.findings[0]
        # server-side fields filled from the envelope, not expected from the agent
        assert f.finding_id  # generated uuid
        assert f.task_id == "t1"
        assert f.agent_id == "agent-1"
        assert f.hostname == "host-1"
        # fix -> fix_advice mapping
        assert f.fix_advice == "upgrade openssh to 9.0+"
        assert f.severity == "high"
        assert f.name == "openssh vulnerable"

    @pytest.mark.asyncio
    async def test_invalid_severity_degraded_not_dropped(self, gateway, mock_ws):
        finding = {**AGENT_FINDING, "severity": "WARN"}
        raw = json.dumps(
            {
                "type": "scan_result",
                "payload": {
                    "task_id": "t1",
                    "hostname": "h",
                    "findings": [finding],
                    "batch": 1,
                    "is_final": True,
                    "ts": "",
                },
            }
        )
        mock_store = AsyncMock()
        with patch("src.agents.ws_gateway.get_vulnscan_store", return_value=mock_store):
            await gateway.handle_message(mock_ws, raw)
        saved = mock_store.save_result.call_args.args[0]
        assert len(saved.findings) == 1
        assert saved.findings[0].severity == "info"  # degraded, not rejected

    @pytest.mark.asyncio
    async def test_invalid_category_degraded(self, gateway, mock_ws):
        finding = {**AGENT_FINDING, "category": "weird"}
        raw = json.dumps(
            {
                "type": "scan_result",
                "payload": {
                    "task_id": "t1",
                    "hostname": "h",
                    "findings": [finding],
                    "batch": 1,
                    "is_final": True,
                    "ts": "",
                },
            }
        )
        mock_store = AsyncMock()
        with patch("src.agents.ws_gateway.get_vulnscan_store", return_value=mock_store):
            await gateway.handle_message(mock_ws, raw)
        saved = mock_store.save_result.call_args.args[0]
        assert saved.findings[0].category.value == "sys_vuln"

    @pytest.mark.asyncio
    async def test_save_failure_does_not_disconnect(self, gateway, mock_ws):
        """An ES hiccup must not tear down the agent WS connection."""
        raw = json.dumps(
            {
                "type": "scan_result",
                "payload": {
                    "task_id": "t1",
                    "hostname": "h",
                    "findings": [AGENT_FINDING],
                    "batch": 1,
                    "is_final": True,
                    "ts": "",
                },
            }
        )
        mock_store = AsyncMock()
        mock_store.save_result = AsyncMock(side_effect=RuntimeError("es down"))
        with patch("src.agents.ws_gateway.get_vulnscan_store", return_value=mock_store):
            await gateway.handle_message(mock_ws, raw)  # must NOT raise

    @pytest.mark.asyncio
    async def test_non_dict_finding_dropped_others_kept(self, gateway, mock_ws):
        raw = json.dumps(
            {
                "type": "scan_result",
                "payload": {
                    "task_id": "t1",
                    "hostname": "h",
                    "findings": [AGENT_FINDING, "not-a-dict", {**AGENT_FINDING, "name": "second"}],
                    "batch": 1,
                    "is_final": True,
                    "ts": "",
                },
            }
        )
        mock_store = AsyncMock()
        with patch("src.agents.ws_gateway.get_vulnscan_store", return_value=mock_store):
            await gateway.handle_message(mock_ws, raw)
        saved = mock_store.save_result.call_args.args[0]
        names = [f.name for f in saved.findings]
        assert "openssh vulnerable" in names
        assert "second" in names
        assert len(saved.findings) == 2  # the string entry dropped, both dicts kept

    @pytest.mark.asyncio
    async def test_handler_exception_does_not_disconnect(self, gateway, mock_ws):
        """Any handler exception (here: heartbeat) must not propagate -- the
        receive loop in main.py treats a raised exception as fatal."""
        raw = json.dumps({"type": "heartbeat", "payload": {"cpu": 10}})
        with patch(
            "src.agents.ws_gateway.process_heartbeat", AsyncMock(side_effect=RuntimeError("boom"))
        ):
            await gateway.handle_message(mock_ws, raw)  # must NOT raise


# -- V13 P1-1: shared redis client must not be closed -------------------------


class TestSharedRedisNotClosed:
    """V13 P1-1 regression: the module-level shared redis client (V12 5.6
    single-instance fix) was being aclose()'d in 4 places, tearing down the
    shared connection pool on every send_to_agent / disconnect / ack. The
    shared client is process-lifetime; no code path may close it."""

    @pytest.fixture(autouse=True)
    def _reset_shared_redis(self):
        import src.agents.ws_gateway as wsg

        wsg._redis_client = None
        yield
        wsg._redis_client = None

    async def test_send_to_agent_does_not_close_shared_client(self, gateway):
        """Disconnected-agent publish path must leave the shared client open."""
        import src.agents.ws_gateway as wsg

        fake = AsyncMock()
        fake.aclose = AsyncMock()
        fake.publish = AsyncMock(return_value=0)  # no subscribers -> pending path
        fake.get = AsyncMock(return_value=None)
        with patch.object(wsg, "_get_redis", return_value=fake):
            await gateway.send_to_agent("agent-1", {"type": "scan_command"})
        fake.aclose.assert_not_awaited()

    async def test_record_response_ack_does_not_close_shared_client(self, gateway):
        import src.agents.ws_gateway as wsg

        fake = AsyncMock()
        fake.aclose = AsyncMock()
        with patch.object(wsg, "_get_redis", return_value=fake):
            await gateway._record_response_ack("agent-1", {"action_id": "a1", "ok": True})
        fake.aclose.assert_not_awaited()

    async def test_disconnect_does_not_close_shared_client(self, gateway, mock_ws):
        import src.agents.ws_gateway as wsg

        fake = AsyncMock()
        fake.aclose = AsyncMock()
        fake.get = AsyncMock(return_value="worker")
        wsg._conns["agent-1"] = mock_ws
        try:
            with patch.object(wsg, "_get_redis", return_value=fake):
                await gateway.disconnect(mock_ws)
        finally:
            wsg._conns.clear()
        fake.aclose.assert_not_awaited()
