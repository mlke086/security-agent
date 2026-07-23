"""Behavior tests for the public scan cancellation action."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.models import ScanTask
from src.api.routers.vulnscan import api_cancel_task
from src.orchestration.subgraphs.vulnscan.nodes import generate_report


@pytest.mark.asyncio
async def test_cancel_running_task_broadcasts_to_assigned_agents() -> None:
    task = ScanTask(
        task_id="task-1",
        targets=["agent-1", "agent-2"],
        status="scanning",
        created_at="2026-07-22T00:00:00+00:00",
    )
    store = AsyncMock()
    store.get_task.return_value = task
    gateway = AsyncMock()
    gateway.broadcast.return_value = {"sent": 2, "failed": 0}
    redis = AsyncMock()

    with (
        patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store),
        patch("src.agents.ws_gateway.get_agent_gateway", return_value=gateway),
        patch("src.api.routers.vulnscan.aioredis.from_url", return_value=redis),
        patch("src.api.routers.vulnscan.get_audit_logger") as audit,
    ):
        audit.return_value.log = AsyncMock()
        result = await api_cancel_task(
            "task-1",
            current_user=SimpleNamespace(username="admin"),
        )

    assert result == {"status": "cancelled", "sent": 2, "failed": 0}
    gateway.broadcast.assert_awaited_once()
    agent_ids, message = gateway.broadcast.await_args.args
    assert agent_ids == ["agent-1", "agent-2"]
    assert message["type"] == "scan_cancel"
    assert message["payload"] == {"task_id": "task-1"}
    assert any(
        call.kwargs.get("status") == "cancelled"
        for call in store.update_task.await_args_list
    )
    redis.publish.assert_awaited()


@pytest.mark.asyncio
async def test_cancel_queued_task_uses_redis_side_channel() -> None:
    store = AsyncMock()
    store.get_task.return_value = None
    redis = AsyncMock()
    redis.get.return_value = json.dumps(
        {
            "status": "queued",
            "targets": ["host-a"],
            "submitted_at": "2026-07-22T00:00:00+00:00",
        }
    )

    with (
        patch("src.api.routers.vulnscan.get_vulnscan_store", return_value=store),
        patch("src.api.routers.vulnscan.aioredis.from_url", return_value=redis),
        patch("src.api.routers.vulnscan.get_audit_logger") as audit,
    ):
        audit.return_value.log = AsyncMock()
        result = await api_cancel_task(
            "task-queued",
            current_user=SimpleNamespace(username="admin"),
        )

    assert result == {"status": "cancelled", "sent": 0, "failed": 0}
    redis.set.assert_awaited()
    redis.publish.assert_awaited()


@pytest.mark.asyncio
async def test_cancelled_graph_never_generates_a_report() -> None:
    store = AsyncMock()
    store.list_vulns.return_value = []

    with patch(
        "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
        return_value=store,
    ):
        result = await generate_report(
            {"task_id": "task-1", "status": "cancelled"}
        )

    assert result == {"report": None, "status": "cancelled"}
    store.save_report.assert_not_awaited()
    assert any(
        call.kwargs.get("status") == "cancelled"
        for call in store.update_task.await_args_list
    )


@pytest.mark.asyncio
async def test_late_result_for_cancelled_task_is_ignored() -> None:
    from src.agents.ws_gateway import AgentGateway

    store = AsyncMock()
    store.get_task.return_value = ScanTask(
        task_id="task-1", targets=["agent-1"], status="cancelled"
    )
    gateway = AgentGateway()
    ws = AsyncMock()
    ws.state = SimpleNamespace(_agent_id="agent-1")
    raw = json.dumps(
        {
            "type": "scan_result",
            "payload": {
                "task_id": "task-1",
                "hostname": "host-1",
                "findings": [],
                "batch": 1,
                "is_final": True,
            },
        }
    )

    with patch(
        "src.agents.ws_gateway.get_vulnscan_store", return_value=store
    ):
        await gateway.handle_message(ws, raw)

    store.save_result.assert_not_awaited()
