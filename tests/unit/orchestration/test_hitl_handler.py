"""Unit tests for hitl_handler: approval gating + execute/reject nodes."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.orchestration.subgraphs.responder.hitl_handler import (
    execute_response_node,
    hitl_approval_node,
    reject_response_node,
)


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    mock = MagicMock()
    mock.log = AsyncMock()
    monkeypatch.setattr("src.common.audit.audit_logger.get_audit_logger", lambda: mock)


@pytest.mark.asyncio
async def test_l1_auto_approve():
    result = await hitl_approval_node({"operation_level": "L1", "event_id": "e1"})
    assert result["approval_status"] == "approved"
    assert result["approval_id"] is None


@pytest.mark.asyncio
async def test_l2_auto_approve():
    result = await hitl_approval_node({"operation_level": "L2", "event_id": "e1"})
    assert result["approval_status"] == "approved"


def _mock_store(monkeypatch, wait_returns):
    store = MagicMock()
    store.create = AsyncMock()
    store.wait_result = AsyncMock(return_value=wait_returns)
    monkeypatch.setattr(
        "src.orchestration.subgraphs.responder.hitl_handler.get_approval_store",
        lambda: store,
    )
    monkeypatch.setattr(
        "src.orchestration.subgraphs.responder.hitl_handler._push_approval_card",
        AsyncMock(),
    )
    return store


@pytest.mark.asyncio
async def test_l3_approved(monkeypatch):
    store = _mock_store(monkeypatch, "approved")
    result = await hitl_approval_node({"operation_level": "L3", "event_id": "e1", "playbook_draft": {}})
    assert result["approval_status"] == "approved"
    store.create.assert_awaited_once()


@pytest.mark.asyncio
async def test_l3_rejected(monkeypatch):
    _mock_store(monkeypatch, "rejected")
    result = await hitl_approval_node({"operation_level": "L3", "event_id": "e1", "playbook_draft": {}})
    assert result["approval_status"] == "rejected"


@pytest.mark.asyncio
async def test_l3_timeout_treated_as_rejected(monkeypatch):
    _mock_store(monkeypatch, "timeout")
    result = await hitl_approval_node({"operation_level": "L3", "event_id": "e1", "playbook_draft": {}})
    assert result["approval_status"] == "rejected"


@pytest.mark.asyncio
async def test_execute_skipped_when_not_approved():
    result = await execute_response_node({"approval_status": "rejected", "event_id": "e1"})
    assert result["execution_result"]["status"] == "skipped"


@pytest.mark.asyncio
async def test_execute_runs_dispatcher_when_approved(monkeypatch):
    mock_disp = MagicMock()
    mock_disp.execute_playbook = AsyncMock(
        return_value=[{"op_id": "x", "op_type": "notify", "status": "success"}]
    )
    import src.execution.actions as actions_mod
    monkeypatch.setattr(actions_mod, "ActionDispatcher", lambda **kw: mock_disp)

    state = {
        "approval_status": "approved",
        "event_id": "e1",
        "approval_id": "a1",
        "playbook_draft": {"operations": [{"type": "notify"}]},
    }
    result = await execute_response_node(state)
    assert result["execution_result"]["status"] == "completed"
    mock_disp.execute_playbook.assert_awaited_once()


@pytest.mark.asyncio
async def test_reject_response_node():
    result = await reject_response_node({"approval_status": "rejected", "event_id": "e1"})
    assert result["execution_result"]["status"] == "rejected"
