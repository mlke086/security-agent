"""Unit tests for ActionDispatcher (dry-run, idempotency, rollback, routing)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.execution.actions.base import ActionContext, ActionResult
from src.execution.actions.dispatcher import ActionDispatcher


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    mock = MagicMock()
    mock.log = AsyncMock()
    monkeypatch.setattr("src.common.audit.audit_logger.get_audit_logger", lambda: mock)


@pytest.mark.asyncio
async def test_dry_run_skips_real_execution():
    d = ActionDispatcher(dry_run=True)
    ctx = ActionContext(event_id="e1", dry_run=True)
    pb = {"operations": [{"type": "notify", "params": {}}, {"type": "firewall_block", "params": {}}]}
    results = await d.execute_playbook(pb, ctx)
    assert len(results) == 2
    assert all(r["status"] == "dry_run" for r in results)


@pytest.mark.asyncio
async def test_idempotency_skip(monkeypatch):
    d = ActionDispatcher(dry_run=False)
    ctx = ActionContext(event_id="e1", dry_run=False)
    monkeypatch.setattr(d, "_is_done", AsyncMock(return_value=True))
    pb = {"operations": [{"type": "notify", "params": {}}]}
    results = await d.execute_playbook(pb, ctx)
    assert results[0]["status"] == "skipped"


@pytest.mark.asyncio
async def test_unknown_connector_skipped(monkeypatch):
    d = ActionDispatcher(dry_run=False)
    ctx = ActionContext(event_id="e1", dry_run=False)
    monkeypatch.setattr(d, "_is_done", AsyncMock(return_value=False))
    pb = {"operations": [{"type": "no_such_op", "params": {}}]}
    results = await d.execute_playbook(pb, ctx)
    assert results[0]["status"] == "skipped"
    assert "No connector" in results[0]["output"]


@pytest.mark.asyncio
async def test_execute_success_marks_done(monkeypatch):
    d = ActionDispatcher(dry_run=False)
    ctx = ActionContext(event_id="e1", dry_run=False)
    monkeypatch.setattr(d, "_is_done", AsyncMock(return_value=False))
    mark = AsyncMock()
    monkeypatch.setattr(d, "_mark_done", mark)
    conn = MagicMock()
    conn.execute = AsyncMock(
        return_value=ActionResult(op_id="x", op_type="notify", status="success")
    )
    d._registry["notify"] = conn
    pb = {"operations": [{"type": "notify", "params": {}}]}
    results = await d.execute_playbook(pb, ctx)
    assert results[0]["status"] == "success"
    mark.assert_awaited_once()
    conn.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_rollback_on_failure(monkeypatch):
    d = ActionDispatcher(dry_run=False)
    ctx = ActionContext(event_id="e1", dry_run=False)
    monkeypatch.setattr(d, "_is_done", AsyncMock(return_value=False))
    monkeypatch.setattr(d, "_mark_done", AsyncMock())

    ok = MagicMock()
    ok.execute = AsyncMock(
        return_value=ActionResult(op_id="a", op_type="notify", status="success")
    )
    ok.rollback = AsyncMock()
    bad = MagicMock()
    bad.execute = AsyncMock(side_effect=RuntimeError("boom"))
    d._registry["notify"] = ok
    d._registry["firewall_block"] = bad

    pb = {"operations": [{"type": "notify", "params": {}}, {"type": "firewall_block", "params": {}}]}
    results = await d.execute_playbook(pb, ctx)
    assert results[0]["status"] == "success"
    assert results[1]["status"] == "failed"
    ok.rollback.assert_awaited_once()  # prior success rolled back
