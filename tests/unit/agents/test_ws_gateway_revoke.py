"""Lifecycle tests for AgentGateway revocation handling (F4)."""

from unittest.mock import AsyncMock

import pytest

from src.agents.ws_gateway import AgentGateway


def _fake_ws():
    ws = AsyncMock()
    ws.close = AsyncMock(return_value=None)
    return ws


@pytest.mark.asyncio
async def test_drop_revoked_connection_closes_local_ws() -> None:
    import src.agents.ws_gateway as gw

    gw._conns.clear()
    ws = _fake_ws()
    gw._conns["agent-1"] = ws
    try:
        gateway = AgentGateway()
        await gateway.drop_revoked_connection("agent-1")
    finally:
        gw._conns.pop("agent-1", None)

    assert "agent-1" in gateway._revoked_conns
    ws.close.assert_awaited_once()
    ws.close.assert_awaited_once_with(code=1011, reason="server_revoked")


@pytest.mark.asyncio
async def test_drop_revoked_connection_is_noop_when_no_local_ws() -> None:
    import src.agents.ws_gateway as gw

    gw._conns.clear()
    gateway = AgentGateway()
    await gateway.drop_revoked_connection("agent-ghost")
    assert "agent-ghost" in gateway._revoked_conns


@pytest.mark.asyncio
async def test_authenticate_rejects_revoked_agent() -> None:
    gateway = AgentGateway()
    gateway._revoked_conns.add("agent-1")
    result = await gateway.authenticate("agent-1", "any-token")
    assert result is False