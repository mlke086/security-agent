"""Behavior tests for cross-worker agent revocation."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.agents import revoke as revoke_mod
from src.agents.revoke import (
    REVOKE_CHANNEL_PREFIX,
    revoke_agent,
    revoke_channel,
)


def _make_pool_ctx(execute_mock):
    class _PoolCtx:
        async def __aenter__(self):
            return SimpleNamespace(execute=execute_mock)

        async def __aexit__(self, *_):
            return False

    return _PoolCtx()


@pytest.mark.asyncio
async def test_revoke_agent_updates_token_and_publishes() -> None:
    publish_mock = AsyncMock(return_value=2)
    execute_mock = AsyncMock(return_value=None)
    pool = SimpleNamespace(acquire=lambda: _make_pool_ctx(execute_mock))
    redis = SimpleNamespace(publish=publish_mock, aclose=AsyncMock(return_value=None))

    fake_pool = AsyncMock(return_value=pool)

    with (
        patch("src.common.db.pg.get_pg_pool", fake_pool),
        patch("redis.asyncio.from_url", return_value=redis),
    ):
        summary = await revoke_agent("agent-1")

    fake_pool.assert_awaited_once()
    execute_mock.assert_awaited_once()
    sql, agent_id = execute_mock.await_args.args[:2]
    assert "revoked_at = NOW()" in sql
    assert "revoked_at IS NULL" in sql
    assert agent_id == "agent-1"
    publish_mock.assert_awaited_once()
    channel, payload = publish_mock.await_args.args
    assert channel == revoke_channel("agent-1")
    assert channel == f"{REVOKE_CHANNEL_PREFIX}agent-1"
    assert json.loads(payload)["agent_id"] == "agent-1"
    assert summary == {"agent_id": "agent-1", "subscribers": 2}


@pytest.mark.asyncio
async def test_revoke_agent_reports_zero_subscribers_when_no_workers() -> None:
    publish_mock = AsyncMock(return_value=0)
    execute_mock = AsyncMock(return_value=None)
    pool = SimpleNamespace(acquire=lambda: _make_pool_ctx(execute_mock))
    fake_pool = AsyncMock(return_value=pool)
    redis = SimpleNamespace(publish=publish_mock, aclose=AsyncMock(return_value=None))

    with (
        patch("src.common.db.pg.get_pg_pool", fake_pool),
        patch("redis.asyncio.from_url", return_value=redis),
    ):
        summary = await revoke_agent("agent-ghost")

    assert summary["subscribers"] == 0


def _msg(kind, data):
    """Lightweight dict matching what ``pubsub.listen()`` yields."""
    return {"type": kind, "data": data}


@pytest.mark.asyncio
async def test_listen_for_revocations_dispatches_and_skips_bad_events() -> None:
    """listen_for_revocations must dispatch every valid event and skip garbage."""
    seen: list[str] = []

    async def callback(agent_id: str) -> None:
        seen.append(agent_id)

    messages = [
        _msg("psubscribe", f"{REVOKE_CHANNEL_PREFIX}*"),
        None,
        _msg("pmessage", ""),
        _msg("pmessage", "not json"),
        _msg("pmessage", json.dumps({"agent_id": "agent-1"})),
        _msg("pmessage", json.dumps({})),
        _msg("pmessage", json.dumps({"agent_id": "agent-2"})),
    ]

    class _FakePubSub:
        async def psubscribe(self, *_):
            return None

        async def listen(self):
            for m in messages:
                yield m

        async def aclose(self):
            return None

    redis = SimpleNamespace(
        pubsub=lambda: _FakePubSub(),
        aclose=AsyncMock(return_value=None),
    )

    with patch("redis.asyncio.from_url", return_value=redis):
        await revoke_mod.listen_for_revocations(callback)

    assert seen == ["agent-1", "agent-2"]


@pytest.mark.asyncio
async def test_listen_for_revocations_swallows_callback_errors() -> None:
    seen: list[str] = []

    async def dual_callback(agent_id):
        raise RuntimeError("boom")

    messages = [_msg("pmessage", json.dumps({"agent_id": "x"}))]

    class _FakePubSub:
        async def psubscribe(self, *_):
            return None

        async def listen(self):
            for m in messages:
                yield m

        async def aclose(self):
            return None

    redis = SimpleNamespace(pubsub=lambda: _FakePubSub(), aclose=AsyncMock(return_value=None))

    with patch("redis.asyncio.from_url", return_value=redis):
        await revoke_mod.listen_for_revocations(dual_callback)

    assert seen == []