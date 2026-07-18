"""Integration tests for ApprovalStore (Redis-backed quorum + wait_result).

Skipped when Redis is unreachable (e.g. CI). Locally exercises the real
Lua-script quorum and the pub/sub wait loop that the C2/M4 fix addressed.
"""

import asyncio
import uuid

import pytest
import redis as sync_redis
import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.orchestration.subgraphs.responder.approval_store import ApprovalStore

try:
    _r = sync_redis.Redis.from_url(get_settings().redis_url)
    _r.ping()
    _r.close()
    _HAS_REDIS = True
except Exception:
    _HAS_REDIS = False

pytestmark = pytest.mark.skipif(not _HAS_REDIS, reason="Redis unreachable")


def _eid() -> str:
    return f"evt-{uuid.uuid4().hex[:10]}"


@pytest.fixture(autouse=True)
async def _clean_approvals():
    """Wipe stale approval:* keys so tests don't collide across runs."""
    if _HAS_REDIS:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            for key in await r.keys("approval:*"):
                await r.delete(key)
        finally:
            await r.aclose()
    yield


@pytest.mark.asyncio
async def test_create_get_resolve():
    s = ApprovalStore()
    aid = str(uuid.uuid4())
    eid = _eid()
    await s.create(aid, eid, "L3", 1)
    data = await s.get(aid)
    assert data["event_id"] == eid
    assert data["status"] == "pending"
    assert data["required"] == 1
    await s.resolve(aid, "approved")
    assert (await s.get(aid))["status"] == "approved"
    await s.close()


@pytest.mark.asyncio
async def test_quorum_l4_requires_two_voters():
    s = ApprovalStore()
    aid = str(uuid.uuid4())
    eid = _eid()
    await s.create(aid, eid, "L4", 2)
    r1 = await s.add_vote(eid, "alice", "approved")
    assert r1["status"] == "pending"  # 1 < 2, not yet
    r2 = await s.add_vote(eid, "bob", "approved")
    assert r2["status"] == "approved"  # 2 >= 2
    await s.close()


@pytest.mark.asyncio
async def test_reject_overrides_quorum():
    s = ApprovalStore()
    aid = str(uuid.uuid4())
    eid = _eid()
    await s.create(aid, eid, "L4", 2)
    r = await s.add_vote(eid, "alice", "rejected")
    assert r["status"] == "rejected"
    await s.close()


@pytest.mark.asyncio
async def test_wait_result_times_out_when_nobody_approves():
    s = ApprovalStore()
    aid = str(uuid.uuid4())
    await s.create(aid, _eid(), "L3", 1)
    result = await s.wait_result(aid, timeout=2)
    assert result == "timeout"
    await s.close()


@pytest.mark.asyncio
async def test_wait_result_returns_approved_after_vote():
    s = ApprovalStore()
    aid = str(uuid.uuid4())
    eid = _eid()
    await s.create(aid, eid, "L3", 1)

    async def _approve_later():
        await asyncio.sleep(0.3)
        await s.add_vote(eid, "alice", "approved")

    asyncio.create_task(_approve_later())
    result = await s.wait_result(aid, timeout=5)
    assert result == "approved"
    await s.close()


@pytest.mark.asyncio
async def test_wait_result_waits_through_partial_vote():
    """L4: first vote is 'pending'; wait_result must keep waiting for the second."""
    s = ApprovalStore()
    aid = str(uuid.uuid4())
    eid = _eid()
    await s.create(aid, eid, "L4", 2)

    async def _vote_twice_later():
        await asyncio.sleep(0.3)
        await s.add_vote(eid, "alice", "approved")   # pending (1<2)
        await asyncio.sleep(0.3)
        await s.add_vote(eid, "bob", "approved")     # approved (2>=2)

    asyncio.create_task(_vote_twice_later())
    result = await s.wait_result(aid, timeout=5)
    assert result == "approved"
    await s.close()
