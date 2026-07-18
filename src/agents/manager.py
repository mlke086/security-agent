"""Agent host manager: online/offline tracking, heartbeat, host CRUD."""
import redis.asyncio as aioredis

from src.agents.models import Host
from src.agents.store import get_vulnscan_store
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


def _redis() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


async def register_online(agent_id: str, worker_id: str) -> None:
    """Mark agent as online on this worker after WS connect."""
    r = _redis()
    heartbeat_interval = get_settings().agent_heartbeat_interval
    await r.setex(f"agent:online:{agent_id}", heartbeat_interval * 2 + 30, "1")
    await r.set(f"agent:conn:{agent_id}", worker_id)
    await get_vulnscan_store().update_host(agent_id, status="online")


async def heartbeat(agent_id: str, payload: dict) -> None:
    """Process heartbeat: refresh TTL, update last_heartbeat in ES."""
    r = _redis()
    heartbeat_interval = get_settings().agent_heartbeat_interval
    await r.setex(f"agent:online:{agent_id}", heartbeat_interval * 2 + 30, "1")

    updates = {"last_heartbeat": payload.get("ts", "")}
    if "agent_version" in payload:
        updates["agent_version"] = payload["agent_version"]
    if "rule_version" in payload:
        updates["rule_version"] = payload["rule_version"]
    await get_vulnscan_store().update_host(agent_id, **updates)

    # Check if agent needs rule update
    agent_rule_version = payload.get("rule_version", "")
    if agent_rule_version:
        try:
            import asyncio

            from src.agents.rules_sync import trigger_update_if_outdated
            asyncio.create_task(trigger_update_if_outdated(agent_id, agent_rule_version))
        except Exception:
            pass


async def mark_offline_expired() -> int:
    """Background task: mark stale hosts offline. Returns count marked."""
    heartbeat_interval = get_settings().agent_heartbeat_interval
    count = await get_vulnscan_store().mark_offline_expired(heartbeat_interval)
    if count:
        logger.info("offline_marked", count=count)
    return count


async def list_hosts(status_filter: str | None = None, group: str | None = None) -> list[Host]:
    """List hosts with optional filters."""
    return await get_vulnscan_store().list_hosts(status=status_filter, group=group)


async def get_host(agent_id: str) -> Host | None:
    """Get a single host by agent_id."""
    return await get_vulnscan_store().get_host(agent_id)


async def decommission_host(agent_id: str) -> None:
    """Decommission (soft-delete) a host."""
    await get_vulnscan_store().update_host(agent_id, status="decommissioned")
    # Clean Redis keys
    r = _redis()
    await r.delete(f"agent:online:{agent_id}", f"agent:conn:{agent_id}", f"agent:token:{agent_id}")
    logger.info("host_decommissioned", agent_id=agent_id)

async def decommission_host_by_ip(ip: str) -> int:
    """Decommission every host row whose ``ip`` equals the given value.

    Returns the number of rows affected. Used by the enroll handler so a
    re-registration of the same physical host (same IP) cleanly replaces the
    old record -- the new agent_id / agent_token take effect, the old agent's
    Redis presence is cleared, and the host list stays de-duplicated by IP.

    Note: in NAT / proxy scenarios several physical hosts can share an IP; this
    helper will decommission them all. That is intentional -- the operator
    explicitly chose to register on this IP, and only one host can be
    "current" at a time anyway.
    """
    if not ip:
        return 0
    store = get_vulnscan_store()
    try:
        async with await store._pg_conn() as conn:
            rows = await conn.fetch(
                "SELECT agent_id FROM hosts WHERE ip = $1 AND status <> 'decommissioned'",
                ip,
            )
        if not rows:
            return 0
        for row in rows:
            await decommission_host(row["agent_id"])
        logger.info("hosts_decommissioned_by_ip", ip=ip, count=len(rows))
        return len(rows)
    except Exception as exc:
        logger.warning("decommission_host_by_ip_failed", ip=ip, error=str(exc))
        return 0
