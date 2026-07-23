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
    """Mark agent as online on this worker after WS connect.

    We refresh ``last_heartbeat`` to now alongside ``status`` so the very next
    ``mark_offline_expired`` sweep (cutoff = now - 2*heartbeat - 30s) does not
    immediately re-flag this freshly-connected agent offline using a stale
    heartbeat left over from a previous console session -- that race kept
    ``_resolve_targets`` (which filters status=online) from ever seeing the
    agent and aborted every dispatch with "No target agents found".
    """
    from datetime import UTC, datetime

    r = _redis()
    heartbeat_interval = get_settings().agent_heartbeat_interval
    await r.setex(f"agent:online:{agent_id}", heartbeat_interval * 2 + 30, "1")
    await r.set(f"agent:conn:{agent_id}", worker_id)
    await get_vulnscan_store().update_host(
        agent_id, status="online", last_heartbeat=datetime.now(UTC).isoformat()
    )


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

    # P2-UPGRADE-01 (2026-07-22): if the Agent re-announced its version
    # (e.g. after a successful upgrade + restart), update the upgrade
    # status row to confirm or report mismatch. This runs on every
    # heartbeat; confirm_upgrade_from_heartbeat is idempotent.
    agent_version = str(payload.get("agent_version") or "")
    if agent_version:
        from src.agents.upgrade import confirm_upgrade_from_heartbeat

        await confirm_upgrade_from_heartbeat(agent_id, agent_version)

    # Check if agent needs rule update.
    # 修复(需求7)：原 `if agent_rule_version:` 在 agent 上报空版本时短路，
    # 永不触发更新 -- 而 agent 首次连接/未持久化规则版本时恰好上报空串，
    # 导致规则永远分发不下去、matcher 扫描产出 0 findings。改为：空版本
    # 视为 "0"，触发全量更新检查（diff_versions 内部会判断服务端是否有
    # pack 可下发、版本是否已最新，幂等安全）。
    agent_rule_version = payload.get("rule_version", "") or "0"
    # P2-6 修复：fire-and-forget 但用 done_callback 记录异常，避免规则推送
    # 失败被静默吞掉（仅产生 "Task exception was never retrieved" 警告）。
    # 不 await 以免心跳路径被规则下发（含 WS 发送）拖慢。
    try:
        import asyncio

        from src.agents.rules_sync import trigger_update_if_outdated

        task = asyncio.create_task(trigger_update_if_outdated(agent_id, agent_rule_version))

        def _on_done(t: asyncio.Task) -> None:
            if t.cancelled():
                return
            exc = t.exception()
            if exc:
                logger.warning("rule_update_failed", agent_id=agent_id, error=str(exc))

        task.add_done_callback(_on_done)
    except Exception as exc:
        logger.warning("rule_update_schedule_failed", agent_id=agent_id, error=str(exc))


async def mark_offline_expired() -> int:
    """Background task: mark stale hosts offline. Returns count marked."""
    heartbeat_interval = get_settings().agent_heartbeat_interval
    count = await get_vulnscan_store().mark_offline_expired(heartbeat_interval)
    if count:
        logger.info("offline_marked", count=count)
    return count


async def list_hosts(
    status_filter: str | None = None,
    group: str | None = None,
    include_decommissioned: bool = False,
) -> list[Host]:
    """List hosts with optional filters.

    ``include_decommissioned=False`` (default) hides soft-deleted hosts from
    the operator view; pass True to see the full roster (used by the
    admin-only "已下线主机" management view)."""
    return await get_vulnscan_store().list_hosts(
        status=status_filter,
        group=group,
        exclude_decommissioned=not include_decommissioned,
    )


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


async def delete_host_permanently(agent_id: str) -> bool:
    """Physically delete a host (PG + ES + Redis).

    需求1.4：仅允许删除已下线（decommissioned）的主机，避免误删在线主机。
    返回 True 表示已删除，False 表示主机不存在或仍在线（不允许删）。
    """
    host = await get_host(agent_id)
    if not host:
        return False
    if host.status != "decommissioned":
        return False
    await get_vulnscan_store().delete_host(agent_id)
    r = _redis()
    await r.delete(f"agent:online:{agent_id}", f"agent:conn:{agent_id}", f"agent:token:{agent_id}")
    logger.info("host_deleted_permanently", agent_id=agent_id)
    return True


async def list_groups() -> list[dict]:
    """List host groups with member counts."""
    return await get_vulnscan_store().list_groups()


async def create_group(name: str, description: str = "") -> None:
    """Create a new host group. Raises asyncpg.UniqueViolationError on dup."""
    await get_vulnscan_store().create_group(name, description)
    logger.info("host_group_created", group=name)


async def delete_group(name: str) -> int:
    """Delete a host group; returns remaining member count."""
    remaining = await get_vulnscan_store().delete_group(name)
    logger.info("host_group_deleted", group=name, remaining_members=remaining)
    return remaining


async def update_host_group(agent_id: str, group: str | None) -> Host | None:
    """Move a host to a different group (None clears it)."""
    host = await get_host(agent_id)
    if not host:
        return None
    await get_vulnscan_store().update_host(agent_id, group_name=group)
    logger.info("host_group_changed", agent_id=agent_id, group=group)
    return await get_host(agent_id)


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
