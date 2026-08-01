"""Server-side orchestration for controlled Agent binary upgrades."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis

from src.agents.models import Host
from src.agents.signing import sign_bytes
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_UPGRADE_STATUS_PREFIX = "agent:upgrade:"
_UPGRADE_STATUS_TTL_SEC = 24 * 3600


class UpgradeNotAvailableError(RuntimeError):
    """The requested packaged binary cannot be offered to this Agent."""


@dataclass(frozen=True)
class PreparedUpgrade:
    version: str
    binary_path: Path
    message: dict[str, Any]


def binary_path_for(host: Host) -> Path:
    root = Path(get_settings().agent_binary_dir).resolve()
    ext = ".exe" if host.os.lower() == "windows" else ""
    candidate = (root / host.os.lower() / host.arch.lower() / f"agent{ext}").resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise UpgradeNotAvailableError("invalid Agent platform path") from exc
    return candidate


def packaged_version() -> str:
    settings = get_settings()
    version_file = Path(settings.agent_binary_dir) / "VERSION"
    if version_file.is_file():
        version = version_file.read_text(encoding="utf-8").strip()
        if version:
            return version
    return settings.agent_binary_version.strip() or "0.1.0"


def _version_key(value: str) -> tuple[int, ...]:
    """Return a conservative numeric key for semver-like Agent versions.

    V9 4.8 (2026-07-30): pre-release tags (``-rc1`` / ``-beta2``) and
    build metadata (``+sha.abc123``) are stripped -- only digits
    participate. Side effect: ``0.2.1-rc1`` and ``0.2.1`` compare
    equal. Acceptable for the current "upgrade only older agents"
    contract (no pre-release GA path), but flag this in the upgrade
    release notes if/when we ship a 0.x-rc line.
    """
    # V10 4.2 (2026-07-30): ``re.findall(r"\d+", ...)`` only
    # sees digits -- so Chinese version labels like
    # ``v0.2.1-正式`` rank the same as ``0.2.1`` (digits 0/2/1).
    # Acceptable for the current upgrade contract; flag the
    # release notes if/when we ship a localised versioning scheme.
    numbers = re.findall(r"\d+", value or "")
    return tuple(int(part) for part in numbers) if numbers else (0,)


def upgrade_needed(current_version: str, target_version: str) -> bool:
    """Only older Agents should receive an upgrade command."""
    return _version_key(current_version) < _version_key(target_version)


def prepare_upgrade(host: Host, requested_version: str | None = None) -> PreparedUpgrade:
    version = packaged_version()
    if requested_version and requested_version != version:
        raise UpgradeNotAvailableError(
            f"requested version {requested_version!r} is not the packaged version {version!r}"
        )

    binary_path = binary_path_for(host)
    if not binary_path.is_file():
        raise UpgradeNotAvailableError(
            f"binary not available for {host.os}/{host.arch}; build the Agent package first"
        )

    digest = hashlib.sha256(binary_path.read_bytes()).digest()
    signature = sign_bytes(digest)
    if not signature:
        raise UpgradeNotAvailableError("AGENT_SIGNING_KEY is not configured")

    base = get_settings().agent_console_external_url.rstrip("/")
    if not base:
        raise UpgradeNotAvailableError("AGENT_CONSOLE_EXTERNAL_URL is not configured")
    download_url = f"{base}/api/v1/agents/binary/{host.os.lower()}/{host.arch.lower()}?agent_id={host.agent_id}"
    message = {
        "v": 1,
        "type": "agent_upgrade",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "version": version,
            "download_url": download_url,
            "signature": signature,
        },
    }
    return PreparedUpgrade(version=version, binary_path=binary_path, message=message)


def _status_key(agent_id: str) -> str:
    return _UPGRADE_STATUS_PREFIX + agent_id


# V12 阶段 5.3: shared lazy redis client (S-P1-1 pattern). The status
# transaction and the nuclei cooldown lock used to open+close a connection
# per call.
_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        from src.common.config.settings import get_settings

        _redis_client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


async def _redis_update(agent_id: str, changes: dict[str, Any] | None = None) -> dict[str, Any]:
    """Single-flight Redis transaction for the upgrade status key.

    A previous implementation opened two connections per update
    (``from_url`` + ``aclose``) and called ``get``/``set`` separately, so a
    racing update from the heartbeat handler could clobber the new state
    with the old snapshot read in between. We now pipeline read+write on a
    single connection.
    """
    redis = _get_redis()
    current: dict[str, Any] = {}
    raw = await redis.get(_status_key(agent_id))
    if raw:
        current = json.loads(raw)
    if changes:
        current.update(changes)
    current["agent_id"] = agent_id
    current["updated_at"] = datetime.now(UTC).isoformat()
    await redis.set(
        _status_key(agent_id),
        json.dumps(current, ensure_ascii=False),
        ex=_UPGRADE_STATUS_TTL_SEC,
    )
    return current


async def update_upgrade_status(agent_id: str, **changes: Any) -> dict[str, Any]:
    return await _redis_update(agent_id, changes)


async def get_upgrade_status(agent_id: str) -> dict[str, Any] | None:
    state = await _redis_update(agent_id, None)
    return state


async def record_upgrade_ack(agent_id: str, payload: dict[str, Any]) -> None:
    if payload.get("kind") != "agent":
        return
    status = await get_upgrade_status(agent_id)
    ack_version = str(payload.get("version") or "")
    if not status or ack_version != str(status.get("target_version") or ""):
        return
    ok = bool(payload.get("ok"))
    await update_upgrade_status(
        agent_id,
        state="restarting" if ok else "failed",
        ack_received=True,
        message="Agent verified the package and is restarting" if ok else "Upgrade failed",
        error=str(payload.get("error") or ""),
    )


async def confirm_upgrade_from_heartbeat(agent_id: str, current_version: str) -> None:
    status = await get_upgrade_status(agent_id)
    if not status or status.get("state") != "restarting" or not status.get("ack_received"):
        return
    changes: dict[str, Any] = {"current_version": current_version}
    if current_version and current_version == status.get("target_version"):
        changes.update(
            state="confirmed",
            message=f"Agent is online on version {current_version}",
            error="",
        )
    await update_upgrade_status(agent_id, **changes)


# ----------------------------------------------------------------------- Nuclei upgrade
#
# The agent reports its installed nuclei CLI version on every heartbeat. The
# server compares it against the Nacos-configured ``nuclei_version`` and, on
# mismatch, pushes a signed ``nuclei_upgrade`` command whose download_url
# points at the internal nginx mirror (``nuclei_{version}_{os}_{arch}.zip``).
# The agent downloads the zip, swaps the binary in place (no restart), and
# re-reports the new version on the next heartbeat.

_NUCLEI_UPGRADE_COOLDOWN_SEC = 300  # avoid re-pushing every heartbeat tick


def _norm_nuclei_version(value: str) -> str:
    """Normalize a nuclei version for comparison: strip a leading ``v`` and
    surrounding whitespace. ``"v3.11.0"`` -> ``"3.11.0"``. Returns "" for
    empty input so an absent nuclei (agent reports "") never equals a real
    expected version and thus always triggers an install push."""
    v = (value or "").strip()
    if v.startswith(("v", "V")):
        v = v[1:]
    return v


def _nuclei_upgrade_lock_key(agent_id: str) -> str:
    return f"agent:nuclei_upgrade:{agent_id}"


def _nuclei_zip_name(version: str, os_name: str, arch: str) -> str:
    return f"nuclei_{version}_{os_name}_{arch}.zip"


async def trigger_nuclei_upgrade(agent_id: str, version: str, os_name: str, arch: str) -> None:
    """Push a signed nuclei_upgrade command to the agent.

    A Redis cooldown lock (``agent:nuclei_upgrade:{agent_id}``, 5 min TTL)
    prevents a heartbeat storm from re-dispatching while an in-flight upgrade
    is still pending or repeatedly failing -- the agent re-reports the new
    version after a successful swap, which naturally clears the mismatch.
    """
    settings = get_settings()
    base = (settings.nuclei_download_base_url or "").strip().rstrip("/")
    if not base or not version:
        logger.warning(
            "nuclei_upgrade_skipped_no_config",
            agent_id=agent_id,
            has_base=bool(base),
            version=version,
        )
        return

    # Cooldown: skip if we already dispatched for this agent recently. The
    # NX + TTL means the first heartbeat that detects the mismatch wins; the
    # rest no-op until either the lock expires or the agent reports the new
    # version (which removes the mismatch entirely).
    redis = _get_redis()
    got = await redis.set(
        _nuclei_upgrade_lock_key(agent_id), "1", ex=_NUCLEI_UPGRADE_COOLDOWN_SEC, nx=True
    )
    if not got:
        return  # another tick is mid-flight; let it finish

    zip_name = _nuclei_zip_name(version, os_name, arch)
    download_url = f"{base}/{zip_name}"
    from src.agents.ws_gateway import get_agent_gateway

    msg = {
        "v": 1,
        "type": "nuclei_upgrade",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "version": version,
            "download_url": download_url,
        },
    }
    # send_to_agent signs the command (nuclei_upgrade is in SENSITIVE_TYPES)
    # and delivers via WS or queues a pending_cmd for an offline agent.
    delivered = await get_agent_gateway().send_to_agent(agent_id, msg)
    if not delivered:
        # V12 阶段 5.3: the lock would otherwise linger for the full 5min
        # cooldown, so the next heartbeat mismatch is blocked even though
        # nothing was actually dispatched. Drop it now -- the next
        # heartbeat re-attempts in ~60s instead of ~5min.
        logger.warning(
            "nuclei_upgrade_lock_cleared_send_failed",
            agent_id=agent_id,
            version=version,
        )
        await redis.delete(_nuclei_upgrade_lock_key(agent_id))
        return
    logger.info(
        "nuclei_upgrade_triggered",
        agent_id=agent_id,
        version=version,
        zip=zip_name,
        delivered=delivered,
    )
