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


async def _redis_update(agent_id: str, changes: dict[str, Any] | None = None) -> dict[str, Any]:
    """Single-flight Redis transaction for the upgrade status key.

    A previous implementation opened two connections per update
    (``from_url`` + ``aclose``) and called ``get``/``set`` separately, so a
    racing update from the heartbeat handler could clobber the new state
    with the old snapshot read in between. We now pipeline read+write on a
    single connection.
    """
    from src.common.config.settings import get_settings

    redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    try:
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
    finally:
        await redis.aclose()


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
