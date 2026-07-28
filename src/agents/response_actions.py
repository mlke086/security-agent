"""Response action registry for direct agent commands.

Phase 4 of the monitoring/alerting refactor: operators can dispatch a small
set of defensive actions (kill a process, quarantine a file) directly to a
specific agent via the WS gateway. This module owns:

  - the canonical list of supported ``action_name`` strings
  - the Pydantic models that validate the per-action payload
  - the JSON envelope (``ResponseActionRequest``) that gets signed and
    pushed over the WebSocket as a ``response_action`` message

Design notes:

  - The schema is intentionally narrow. Anything beyond ``kill_process``
    / ``quarantine_file`` is rejected before the agent sees it, so a
    compromised operator cannot smuggle arbitrary ``op_type`` values to
    the on-host dispatcher. (This is the same threat model
    ``src/execution/actions/dispatcher.py`` uses.)
  - ``isolate_host`` is intentionally NOT in this module yet. It needs
    iptables/nftables write access and a clear rollback story; it is
    tracked separately.
  - Action ids are server-side UUIDs, NOT caller-supplied, so the
    ``response_ack`` correlation can never collide across operators.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

from src.common.logging.logger import get_logger

logger = get_logger(__name__)


# ---------- canonical action catalogue --------------------------------------

#: Action names this server will dispatch. The agent also enforces this
#: whitelist in ``agent/internal/response/response.go`` so that a stale
#: server with a removed action cannot keep using it.
SUPPORTED_ACTIONS: frozenset[str] = frozenset({"kill_process", "quarantine_file"})

#: WebSocket message type the agent listens for.
ACTION_MSG_TYPE: str = "response_action"

#: WebSocket message type the agent uses to acknowledge.
ACTION_ACK_MSG_TYPE: str = "response_ack"


# ---------- per-action payload models ---------------------------------------

class KillProcessPayload(BaseModel):
    """Payload for ``kill_process``.

    ``pid`` must be a positive integer. We do not allow PID 0 or negative
    values; the agent layer additionally rejects ``pid == os.getpid()`` to
    avoid the agent committing suicide mid-task.

    ``signal`` is a small allow-list. Anything outside it is rejected so a
    typo (``SIGKILL_``) cannot leak through and silently no-op on the
    agent side.
    """

    pid: int = Field(..., ge=1, le=4194304, description="Target process id; must be >0 and != self")
    signal: Literal["SIGKILL", "SIGTERM", "SIGABRT"] = Field(
        default="SIGKILL",
        description="POSIX signal to send; SIGTERM first is the gentler default but most callers want SIGKILL",
    )


class QuarantineFilePayload(BaseModel):
    """Payload for ``quarantine_file``.

    ``path`` is an absolute filesystem path. The agent refuses paths that
    resolve outside its allow-listed roots (typically the agent's working
    directory + a per-tenant quarantine zone); this is enforced on the
    agent side so we cannot fully predict the safety check from here.

    We do not accept wildcards or shell globs on purpose -- the operator
    must know exactly which file they want quarantined.
    """

    path: str = Field(..., min_length=1, max_length=4096, description="Absolute path to the file to quarantine")
    reason: str = Field(
        default="",
        max_length=512,
        description="Free-form justification; stored in audit log and shown back in UI",
    )

    @field_validator("path")
    @classmethod
    def _abs_path(cls, v: str) -> str:
        # Path must be absolute on POSIX; on Windows we accept drive-letter
        # absolute too. We don't resolve symlinks here -- the agent does that.
        if not v.startswith("/") and not (len(v) >= 2 and v[1] == ":"):
            raise ValueError("path must be absolute (start with '/' on POSIX)")
        return v


# Discriminated union by ``action`` field. Pydantic v2 supports this via
# ``discriminated unions`` but for two actions a hand-rolled dispatcher
# keeps the error messages friendlier.
_PAYLOAD_MODELS = {
    "kill_process": KillProcessPayload,
    "quarantine_file": QuarantineFilePayload,
}


# ---------- envelope -------------------------------------------------------

class ResponseActionRequest(BaseModel):
    """Server-side envelope that becomes the ``payload`` of a ``response_action`` WS message.

    ``action_id`` is generated server-side; callers only choose ``action``
    and the action-specific ``params``.
    """

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: Literal["kill_process", "quarantine_file"]
    params: dict
    actor: str = Field(default="system", description="username from the JWT subject")
    issued_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @field_validator("params")
    @classmethod
    def _validate_params(cls, v: dict, info) -> dict:
        action = info.data.get("action")
        if action not in _PAYLOAD_MODELS:
            # Literal[...] should have caught this, but stay defensive.
            raise ValueError(f"unsupported action: {action!r}")
        model = _PAYLOAD_MODELS[action]
        # model_validate raises a clean ValidationError on mismatch.
        validated = model.model_validate(v)
        # Round-trip through .model_dump so downstream gets plain types.
        return validated.model_dump()


# ---------- dispatcher helper ----------------------------------------------

def build_action_message(
    agent_id: str, action: str, params: dict, actor: str
) -> dict:
    """Build the full WS message dict for a response_action.

    Returns a dict shaped as ``{v, type, ts, payload, ...}`` ready for
    ``AgentGateway.send_to_agent`` to sign and ship.
    """
    envelope = ResponseActionRequest(action=action, params=params, actor=actor)
    payload = envelope.model_dump()
    return {
        "v": 1,
        "type": ACTION_MSG_TYPE,
        "ts": datetime.now(UTC).isoformat(),
        "payload": payload,
    }


def parse_agent_id_from_action(action: str, params: dict) -> tuple[bool, str]:
    """Quick safety check before we even build the envelope.

    Used by the router to short-circuit obvious garbage (``pid=0``,
    ``path=``) without spending a DB roundtrip looking up the agent.

    Returns ``(ok, reason)``.
    """
    if action not in SUPPORTED_ACTIONS:
        return False, f"unsupported action: {action!r}"
    try:
        model = _PAYLOAD_MODELS[action]
        model.model_validate(params)
    except Exception as exc:  # noqa: BLE001
        return False, f"invalid params for {action}: {exc}"
    return True, ""
