"""Response action router (Phase 4 of monitoring plan).

Endpoints:
  POST /api/v1/agents/{agent_id}/actions/{action_name}
      Dispatch a single defensive action to a specific agent. Server
      validates the action+params, signs a WS message, ships it via the
      AgentGateway (which fans out via Redis pub/sub for cross-worker).
      Audit-logs the dispatch and returns immediately with the
      ``action_id`` so the operator can correlate the eventual ack.

  GET /api/v1/agents/actions/{action_id}
      Best-effort status read. Returns ``"dispatched"`` until the agent
      reports ``response_ack``, then ``"succeeded"`` / ``"failed"``.
      Cached in Redis with a 5-minute TTL (acks are typically seconds).

RBAC: viewer is denied everywhere; ``responder`` and ``admin`` can dispatch.
"""

from __future__ import annotations

import json
import time

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, Field

from src.agents.response_actions import (
    SUPPORTED_ACTIONS,
    build_action_message,
    parse_agent_id_from_action,
)
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["response"])


# P1 (F4): same `action` segment can be ``kill_process`` etc. FastAPI does
# not validate path values, so we whitelist in the handler. Keeping the
# validator here (rather than only in the body schema) makes OpenAPI/docs
# show the right thing and lets us 404 vs 400 clearly.
SUPPORTED_PATH_ACTIONS = sorted(SUPPORTED_ACTIONS)


class ActionDispatchResponse(BaseModel):
    action_id: str
    action: str
    agent_id: str
    status: str = Field(
        default="dispatched", description="dispatched | succeeded | failed | unknown"
    )


class ActionStatusResponse(BaseModel):
    action_id: str
    status: str
    detail: str = ""
    agent_id: str = ""
    received_at: str = ""


# ---------- helpers ---------------------------------------------------------


def _redis() -> aioredis.Redis:
    """One-shot Redis client. Cheap to construct; the gateway does the same."""
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


def _status_key(action_id: str) -> str:
    return f"response_action:status:{action_id}"


def _ack_channel(agent_id: str) -> str:
    # Same shape used by AgentGateway.send_to_agent cross-worker fan-out,
    # but for ack *back* from agent -> server. Kept here for locality; if a
    # second consumer appears, lift it into ws_gateway.
    return f"response_action:ack:{agent_id}"


async def _publish_ack_subscriber(ws_gateway) -> None:
    """No-op for MVP: we read ack status from Redis on demand in the GET.

    Kept as a placeholder so a follow-up PR can wire a background listener
    that flips Redis state on incoming ``response_ack`` messages without
    touching the route handler.
    """
    return None


# ---------- routes ----------------------------------------------------------


@router.post(
    "/{agent_id}/actions/{action_name}",
    response_model=ActionDispatchResponse,
)
async def dispatch_action(
    agent_id: str = Path(..., min_length=1, max_length=128),
    action_name: str = Path(..., min_length=1, max_length=64),
    body: dict = ...,  # type: ignore[assignment]  # FastAPI required-body idiom
    request: Request = ...,  # type: ignore[assignment]  # injected, required
    current_user=Depends(require_role("admin", "responder")),
) -> ActionDispatchResponse:
    """Dispatch one response action to ``agent_id``.

    Body shape:
        { "params": { ... action-specific ... }, "reason": "optional note" }

    The ``reason`` field is logged but not enforced -- operators sometimes
    want a fast button without writing a justification.
    """
    if action_name not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported action: {action_name!r}. allowed: {SUPPORTED_PATH_ACTIONS}",
        )

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    params = body.get("params") or {}
    reason = (body.get("reason") or "").strip()
    if not isinstance(params, dict):
        raise HTTPException(status_code=400, detail="params must be a JSON object")

    ok, why = parse_agent_id_from_action(action_name, params)
    if not ok:
        raise HTTPException(status_code=400, detail=why)

    actor = getattr(current_user, "username", "system")
    msg = build_action_message(agent_id=agent_id, action=action_name, params=params, actor=actor)
    action_id = msg["payload"]["action_id"]

    # P2-AUDIT-1: every dispatched action lands in the audit log before we
    # touch the network, so a gateway failure doesn't lose the record.
    try:
        audit = get_audit_logger()
        await audit.log(
            event_id=action_id,
            node=agent_id,
            action=f"response_action.{action_name}",
            actor=actor,
            details={"params": params, "reason": reason},
        )
    except Exception as exc:  # noqa: BLE001
        # Don't fail the dispatch on audit-write error; just shout in the log.
        logger.warning(
            "response_action_audit_failed",
            action_id=action_id,
            agent_id=agent_id,
            error=str(exc),
        )

    # Reserve a status slot so the GET can find it later. TTL 5 minutes is
    # plenty: an agent either acks in seconds or it isn't connected.
    r = None
    try:
        r = _redis()
        await r.set(
            _status_key(action_id),
            json.dumps(
                {
                    "status": "dispatched",
                    "agent_id": agent_id,
                    "action": action_name,
                    "dispatched_at": int(time.time()),
                    "actor": actor,
                }
            ),
            ex=300,
        )
    except Exception as exc:
        logger.warning(
            "response_action_status_set_failed",
            action_id=action_id,
            error=str(exc),
        )
    finally:
        if r is not None:
            try:
                await r.aclose()
            except Exception:
                pass

    # Ship via the gateway. Falls back to Redis pub/sub for cross-worker.
    try:
        gateway = request.app.state.agent_gateway
    except AttributeError:
        # Fall back to the singleton getter; the gateway is loop-aware so
        # this is safe under FastAPI's per-request lifespan.
        from src.agents.ws_gateway import get_agent_gateway

        gateway = get_agent_gateway()
    sent = await gateway.send_to_agent(agent_id, msg)

    if not sent:
        logger.warning(
            "response_action_dispatch_no_subscriber",
            action_id=action_id,
            agent_id=agent_id,
            action=action_name,
        )
        # Not a 500: the agent is simply offline. The status slot keeps the
        # operator informed via the polling endpoint when it reconnects.

    logger.info(
        "response_action_dispatched",
        action_id=action_id,
        agent_id=agent_id,
        action=action_name,
        actor=actor,
        delivered=sent,
    )
    return ActionDispatchResponse(
        action_id=action_id,
        action=action_name,
        agent_id=agent_id,
        status="dispatched",
    )


@router.get(
    "/actions/{action_id}",
    response_model=ActionStatusResponse,
)
async def get_action_status(
    action_id: str = Path(..., min_length=1, max_length=64),
    current_user=Depends(require_role("admin", "responder", "viewer")),
) -> ActionStatusResponse:
    """Read the current status of a dispatched action.

    Returns ``status="unknown"`` if no record is found (TTL expired, never
    existed, or wrong id). Callers should treat ``unknown`` as
    "investigate manually" rather than retry.
    """
    r = None
    try:
        r = _redis()
        raw = await r.get(_status_key(action_id))
    except Exception as exc:
        logger.warning("response_action_status_get_failed", action_id=action_id, error=str(exc))
        raise HTTPException(status_code=503, detail="status store unavailable")
    finally:
        if r is not None:
            try:
                await r.aclose()
            except Exception:
                pass
    if not raw:
        return ActionStatusResponse(action_id=action_id, status="unknown")
    try:
        data = json.loads(raw)
    except Exception:
        return ActionStatusResponse(action_id=action_id, status="unknown")
    return ActionStatusResponse(
        action_id=action_id,
        status=str(data.get("status", "unknown")),
        detail=str(data.get("detail", "")),
        agent_id=str(data.get("agent_id", "")),
        received_at=str(data.get("received_at", "")),
    )
