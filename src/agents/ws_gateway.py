"""WebSocket gateway for agent communication."""
import asyncio
import json
import os
import socket
from datetime import UTC, datetime

import redis.asyncio as aioredis
from fastapi import WebSocket

from src.agents.manager import heartbeat as process_heartbeat
from src.agents.manager import register_online
from src.agents.models import ScanResult
from src.agents.signing import sign_message
from src.agents.store import get_vulnscan_store
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_worker_id = os.environ.get("HOSTNAME", socket.gethostname())

_conns: dict[str, WebSocket] = {}


class AgentGateway:
    """Manages persistent WebSocket connections to agents with multi-worker routing."""

    @property
    def worker_id(self) -> str:
        return _worker_id

    def _redis(self) -> aioredis.Redis:
        return aioredis.from_url(get_settings().redis_url, decode_responses=True)

    async def authenticate(self, agent_id: str, token: str) -> bool:
        """Validate agent_token against PG (agent_tokens.token_hash).

        Tokens are stored as SHA-256 hashes by `register_enroll_token` in PG.
        We intentionally avoid using a Redis cache here because the only writer
        of those keys was missing -- reading from Redis always returned None and
        blocked every agent connection (P0-VS-1).
        """
        if not agent_id or not token:
            return False
        # Local import to avoid a circular import with src.agents.manager.
        from src.agents.enroll import validate_agent_token
        try:
            return await validate_agent_token(agent_id, token)
        except Exception as exc:
            logger.warning("auth_pg_lookup_failed", agent_id=agent_id, error=str(exc))
            return False

    async def connect(self, ws: WebSocket, agent_id: str) -> None:
        """Register connection and mark agent online.

        P1-VS-7: previously we subscribed to ``agent:cmd:{agent_id}`` and stored
        the pubsub object on ws.state, but no task ever consumed it. Cross-worker
        routing via ``redis.publish`` therefore never reached the agent. We now
        start a long-running consumer task that pushes every message back into the
        local ``_conns`` map; the handle loop keeps forwarding agent traffic.
        """
        await ws.accept()
        _conns[agent_id] = ws
        await register_online(agent_id, self.worker_id)
        pubsub = self._redis().pubsub()
        await pubsub.subscribe(f"agent:cmd:{agent_id}")
        ws.state._pubsub = pubsub
        ws.state._agent_id = agent_id
        ws.state._pubsub_task = asyncio.create_task(
            self._pubsub_consumer(agent_id, pubsub),
            name=f"pubsub-{agent_id}",
        )
        logger.info("agent_connected", agent_id=agent_id, worker=self.worker_id)

    async def disconnect(self, ws: WebSocket) -> None:
        """Clean up connection."""
        agent_id: str = getattr(ws.state, "_agent_id", "")
        if agent_id:
            _conns.pop(agent_id, None)
            r = self._redis()
            await r.delete(f"agent:conn:{agent_id}")
            logger.info("agent_disconnected", agent_id=agent_id)
        pubsub = getattr(ws.state, "_pubsub", None)
        if pubsub:
            await pubsub.unsubscribe()
        consumer = getattr(ws.state, "_pubsub_task", None)
        if consumer:
            consumer.cancel()
            try:
                await consumer
            except (asyncio.CancelledError, Exception):
                pass

    async def _pubsub_consumer(self, agent_id: str, pubsub) -> None:
        """Forward cross-worker commands published on ``agent:cmd:{agent_id}`` to the
        local WebSocket. Without this loop, the message published by another worker
        for an agent connected to *this* worker would be silently dropped (P1-VS-7).
        """
        try:
            async for raw in pubsub.listen():
                if raw is None or raw.get("type") != "message":
                    continue
                ws = _conns.get(agent_id)
                if not ws:
                    # Agent disconnected on this worker -- nothing to forward.
                    continue
                try:
                    payload = raw.get("data")
                    if isinstance(payload, bytes):
                        payload = payload.decode("utf-8", "replace")
                    await ws.send_text(payload)
                except Exception as exc:
                    logger.warning(
                        "pubsub_forward_failed", agent_id=agent_id, error=str(exc),
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("pubsub_consumer_crashed", agent_id=agent_id, error=str(exc))

    async def handle_message(self, ws: WebSocket, raw: str) -> None:
        """Dispatch incoming agent message by type."""
        agent_id: str = getattr(ws.state, "_agent_id", "?")
        try:
            msg: dict = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("invalid_agent_message", agent_id=agent_id, raw=raw[:100])
            return

        msg_type = msg.get("type", "")
        payload = msg.get("payload", {})

        if msg_type == "heartbeat":
            await process_heartbeat(agent_id, payload)
        elif msg_type == "scan_step":
            self._pub_task_progress(payload)
        elif msg_type == "scan_result":
            await self._handle_scan_result(agent_id, payload)
        elif msg_type == "task_ack":
            self._pub_task_progress(payload)
        elif msg_type == "update_ack":
            logger.info("update_ack", agent_id=agent_id, payload=payload)
        else:
            logger.debug("unknown_agent_msg_type", type=msg_type, agent_id=agent_id)

    async def send_to_agent(self, agent_id: str, msg: dict) -> bool:
        """Send a message to an agent. Sensitive commands are signed before sending."""
        msg = sign_message(msg)
        ws = _conns.get(agent_id)
        if ws:
            try:
                await ws.send_json(msg)
                return True
            except Exception as exc:
                logger.warning("ws_send_failed", agent_id=agent_id, error=str(exc))
                return False

        try:
            r = self._redis()
            await r.publish(f"agent:cmd:{agent_id}", json.dumps(msg, ensure_ascii=False))
        except Exception as exc:
            logger.warning("redis_publish_failed", agent_id=agent_id, error=str(exc))

        return False

    async def broadcast(self, agent_ids: list[str], msg: dict) -> dict:
        """Send a message to multiple agents. Returns {sent, failed}."""
        result = {"sent": 0, "failed": 0}
        for aid in agent_ids:
            ok = await self.send_to_agent(aid, msg)
            if ok:
                result["sent"] += 1
            else:
                result["failed"] += 1
        return result

    def _pub_task_progress(self, payload: dict) -> None:
        """Publish task progress to Redis for SSE subscribers."""
        try:
            task_id = payload.get("task_id", "")
            if task_id:
                import asyncio
                asyncio.create_task(self._pub_async(task_id, payload))
        except Exception:
            pass

    async def _pub_async(self, task_id: str, payload: dict) -> None:
        try:
            r = self._redis()
            await r.publish(f"vulnscan:task:{task_id}", json.dumps(payload, ensure_ascii=False))
        except Exception:
            pass

    async def _handle_scan_result(self, agent_id: str, payload: dict) -> None:
        """Persist scan result and publish progress."""
        store = get_vulnscan_store()
        result = ScanResult(
            task_id=payload.get("task_id", ""),
            agent_id=agent_id,
            hostname=payload.get("hostname", ""),
            findings=payload.get("findings", []),
            batch=payload.get("batch", 0),
            is_final=payload.get("is_final", False),
            ts=payload.get("ts", datetime.now(UTC).isoformat()),
        )
        await store.save_result(result)
        self._pub_task_progress(payload)


_gateway: AgentGateway | None = None


def get_agent_gateway() -> AgentGateway:
    global _gateway
    if _gateway is None:
        _gateway = AgentGateway()
    return _gateway
