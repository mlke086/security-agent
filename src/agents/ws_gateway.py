"""WebSocket gateway for agent communication."""

import asyncio
import json
import os
import socket
import uuid
from datetime import UTC, datetime
from typing import Literal, cast

import redis.asyncio as aioredis
from fastapi import WebSocket

from src.agents.manager import heartbeat as process_heartbeat
from src.agents.manager import register_online
from src.agents.models import ScanModule, ScanResult, VulnFinding
from src.agents.signing import sign_message
from src.agents.store import get_vulnscan_store
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_worker_id = os.environ.get("HOSTNAME", socket.gethostname())

_conns: dict[str, WebSocket] = {}


class AgentGateway:
    # P1 (F4) -- agent_ids revoked by the server until the next reconnect.
    # Used by `authenticate` so a WS that was already open at revocation
    # time cannot continue to push commands under the old credentials.
    def __init__(self) -> None:
        self._revoked_conns: set[str] = set()

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
        if agent_id in self._revoked_conns:
            logger.warning("agent_auth_failed_revoked_locally", agent_id=agent_id)
            return False

        # Local import to avoid a circular import with src.agents.manager.
        from src.agents.enroll import validate_agent_token

        try:
            return await validate_agent_token(agent_id, token)
        except Exception as exc:
            logger.warning("auth_pg_lookup_failed", agent_id=agent_id, error=str(exc))
            return False

    async def drop_revoked_connection(self, agent_id: str) -> None:
        """Close the local WebSocket for ``agent_id`` if we still hold it."""
        self._revoked_conns.add(agent_id)
        ws = _conns.pop(agent_id, None)
        if ws is not None:
            try:
                await ws.close(code=1011, reason="server_revoked")
            except Exception:
                pass

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
        # Keepalive: 濮?30s 閸欐垵绨查悽銊ョ湴濞戝牊浼呴敍宀冾唨 agent 閻?ReadMessage 鏉╂柨娲栭獮鍫曞櫢缂?
        # read deadline閵嗗倷鎱ㄦ径?read-deadline 娑撳骸绺剧捄鍐插暱缁愪浇鍤ф０鎴犵畳闁插秷绻?閸涙垝鎶ゆ稉銏犮亼閿?
        # agent 鐠?read deadline 濡偓濞村顒存潻鐐村复閿涘奔绲鹃崥搴ｎ伂娑撳秴褰傚☉鍫熶紖閺?deadline 閸掔増婀￠柌宥堢箾閿?
        # 閹澘銈介柨娆掔箖娑撳褰傞惃?rule_update/scan_command閵嗕看eepalive 娣囨繃妞跨拋?agent 缁嬪啿鐣鹃崷銊у殠閵?
        ws.state._keepalive_task = asyncio.create_task(
            self._keepalive_loop(ws, agent_id),
            name=f"keepalive-{agent_id}",
        )
        logger.info("agent_connected", agent_id=agent_id, worker=self.worker_id)

    async def _keepalive_loop(self, ws: WebSocket, agent_id: str) -> None:
        """濮?30s 閸?keepalive 鎼存梻鏁ょ仦鍌涚Х閹垽绱欓棃鐐存櫛閹扮喎鎳℃禒銈忕礉閺冪娀娓剁粵鎯ф倳閿涘鈧?

        agent 閺€璺哄煂閸?handleMessage 鏉╂柨娲栭妴涓積adMessage 瀵邦亞骞嗛柌宥嗘煀 SetReadDeadline閿?
        娴犲氦鈧奔绗夋导姘礈 deadline 閸掔増婀￠柌宥堢箾閵嗗倽绻涢幒銉︽焽瀵偓閺?send_json 閹舵稑绱撶敮闈╃礉瀵邦亞骞嗛柅鈧崙鎭掆偓?
        """
        try:
            while True:
                await asyncio.sleep(30)
                try:
                    await ws.send_json(
                        {
                            "v": 1,
                            "type": "keepalive",
                            "ts": datetime.now(UTC).isoformat(),
                        }
                    )
                except Exception:
                    break  # 鏉╃偞甯村鍙夋焽
        except asyncio.CancelledError:
            pass

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
        keepalive = getattr(ws.state, "_keepalive_task", None)
        if keepalive:
            keepalive.cancel()
            try:
                await keepalive
            except (asyncio.CancelledError, Exception):
                pass
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
                        "pubsub_forward_failed",
                        agent_id=agent_id,
                        error=str(exc),
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("pubsub_consumer_crashed", agent_id=agent_id, error=str(exc))

    async def handle_message(self, ws: WebSocket, raw: str) -> None:
        """Dispatch incoming agent message by type.

        Each branch is isolated so a failure processing one message (e.g. a
        malformed scan_result) never tears down the whole agent connection.
        The WS receive loop in main.py treats any exception raised here as
        fatal and disconnects the agent, so we swallow handler errors with a
        warning instead -- one bad payload must not cost an agent its socket.
        """
        agent_id: str = getattr(ws.state, "_agent_id", "?")
        try:
            msg: dict = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("invalid_agent_message", agent_id=agent_id, raw=raw[:100])
            return

        msg_type = msg.get("type", "")
        payload = msg.get("payload", {}) or {}

        try:
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
                try:
                    from src.agents.upgrade import record_upgrade_ack

                    await record_upgrade_ack(agent_id, payload)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "update_ack_handler_failed",
                        agent_id=agent_id,
                        error=str(exc),
                    )
            else:
                logger.debug("unknown_agent_msg_type", type=msg_type, agent_id=agent_id)
        except Exception as exc:
            logger.warning(
                "agent_msg_handler_failed",
                agent_id=agent_id,
                msg_type=msg_type,
                error=str(exc),
            )

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

        r = None
        try:
            r = self._redis()
            subscribers = await r.publish(
                f"agent:cmd:{agent_id}", json.dumps(msg, ensure_ascii=False)
            )
            return int(subscribers or 0) > 0
        except Exception as exc:
            logger.warning("redis_publish_failed", agent_id=agent_id, error=str(exc))
            return False
        finally:
            if r is not None:
                await r.aclose()

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
        """Persist scan result and publish progress.

        The agent sends findings in its own ``scan.Finding`` shape
        (category/cve/name/severity/evidence/fix/match_type/tags) -- it does
        NOT carry the server-side ``VulnFinding`` fields (finding_id/task_id/
        agent_id/hostname/fix_advice). We adapt each raw finding here, filling
        those in from the envelope.

        Each finding is coerced individually so one malformed entry drops only
        itself; saving is wrapped so an ES hiccup never bubbles up either.
        Previously ``ScanResult(findings=raw)`` raised a pydantic ValidationError
        (agent findings miss the required VulnFinding fields), which propagated
        through ``handle_message`` into the receive loop and disconnected the
        agent -- the scan_result was lost and ES stayed empty.
        """
        task_id = payload.get("task_id", "")
        hostname = payload.get("hostname", "")
        store = get_vulnscan_store()
        task = await store.get_task(task_id) if task_id else None
        if task is not None and task.status == "cancelled":
            logger.info(
                "late_scan_result_ignored",
                agent_id=agent_id,
                task_id=task_id,
            )
            return
        raw_findings = payload.get("findings") or []
        findings: list[VulnFinding] = []
        for idx, f in enumerate(raw_findings):
            if not isinstance(f, dict):
                logger.warning(
                    "scan_result_finding_not_dict",
                    agent_id=agent_id,
                    task_id=task_id,
                    idx=idx,
                )
                continue
            try:
                findings.append(self._coerce_finding(f, agent_id, task_id, hostname))
            except Exception as exc:
                logger.warning(
                    "scan_result_finding_invalid",
                    agent_id=agent_id,
                    task_id=task_id,
                    idx=idx,
                    error=str(exc),
                )

        try:
            result = ScanResult(
                task_id=task_id,
                agent_id=agent_id,
                hostname=hostname,
                findings=findings,
                batch=payload.get("batch", 0),
                is_final=payload.get("is_final", False),
                ts=payload.get("ts") or datetime.now(UTC).isoformat(),
            )
            await store.save_result(result)
        except Exception as exc:
            logger.warning(
                "scan_result_save_failed",
                agent_id=agent_id,
                task_id=task_id,
                error=str(exc),
            )
            return

        self._pub_task_progress(payload)

    @staticmethod
    def _coerce_finding(
        f: dict,
        agent_id: str,
        task_id: str,
        hostname: str,
    ) -> VulnFinding:
        """Adapt an agent ``scan.Finding`` dict to a server-side ``VulnFinding``.

        Fills server-side fields the agent does not know (finding_id/task_id/
        agent_id/hostname) and maps ``fix`` -> ``fix_advice``. Severity and
        category are normalised to the VulnFinding Literals so a stray value in
        a rule file degrades to ``info`` / ``sys_vuln`` instead of rejecting
        the whole finding.
        """
        sev = str(f.get("severity", "info")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        cat = str(f.get("category", "sys_vuln"))
        if cat not in ("sys_vuln", "baseline"):
            cat = "sys_vuln"
        return VulnFinding(
            finding_id=f.get("finding_id") or str(uuid.uuid4()),
            task_id=f.get("task_id") or task_id,
            agent_id=f.get("agent_id") or agent_id,
            hostname=f.get("hostname") or hostname,
            category=ScanModule(cat),
            cve=f.get("cve") or None,
            name=f.get("name") or "",
            severity=cast(Literal["critical", "high", "medium", "low", "info"], sev),
            evidence=f.get("evidence", ""),
            fix_advice=f.get("fix_advice") or f.get("fix") or None,
            detected_at=f.get("detected_at", ""),
        )


_gateway: AgentGateway | None = None


def get_agent_gateway() -> AgentGateway:
    global _gateway
    if _gateway is None:
        _gateway = AgentGateway()
    return _gateway
