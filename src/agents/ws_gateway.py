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
from src.common.channels import vulnscan_task_channel
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_worker_id = os.environ.get("HOSTNAME", socket.gethostname())

_conns: dict[str, WebSocket] = {}

# V12 阶段 5.6 (2026-08-02): shared lazy redis client -- the old per-call
# _redis() leaked one connection per scan_result publish.
_redis_client = None


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        from src.common.config.settings import get_settings

        _redis_client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


# V10 1.2: fire-and-forget task set. asyncio.create_task() returns
# a Task that may be garbage-collected mid-execution if no strong
# reference exists; CPython warns about this in the docs. We keep
# a module-level set of background tasks and discard the entry
# from inside the task itself once it finishes, mirroring the
# pattern used in users._audit.
_BG_TASKS: set = set()


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
        # V12 阶段 5.6 (2026-08-02): scan_result publish + pubsub used to
        # create a fresh client per call; the publish path never closed it.
        # Share one module-level client (safe for publish; pubsub consumers
        # hold their own subscription object on the same connection pool).
        return _get_redis()

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
        """Close the local WebSocket for ``agent_id`` if we still hold it.

        Before tearing down the connection we push a signed ``agent_shutdown``
        command so the agent can gracefully stop its process (systemd unit,
        cleanup, etc.). If the WS is already dead we skip the send -- the
        agent will naturally exit when the root context is cancelled by the
        OS service manager, but that could take until the next restart cycle.
        """
        self._revoked_conns.add(agent_id)
        ws = _conns.pop(agent_id, None)
        if ws is not None:
            try:
                shutdown_msg = {
                    "v": 1,
                    "type": "agent_shutdown",
                    "ts": datetime.now(UTC).isoformat(),
                    "payload": {"reason": "server_revoked"},
                }
                signed = sign_message(shutdown_msg)
                await ws.send_json(signed)
            except Exception:
                pass
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
        await self._deliver_pending(agent_id, ws)

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
        if agent_id and _conns.get(agent_id) is ws:
            # A stale connection may finish disconnecting after the same Agent
            # has already reconnected. Only the connection that still owns the
            # slot may clear routing state; otherwise it would orphan the new
            # WebSocket while leaving its Redis subscription alive.
            _conns.pop(agent_id, None)
            r = self._redis()
            # V13 P1-1: shared redis client is process-lifetime; do NOT aclose().
            if await r.get(f"agent:conn:{agent_id}") == self.worker_id:
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
            elif msg_type == "response_ack":
                # Phase 4: agent confirmed (or rejected) a response_action.
                # Persist the outcome to the same Redis status key the
                # router set on dispatch so the operator can poll
                # GET /api/v1/agents/actions/{action_id}.
                await self._record_response_ack(agent_id, payload)
            elif msg_type == "monitor_event":
                # Phase 5: lightweight host monitor (process / file
                # snapshots). Best-effort persist to ES; a failure
                # here never tears down the agent connection.
                await self._record_monitor_event(agent_id, payload)
            elif msg_type == "host_metrics":
                # 需求①: host_metrics 性能时序。与 monitor_event 同样
                # best-effort（fire-and-forget 写入 ES，失败仅 log），
                # 高频消息绝不能因存储抖动拖垮 WS 连接。
                await self._record_host_metrics(agent_id, payload)
            else:
                logger.debug("unknown_agent_msg_type", type=msg_type, agent_id=agent_id)
        except Exception as exc:
            logger.warning(
                "agent_msg_handler_failed",
                agent_id=agent_id,
                msg_type=msg_type,
                error=str(exc),
            )

    async def _deliver_pending(self, agent_id: str, ws: WebSocket) -> None:
        """Deliver the latest command queued while the Agent was offline.

        V9 4.6 + V10 4.2 (2026-07-30): the producer
        (send_to_agent) stores at most one pending command per
        agent (24h TTL); the consumer reads + deletes it in a
        single round-trip. If the WS send succeeds but the DELETE
        fails, the next reconnect will replay the same command --
        so the current contract is ``trust the producer to send
        idempotent payloads``; we do not yet stamp a ``msg["seq"]``
        for the agent to dedupe, see follow-up issue #V10-4.2-seq
        (out of scope for this PR; tracked separately).
        """
        r = self._redis()
        key = f"agent:pending_cmd:{agent_id}"
        try:
            raw = await r.get(key)
            if not raw:
                return
            # send_text requires str; redis may return bytes if the client was
            # created without decode_responses.
            await ws.send_text(raw.decode() if isinstance(raw, bytes) else raw)
            await r.delete(key)
            logger.info("pending_agent_command_delivered", agent_id=agent_id)
        except Exception as exc:
            logger.warning(
                "pending_agent_command_delivery_failed", agent_id=agent_id, error=str(exc)
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
            owner = await r.get(f"agent:conn:{agent_id}")
            delivered = int(subscribers or 0) > 0 and bool(owner)
            if not delivered:
                await r.set(
                    f"agent:pending_cmd:{agent_id}",
                    json.dumps(msg, ensure_ascii=False),
                    ex=24 * 3600,
                )
            return delivered
        except Exception as exc:
            logger.warning("redis_publish_failed", agent_id=agent_id, error=str(exc))
            return False

    async def _record_response_ack(self, agent_id: str, payload: dict) -> None:
        """Mirror a response_ack to the per-action Redis status key.

        The router writes status=dispatched with a 5-minute TTL on
        POST; we refresh the same key with the ack outcome so the
        operator GET sees succeeded/failed within seconds.
        """
        import time

        action_id = str(payload.get("action_id", ""))
        if not action_id:
            logger.warning("response_ack_missing_action_id", agent_id=agent_id, payload=payload)
            return
        ok = bool(payload.get("ok", False))
        detail = str(payload.get("detail", ""))
        new_status = "succeeded" if ok else "failed"
        record = {
            "status": new_status,
            "agent_id": agent_id,
            "detail": detail,
            "received_at": int(time.time()),
        }
        r = None
        try:
            r = self._redis()
            await r.set(
                f"response_action:status:{action_id}",
                json.dumps(record, ensure_ascii=False),
                ex=300,
            )
        except Exception as exc:
            logger.warning(
                "response_ack_persist_failed",
                action_id=action_id,
                agent_id=agent_id,
                error=str(exc),
            )
        logger.info(
            "response_ack_recorded",
            action_id=action_id,
            agent_id=agent_id,
            status=new_status,
            detail=detail,
        )

    async def _record_monitor_event(self, agent_id: str, payload: dict) -> None:
        """Persist a monitor_event to the ES index.

        We do not validate the payload here -- the agent is the only
        source of truth for the Snapshot schema, and the Sigma
        detector consumes the live shape. Bad payloads are visible
        immediately in the console (the drawer renders empty or
        partial data) and a future monitor_schema_version field can
        gate upgrades without code on this side.
        """
        try:
            from src.agents.monitor_store import get_monitor_store

            await get_monitor_store().save_event(agent_id, payload)
        except Exception as exc:  # noqa: BLE001
            # ES outage should never cost the agent its socket.
            logger.warning(
                "monitor_event_persist_failed",
                agent_id=agent_id,
                error=str(exc),
            )

    async def _record_host_metrics(self, agent_id: str, payload: dict) -> None:
        """Persist a host_metrics sample to the ES secagent-hostmetrics index.

        需求① (2026-08-06): fire-and-forget like monitor_event -- the agent
        sends every 15s and drops points while disconnected, so a transient
        ES failure only loses the current tick, never the connection.
        hostname rides in the message envelope (agent stamps it at send
        time); agent_id is stamped here from the authenticated connection
        (same trust boundary as scan_result / monitor_event).
        """
        try:
            from src.agents.metrics_store import get_metrics_store

            # hostname 随 payload 上报（与 monitor_event 同约定）；
            # agent_id 由已认证连接盖章。
            hostname = str(payload.get("hostname") or "") if isinstance(payload, dict) else ""
            await get_metrics_store().save_metrics(agent_id, hostname, payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "host_metrics_persist_failed",
                agent_id=agent_id,
                error=str(exc),
            )

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
                # V10 1.2: hold a strong reference via the module-level
                # task set; the task self-removes on completion.
                t = asyncio.create_task(self._pub_async(task_id, payload))
                _BG_TASKS.add(t)
                t.add_done_callback(_BG_TASKS.discard)
        except Exception:
            pass

    async def _pub_async(self, task_id: str, payload: dict) -> None:
        try:
            r = self._redis()
            await r.publish(vulnscan_task_channel(task_id), json.dumps(payload, ensure_ascii=False))
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
                # 2026-07-31 UX upgrade: modules this agent actually completed
                # (from the is_final result). Empty for legacy agents -> the
                # aggregate reconcile skips auto-fix for them (conservative).
                scanned_categories=payload.get("scanned_categories") or [],
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
        # V9 5.3 (F6): accept "nuclei" alongside the matcher outputs so
        # Nuclei-sourced findings keep their engine provenance. Any
        # other unexpected value still falls back to sys_vuln rather
        # than being silently dropped.
        if cat not in ("sys_vuln", "baseline", "nuclei"):
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
