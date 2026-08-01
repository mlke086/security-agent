"""VulnScan subgraph node implementations."""

import asyncio
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from src.agents.models import (
    ScanModule,
    ScanPolicy,
    ScanReport,
    ScanTask,
    VulnFilter,
    VulnFinding,
)
from src.agents.store import INDEX_VULNS, detected_sort_key, get_vulnscan_store
from src.agents.ws_gateway import get_agent_gateway
from src.common.audit.audit_logger import get_audit_logger
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# S-P1-1 (V12): shared lazy redis client. Every _pub_progress / collect
# counter / cancellation check used to build + close a connection per call
# (~180 connects per scan task). One module-level client is reused; it is
# safe across workers (redis-py is thread/event-loop safe for publish),
# and each call still tolerates a dead connection via try/except.
_redis_client = None


def _get_redis():
    """Return the shared redis client, lazily created on first use."""
    global _redis_client
    if _redis_client is None:
        import redis.asyncio as aioredis

        from src.common.config.settings import get_settings

        _redis_client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


def _finding_field(f, name: str, default=None):
    """Read a field from a finding that may be a Pydantic VulnFinding model or
    a plain dict.

    state.py types ``collected_findings`` as ``list[dict]`` but aggregate
    returns models, and P1-VULN-GBL (2026-07-31) swapped `.get()` for
    ``getattr()`` -- which silently reads the default on dicts. Reading through
    one helper keeps callers correct regardless of which shape reaches them.
    """
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def _default_state(
    source: str,
    intent_text: str | None = None,
    targets: list[str] | None = None,
    modules: list[str] | None = None,
    task_id: str | None = None,
    engine: str = "matcher",
    nuclei_severity: list[str] | None = None,
    nuclei_tags: list[str] | None = None,
    nuclei_templates: list[str] | None = None,
    nuclei_timeout_sec: int = 0,
    target_groups: list[str] | None = None,
    nuclei_ports: list[int] | None = None,
) -> dict:
    """Build the initial VulnScanState from input params.

    ``task_id`` is taken from the caller when provided so the API can return
    the SAME identifier the subgraph uses (P0-VS-2). When None (e.g. dialog-driven
    scans started from the orchestrator), generate a fresh uuid.

    P0 (2026-07-18): ``engine`` and the nuclei_* knobs are propagated through
    the subgraph state so dispatch() and the WS scan_command payload both
    see them. The agent's engine.go branches on engine=="nuclei".
    """
    task_id = task_id or str(uuid.uuid4())
    return {
        "task_id": task_id,
        "source": source,
        "intent_text": intent_text,
        "targets": targets or [],
        "modules": modules or ["sys_vuln", "baseline"],
        "engine": engine,
        "nuclei_severity": nuclei_severity or [],
        "nuclei_tags": nuclei_tags or [],
        "nuclei_templates": nuclei_templates or [],
        "nuclei_timeout_sec": nuclei_timeout_sec,
        "nuclei_ports": nuclei_ports or [],
        "resource_limit": {"cpu_percent": 30, "mem_percent": 30},
        "target_groups": target_groups or [],
        "schedule": None,
        "task": None,
        "dispatched": False,
        "total_targets": 0,
        "received_results": 0,
        "collected_findings": [],
        "report": None,
        "error": None,
        "status": "queued",
        "messages": [],
    }


async def parse_intent(state: dict) -> dict:
    """Parse natural-language intent into structured scan parameters (dialog source only)."""
    if state["source"] == "manual":
        # Manual scan: targets/modules already set by caller
        return {
            "status": "dispatching",
            "messages": state.get("messages", []),
        }

    # Confirmed dialog intent: the orchestrator already resolved targets (and
    # modules/engine) before starting the subgraph -- re-parsing would just
    # call the LLM again for data we already have.
    if state.get("targets"):
        return {
            "status": "dispatching",
            "messages": state.get("messages", []),
        }

    intent_text = state.get("intent_text", "")
    if not intent_text:
        return {"error": "No intent text provided for dialog source", "status": "failed"}

    # Use LLM to parse intent into structured form
    try:
        from src.agents.models import ScanIntent
        from src.knowledge.models.adapter import get_model_adapter

        adapter = get_model_adapter()
        prompt = f"""You are a security scan assistant. Parse the following user request into a scan intent.
User request: {intent_text}

Return JSON with fields: targets (list of hostnames/IPs/groups), modules (list of sys_vuln/baseline),
resource_limit (dict with cpu_percent/mem_percent), schedule (null for "now" or cron string)."""
        result = await adapter.chat_completion(
            messages=[{"role": "user", "content": prompt}],
            schema=ScanIntent,
        )
        return {
            "targets": result.targets,
            "modules": [str(m) for m in result.modules],
            "resource_limit": result.resource_limit,
            "schedule": result.schedule,
            "status": "dispatching",
        }
    except Exception as exc:
        logger.warning("parse_intent_failed", error=str(exc))
        return {"error": f"Intent parsing failed: {exc}", "status": "failed"}


async def _nuclei_targets_by_agent(agent_ids: list[str]) -> dict[str, list[str]]:
    """Map each agent_id to its managed IP(s) so nuclei has real targets to scan.

    P1-VULN-GLOBAL (2026-07-31): when the operator picks a managed host via
    the "by host" selector, the task carries ``agent_id`` not IP. nuclei's
    ``-u`` flag against ``http://agent-id:*`` only works if the hostname A-
    record-resolves to the right IP -- in practice agent hostnames often
    resolve to IPv6 first and the operator's Elasticsearch lives on IPv4,
    so the scan reports 0 findings despite the service being up. Fix is to
    look up each agent's recorded ``ip`` (the address supplied at enroll
    time) and use that as the nuclei target list.

    Returns ``{agent_id: [ip, ...]}``. Agents without a recorded IP map to
    an empty list; the caller falls back to the original target string so
    nuclei at least tries DNS resolution.
    """
    store = get_vulnscan_store()
    out: dict[str, list[str]] = {}
    for agent_id in agent_ids:
        try:
            host = await store.get_host(agent_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("nuclei_target_lookup_failed", agent_id=agent_id, error=str(exc))
            host = None
        if host and host.ip:
            out[agent_id] = [host.ip]
        else:
            out[agent_id] = []
    return out


async def dispatch(state: dict) -> dict:
    """Create ScanTask in ES, resolve targets to agent_ids, dispatch scan_command via gateway."""

    store = get_vulnscan_store()
    gateway = get_agent_gateway()

    task_id = state["task_id"]
    targets = state["targets"]
    modules = state["modules"]

    if await _is_task_cancelled(task_id):
        return {"status": "cancelled", "dispatched": False, "total_targets": 0}

    # Resolve targets to agent_ids
    agent_ids = await _resolve_targets(targets)

    # Create and save ScanTask
    task = ScanTask(
        task_id=task_id,
        source=state["source"],
        intent_text=state.get("intent_text"),
        targets=agent_ids,
        policy=ScanPolicy(
            modules=state.get("modules", ["sys_vuln", "baseline"]),
            resource_limit=state.get("resource_limit", {}),
        ),
        rule_version="latest",
        engine=state.get("engine", "matcher"),
        nuclei_severity=state.get("nuclei_severity", []),
        nuclei_tags=state.get("nuclei_tags", []),
        nuclei_templates=state.get("nuclei_templates", []),
        nuclei_timeout_sec=state.get("nuclei_timeout_sec", 0),
        nuclei_ports=list(state.get("nuclei_ports") or []),
        status="dispatching",
        created_at=datetime.now(UTC).isoformat(),
        stats={"total": len(agent_ids), "done": 0, "failed": 0},
        target_groups=list(state.get("target_groups") or []),
    )
    await store.save_task(task)

    if not agent_ids:
        # Persist the failure to ES so GET /tasks/{id} sees "failed" instead
        # of sitting on "queued"/"scanning" forever. Without this the linear
        # graph would still run collect, which (total_targets=0) polled ES for
        # the full timeout window before reporting an empty "completed" (P1-VULN-01).
        await store.update_task(
            task_id,
            status="failed",
            error="No target agents found",
            finished_at=datetime.now(UTC).isoformat(),
        )
        logger.warning("scan_dispatch_no_targets", task_id=task_id, targets=targets)
        # F1.3a (2026-07-21): publish the failure to SSE so the operator
        # sees it the next render tick instead of staring at "等待 agent 上报"
        # for 30 minutes.
        await _pub_progress(
            task_id,
            "dispatch",
            "failed",
            f"No online agent matches any of {targets!r}",
        )
        return {
            "error": "No target agents found",
            "status": "failed",
            "task": task,
            "total_targets": 0,
        }

    # Broadcast scan command.
    #
    # The agent's engine.go branches on payload["engine"]:
    #   "matcher" (default) -> own rule-based matcher (legacy)
    #   "nuclei"           -> os/exec wrapper around the nuclei CLI which carries
    #                        the projectdiscovery templates bundle.
    #
    # Nuclei-specific knobs (nuclei_severity / nuclei_tags / nuclei_templates /
    # nuclei_timeout_sec) are only inspected when engine == "nuclei".
    scan_cmd: dict[str, Any] = {
        "v": 1,
        "type": "scan_command",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "task_id": task_id,
            "policy": task.policy.model_dump(),
            "rule_version": "latest",
            "modules": modules,
            "resource_limit": state.get("resource_limit", {}),
            "deadline": "",
            "engine": "matcher" if task.engine == "global" else task.engine,
            "nuclei_targets": task.targets,
            "nuclei_severity": task.nuclei_severity,
            "nuclei_tags": task.nuclei_tags,
            "nuclei_templates": task.nuclei_templates,
            "nuclei_timeout_sec": task.nuclei_timeout_sec,
            "nuclei_ports": task.nuclei_ports,
        },
    }
    # Only matcher/global use a single broadcast -- nuclei needs the
    # resolved per-agent IP, which the broadcast path can't supply, so
    # we send those per-agent below. Skipping the broadcast for nuclei
    # also avoids the duplicate "scanning N ports" we used to see when
    # nuclei_targets was the raw agent_id and DNS resolved to IPv6.
    # S-P1-2 (V12): keep matcher (broadcast) and nuclei (per-agent) delivery
    # counts separate. The old single counter merged both sends, so a failed
    # nuclei push was hidden behind a successful matcher broadcast and the
    # UI could not tell which side dropped targets. Totals are summed for
    # the task stats; the SSE message reports both lanes.
    lanes: dict[str, dict[str, int]] = {
        "matcher": {"sent": 0, "failed": 0},
        "nuclei": {"sent": 0, "failed": 0},
    }
    if task.engine in ("matcher", "global"):
        lanes["matcher"] = await gateway.broadcast(agent_ids, scan_cmd)

    if task.engine in ("nuclei", "global"):
        target_by_agent = await _nuclei_targets_by_agent(agent_ids)
        for agent_id in agent_ids:
            agent_cmd = {
                **scan_cmd,
                "payload": {
                    **scan_cmd["payload"],
                    "engine": "nuclei",
                    "nuclei_targets": target_by_agent.get(agent_id) or targets,
                },
            }
            ok = await gateway.send_to_agent(agent_id, agent_cmd)
            lanes["nuclei"]["sent" if ok else "failed"] += 1

    total_sent = lanes["matcher"]["sent"] + lanes["nuclei"]["sent"]
    total_failed = lanes["matcher"]["failed"] + lanes["nuclei"]["failed"]

    # Update task status
    await store.update_task(
        task_id,
        status="scanning",
        stats={"total": len(agent_ids), "done": total_sent, "failed": total_failed},
    )
    # F1.3b (2026-07-21): publish the broadcast result to SSE so the operator
    # gets instant feedback (sent vs failed counts) instead of waiting until
    # the first agent scan_step lands -- which never happens for typos like
    # "host-a" where no agent is listening on agent:cmd:host-a.
    lane_summary = "; ".join(
        f"{lane} {c['sent']} sent/{c['failed']} failed"
        for lane, c in lanes.items()
        if c["sent"] or c["failed"]
    )
    await _pub_progress(
        task_id,
        "dispatch",
        "running",
        f"Dispatch to {len(agent_ids)} target(s): {lane_summary or 'no lanes'}; "
        f"{total_failed} not reachable",
    )

    # Store collection tracking in Redis (S-P1-1: shared client).
    r = _get_redis()
    await r.hset(
        f"vulnscan:collect:{task_id}",
        mapping={
            "total": str(len(agent_ids)),
            "received": "0",
        },
    )
    # P2-VULN-15 (2026-07-20): always set the TTL so the counter key
    # doesn't linger forever when generate_report fails. Previously the
    # code only expired the key when state["policy"] (a non-existent
    # field) was truthy -- i.e. essentially never. The fallback below
    # uses the saved task's ScanPolicy or the module default.
    ttl = 1800
    task_obj = state.get("task")
    if task_obj is not None and getattr(task_obj, "policy", None) is not None:
        ttl = int(task_obj.policy.timeout_sec or ttl)
    await r.expire(f"vulnscan:collect:{task_id}", ttl)

    logger.info("scan_dispatched", task_id=task_id, target_count=len(agent_ids))
    return {
        "task": task,
        "dispatched": True,
        "total_targets": len(agent_ids),
        "received_results": total_sent,
        "status": "scanning",
    }


async def _resolve_targets(targets: list[str]) -> list[str]:
    """Resolve target names (hostname/IP/group) to agent_ids.

    A group target expands to EVERY online agent in that group (not just the
    first match) -- otherwise scanning "prod" with 10 agents would silently
    cover only 1 host (P1-VULN-02). agent_id / hostname / IP are unique, so
    they match at most one host. Results are de-duplicated because a host can
    be hit by several targets at once (e.g. its agent_id AND its group).
    """
    store = get_vulnscan_store()
    all_hosts = await store.list_hosts(status="online", limit=1000)

    resolved: list[str] = []
    seen: set[str] = set()
    matched_any = False

    def _add(agent_id: str) -> None:
        nonlocal matched_any
        if agent_id and agent_id not in seen:
            seen.add(agent_id)
            resolved.append(agent_id)
            matched_any = True

    for target in targets:
        for h in all_hosts:
            # agent_id / hostname / ip are unique -- single match is correct.
            if h.agent_id == target or h.hostname == target or h.ip == target:
                _add(h.agent_id)
                break
            # group is NOT unique -- collect every host in the group. Do NOT
            # break here: the loop continues to find the remaining members.
            if h.group == target:
                _add(h.agent_id)

    if not matched_any:
        # Nothing matched: either an offline agent_id the operator knows
        # about (genuine pass-through) or a typo / unregistered name. Pass
        # through so dispatch's "no online agent" branch can name the bad
        # target. (F1.1, 2026-07-21: previous fall-through masked the
        # "host-a" case where the user typed a placeholder that no agent
        # ever connects to, causing a silent 30-minute wait.)
        return targets

    # Surface unresolved targets alongside resolved ones -- a partial scan
    # caused by typos ("test" matches group=5 hosts, "host-b" matches none)
    # used to look like success.
    unknown = [
        t
        for t in targets
        if t not in {h.agent_id for h in all_hosts}
        and t not in {h.hostname for h in all_hosts}
        and t not in {h.ip for h in all_hosts}
        and t not in {h.group for h in all_hosts if h.group}
    ]
    if unknown:
        logger.warning("vulnscan_targets_unresolved", resolved=resolved, unknown=unknown)

    return resolved


async def collect(state: dict) -> dict:
    """Wait for agents to report scan results (or timeout).

    P1-VS-3: previously this node returned "scanning" immediately after the
    first read. Because the graph was linear, the subgraph walked past collect
    long before any agent had finished scanning -- reports were always empty.
    We now poll ES for ``is_final`` batches with a bounded wait bounded by
    ``ScanPolicy.timeout_sec``. When the deadline passes we proceed with the
    partial results so we never deadlock the orchestrator.

    P1-VULN-01: if dispatch already failed (no target agents, or zero targets),
    short-circuit here -- do NOT poll ES for 30 minutes. The failure status is
    already persisted by dispatch.
    """
    import asyncio

    task_id = state["task_id"]
    total = state.get("total_targets", 0)
    if state.get("status") == "cancelled" or await _is_task_cancelled(task_id):
        return {"status": "cancelled", "received_results": 0}
    if state.get("status") == "failed" or total == 0:
        return {"status": "failed", "received_results": 0}

    store = get_vulnscan_store()
    total = state.get("total_targets", 0)
    timeout_sec = int((state["task"].policy.timeout_sec or 1800) if state.get("task") else 1800)
    poll_interval = 5  # seconds
    deadline = asyncio.get_running_loop().time() + timeout_sec

    # F1.2 (2026-07-21): the dispatch node updated ES with the *real* failed
    # count (e.g. 1 when the broadcast could not reach any agent) but the
    # in-memory ScanTask object it returns still has stats["failed"]=0 from
    # its constructor. Reading from state["task"].stats used to overwrite the
    # dispatch-time failure back to 0, so collect waited the full timeout.
    # Always re-read fresh stats from ES (the dispatch update is the source
    # of truth) and treat failed as 0 only when truly absent.
    es_task = await store.get_task(task_id)
    failed = es_task.stats.get("failed", 0) if es_task and es_task.stats else 0

    # F1.2 + P1-VULN-GBL2: fail fast when dispatch reported that EVERY target
    # failed to reach an agent (stats.failed >= total). The old
    # ``done_count + failed >= total`` shortcut was removed because it fired on
    # a global scan's first matcher is_final (done=1 + failed=0 >= total=1) and
    # dropped the slower nuclei results; a pure ``failed >= total`` check
    # cannot misfire that way -- it only triggers when dispatch recorded a
    # failure for all targets, so waiting out the 1800s deadline is pointless.
    if total > 0 and failed >= total:
        await store.update_task(task_id, status="analyzing")
        logger.info(
            "vulnscan_collect_all_targets_failed",
            task_id=task_id,
            total=total,
            failed=failed,
        )
        return {"status": "analyzing", "received_results": 0}

    done_count = 0
    while True:
        # S-P1-9 (V12): confirm the tombstone twice before persisting
        # "cancelled". _is_task_cancelled is fail-closed, so a redis blip
        # would otherwise kill a healthy scan mid-collect and orphan the
        # agent-side results. _confirm_cancellation keeps that fail-closed
        # guarantee while filtering out transient dependency blips.
        if await _confirm_cancellation(task_id):
            await store.update_task(
                task_id,
                status="cancelled",
                finished_at=datetime.now(UTC).isoformat(),
            )
            return {"status": "cancelled", "received_results": done_count}
        results = await store.list_results(task_id=task_id)
        is_final_batches = [r for r in results if r.is_final]
        done_count = len(set(r.agent_id for r in is_final_batches))
        # Global scans produce 2 is_final batches per agent (matcher +
        # nuclei). Bump expected so collect waits for the slower engine.
        # Reading from state["task"] keeps the count tied to whatever the
        # dispatch node actually wired up -- matcher/nuclei/global.
        engine = (es_task.engine if es_task else "matcher") or "matcher"
        expected_per_agent = 2 if engine == "global" else 1
        final_batches_required = total * expected_per_agent
        final_received = len(is_final_batches)
        await store.update_task(
            task_id,
            stats={"total": total, "done": done_count, "failed": failed},
        )

        # P1-VULN-GBL2 (2026-07-31): use AND instead of OR with the
        # ``done_count + failed >= total`` shortcut. The shortcut was
        # meant to time out if some agent never reports at all, but it
        # also fired on the very first agent's is_final -- which for
        # global is the fast matcher scan (~3s) -- so the aggregate
        # node ran with only the matcher's findings and the slower
        # nuclei results were dropped. Require the is_final count to
        # reach ``final_batches_required`` (1 per matcher scan, 1 per
        # nuclei scan, 2 per global scan) before transitioning.
        done_complete = total > 0 and final_received >= final_batches_required
        # If we're past the deadline, also accept the partial result so
        # the orchestrator never deadlocks.
        if not done_complete and asyncio.get_running_loop().time() >= deadline:
            done_complete = True
        if done_complete:
            await store.update_task(task_id, status="analyzing")
            return {"status": "analyzing", "received_results": done_count}

        if asyncio.get_running_loop().time() >= deadline:
            logger.warning(
                "vulnscan_collect_timeout",
                task_id=task_id,
                done=done_count,
                total=total,
                failed=failed,
                final_received=final_received,
                final_required=final_batches_required,
                engine=engine,
            )
            await store.update_task(task_id, status="analyzing")
            return {"status": "analyzing", "received_results": done_count}

        await asyncio.sleep(poll_interval)


async def aggregate(state: dict) -> dict:
    """Aggregate findings from all agents, deduplicate, reconcile with stored vulns.

    2026-07-31 UX upgrade ("漏洞清单整理 + 自动更新修复时间"):
    beyond the existing single-task dedup, the collected findings are reconciled
    against previously stored vulns for the same agents so that

    * one host + one vuln keeps a single record: a re-detection updates
      detected_at, rolls the previous detection time into ``scan_history`` and
      re-opens a manually-fixed/accepted vuln;
    * vulns this scan's covered categories no longer report are automatically
      marked ``fixed`` with ``first_fixed_at``/``last_fixed_at`` stamped.

    Category coverage comes from the agent's is_final ``scanned_categories``
    (only modules that actually completed). Legacy agents that omit it are
    skipped conservatively so a module that failed collection is never
    misjudged as "fixed". When ``settings.vuln_merge_enabled`` is off this
    falls back to the legacy plain-save behaviour.
    """
    task_id = state["task_id"]
    store = get_vulnscan_store()
    # S-P1-9 (V12): double-check before propagating a cancellation -- a
    # fail-closed blip here would otherwise flow to generate_report and
    # persist "cancelled" on a healthy task.
    if state.get("status") == "cancelled" or await _confirm_cancellation(task_id):
        return {"collected_findings": [], "status": "cancelled"}

    # Read all scan results for this task
    results = await store.list_results(task_id=task_id)

    # Dedup across all results (list_results is ts-ascending, so the first
    # occurrence of a key is the earliest batch; we keep it) while remembering
    # the batch timestamp for the detected_at fallback below.
    first_by_key: dict[tuple, tuple[VulnFinding, str]] = {}
    for result in results:
        ts = result.ts or ""
        for f in result.findings:
            key = (f.agent_id, f.cve or "", f.name)
            if key not in first_by_key:
                first_by_key[key] = (f, ts)
    findings = [pair[0] for pair in first_by_key.values()]

    from src.common.config.settings import get_settings

    if not get_settings().vuln_merge_enabled or not results:
        # Rollback / trivial path: legacy behaviour.
        if findings:
            await store.save_vulns(findings)
        logger.info("aggregated_findings", task_id=task_id, count=len(findings))
        return {
            "collected_findings": findings,
            "status": "analyzing",
        }

    now_iso = datetime.now(UTC).isoformat()

    # Per-agent set of categories this scan actually covered, from the is_final
    # scanned_categories. Empty for legacy agents -> auto-fix skipped.
    coverage: dict[str, set[str]] = defaultdict(set)
    for result in results:
        if result.scanned_categories:
            coverage[result.agent_id] |= set(result.scanned_categories)

    # Pull the current vuln set for this task's agents. Spec-P1-RECON
    # (V12): list_vulns_all scrolls with search_after so a >10k vuln set
    # is not silently truncated -- a truncated fetch would re-create
    # duplicates on every scan and never auto-fix the older findings.
    existing = await store.list_vulns_all(
        VulnFilter(agent_ids=[r.agent_id for r in results], limit=1000)
    )

    # Index existing vulns by identity key, keeping the newest copy per key
    # (list_vulns sorts detected_at desc) and queueing older copies for delete
    # -- this self-heals legacy cross-scan duplicates. Also collect every
    # detection time per key so a deleted duplicate's timestamp still lands in
    # scan_history instead of being lost.
    existing_by_key: dict[tuple, VulnFinding] = {}
    existing_times: dict[tuple, list[str]] = defaultdict(list)
    dup_ids: set[str] = set()
    for v in existing:
        key = (v.agent_id, v.cve or "", v.name)
        if v.detected_at:
            existing_times[key].append(v.detected_at)
        cur = existing_by_key.get(key)
        if cur is None or (v.detected_at or "") > (cur.detected_at or ""):
            if cur is not None:
                dup_ids.add(cur.finding_id)
            existing_by_key[key] = v
        else:
            dup_ids.add(v.finding_id)

    actions: list[dict] = []
    merged: list[VulnFinding] = []
    new_keys: set[tuple] = set()
    for key, (f, ts) in first_by_key.items():
        new_keys.add(key)
        # ES detected_at is a date type: empty strings fail indexing, so
        # fall back to the batch timestamp / now.
        detected_at = f.detected_at or ts or now_iso
        f.detected_at = detected_at

        ex = existing_by_key.get(key)
        if ex is not None:
            # Same host+vuln already exists: update the stored record in
            # place (partial doc -- ai_* and fix timestamps are left alone
            # until llm_analysis overwrites them this task), roll every prior
            # detection time (the canonical's scan_history + all same-key docs'
            # detected_at, so a deleted duplicate's timestamp survives) into
            # scan_history, and re-open the vuln.
            hist = list(ex.scan_history or [])
            hist.extend(existing_times.get(key, []))
            hist = [t for t in hist if t != detected_at]  # current scan not "history"
            hist = list(dict.fromkeys(hist))  # dedupe
            hist.sort(key=detected_sort_key)  # ascending
            # V12 5.7 (2026-08-02): do NOT overwrite task_id with the current
            # task -- the ORIGINAL owner keeps the record (its monitor page
            # must still see the vuln). Record the latest confirming scan in
            # last_seen_task_id; the query layer matches either.
            actions.append(
                {
                    "_op_type": "update",
                    "_index": INDEX_VULNS,
                    "_id": ex.finding_id,
                    "doc": {
                        "agent_id": f.agent_id,
                        "hostname": f.hostname,
                        "category": f.category.value,
                        "cve": f.cve,
                        "name": f.name,
                        "severity": f.severity,
                        "evidence": f.evidence,
                        "fix_advice": f.fix_advice,
                        "detected_at": detected_at,
                        "status": "open",
                        "scan_history": hist,
                        "last_seen_task_id": f.task_id,
                    },
                }
            )
            # Key: point llm_analysis / generate_report at the record that
            # actually survived, not a new random UUID.
            f.finding_id = ex.finding_id
        else:
            actions.append(
                {
                    "_op_type": "index",
                    "_index": INDEX_VULNS,
                    "_id": f.finding_id,
                    "_source": f.model_dump(),
                }
            )
        merged.append(f)

    # Auto-fix: an open vuln in a covered category that this scan no longer
    # reported is considered fixed. Only status=open is touched -- manual
    # fixed/accepted decisions are never silently overridden, and agents
    # without coverage info are skipped (conservative).
    auto_fixed: list[str] = []
    for v in existing:
        key = (v.agent_id, v.cve or "", v.name)
        if v.status != "open" or key in new_keys:
            continue
        cov = coverage.get(v.agent_id)
        if not cov or v.category.value not in cov:
            continue
        actions.append(
            {
                "_op_type": "update",
                "_index": INDEX_VULNS,
                "_id": v.finding_id,
                "doc": {
                    "status": "fixed",
                    "first_fixed_at": v.first_fixed_at or now_iso,
                    "last_fixed_at": now_iso,
                },
            }
        )
        auto_fixed.append(v.finding_id)

    # Delete same-key legacy duplicates (self-heal).
    for fid in dup_ids:
        actions.append({"_op_type": "delete", "_index": INDEX_VULNS, "_id": fid})

    if actions:
        await store.bulk_update_vulns(actions)

    if auto_fixed:
        # One summary audit entry per task instead of one per finding, so a
        # 1000-vuln host does not flood the audit log.
        await get_audit_logger().log(
            event_id=task_id,
            node="vulnscan.subgraph",
            action="auto_fix",
            details={
                "task_id": task_id,
                "count": len(auto_fixed),
                "finding_ids": auto_fixed,
            },
        )

    logger.info(
        "aggregated_findings",
        task_id=task_id,
        count=len(merged),
        merged=len(existing_by_key),
        auto_fixed=len(auto_fixed),
        deleted_duplicates=len(dup_ids),
    )
    return {
        "collected_findings": merged,
        "status": "analyzing",
    }


async def _write_fallback(
    findings: list,
    reason: str,
    now_iso: str | None = None,
) -> None:
    """Mark every finding as not-AI-processed with a stable reason."""

    # V10 1.3: extracted from the adapter-None and batch-failed
    # branches of llm_analysis, which were 100 percent identical
    # except for the reason string. collected_findings is typed
    # as list[dict] in state.py so the previous defensive
    # isinstance(f, dict) branches were unreachable code and
    # have been dropped (V9 4.3 follow-up).
    # Each per-finding update is awaited in a try/except so a
    # transient ES failure does not abort the whole fallback
    # batch; the failure is logged for diagnosis.
    if not findings:
        return
    store = get_vulnscan_store()
    if now_iso is None:
        now_iso = datetime.now(UTC).isoformat()
    for f in findings:
        # Findings may be Pydantic VulnFinding models (aggregate output) or
        # plain dicts (state.py). P1-VULN-GBL (2026-07-31) swapped .get() for
        # getattr(), which silently read the default on dicts; _finding_field
        # handles both shapes.
        fid = _finding_field(f, "finding_id", "") or ""
        fsev = _finding_field(f, "severity", "info") or "info"
        fix = _finding_field(f, "fix_advice", None)
        try:
            await store.update_vuln(
                fid,
                ai_severity=fsev,
                ai_filtered=False,
                fix_advice=fix,
                ai_processed=False,
                ai_reason=reason,
                ai_processed_at=now_iso,
            )
        except Exception as exc:
            logger.warning(
                "fallback_write_failed",
                finding_id=fid,
                reason=reason,
                error=str(exc) or type(exc).__name__,
            )


async def llm_analysis(state: dict) -> dict:
    """Use LLM to filter false positives, assign AI severity, and generate fix advice.

    Processes findings in batches and publishes progress via Redis pub/sub.
    Per-batch error handling ensures one batch failure does not stop the rest.
    """
    findings = state.get("collected_findings", [])
    task_id = state["task_id"]
    # S-P1-9 (V12): double-check before propagating a cancellation (same
    # rationale as aggregate -- never persist a blip as "cancelled").
    if state.get("status") == "cancelled" or await _confirm_cancellation(task_id):
        return {"status": "cancelled"}
    if not findings:
        return {"status": "reporting"}

    batch_size = 15
    all_analyzed: list[dict] = []
    batches_total = (len(findings) + batch_size - 1) // batch_size

    # 2026-07-29 UX upgrade: when the LLM adapter is unavailable we used
    # to silently skip the whole AI step, leaving every ai_* field blank
    # and the report looking like AI was never involved. Now we always
    # write a fallback row per finding so the UI can show "等待补扫"
    # instead of an empty column.
    adapter = None
    try:
        from src.knowledge.models.adapter import get_model_adapter

        adapter = get_model_adapter()
    except Exception as exc:
        logger.warning("llm_adapter_unavailable", error=str(exc))

    if adapter is None:
        # Fallback path: every finding gets ai_severity=original,
        # ai_filtered=False, ai_processed=False, ai_reason="LLM 不可用
        # so the operator knows AI never touched the row.
        # V10 1.3: delegated to _write_fallback (was 100 percent
        # duplicate of the batch-failed branch).
        await _write_fallback(findings, reason="LLM unavailable, kept original severity")
        await _pub_progress(
            task_id,
            "analysis",
            "done",
            f"AI unavailable - {len(findings)} findings marked 等待补扫",
        )
        return {"status": "reporting", "ai_processed": False}

    # Publish analysis start
    await _pub_progress(
        task_id,
        "analysis",
        "running",
        f"LLM analysing {len(findings)} findings in {batches_total} batches",
    )

    from pydantic import BaseModel

    class AnalyzedFinding(BaseModel):
        finding_id: str
        ai_severity: str
        ai_filtered: bool
        reason: str
        fix_advice: str

    class AnalyzedResult(BaseModel):
        analyzed: list[AnalyzedFinding]

    for batch_idx in range(batches_total):
        start = batch_idx * batch_size
        batch = findings[start : start + batch_size]

        try:
            prompt = _build_analysis_prompt(batch)
            result = await adapter.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                schema=AnalyzedResult,
            )
            for af in result.analyzed:
                all_analyzed.append(
                    {
                        "finding_id": af.finding_id,
                        "ai_severity": af.ai_severity,
                        "ai_filtered": af.ai_filtered,
                        "reason": af.reason,
                        "fix_advice": af.fix_advice,
                    }
                )
            await _pub_progress(
                task_id,
                "analysis",
                "running",
                f"Batch {batch_idx + 1}/{batches_total} done ({len(result.analyzed)} analysed)",
            )
        except Exception as exc:
            logger.warning("llm_batch_failed", batch=batch_idx, error=str(exc))
            await _pub_progress(
                task_id,
                "analysis",
                "running",
                f"Batch {batch_idx + 1}/{batches_total} failed, continuing",
            )
            continue

    # Write back AI analysis to vulns
    store = get_vulnscan_store()
    analyzed_ids = set()
    now_iso = datetime.now(UTC).isoformat()
    for item in all_analyzed:
        # 2026-07-31: wrap in try/except -- a doc that the consolidation
        # migration (or a concurrent reconcile) just deleted would otherwise
        # 404 and abort the whole analysis write-back. Skipped ids fall into
        # the failed-batch fallback below.
        try:
            await store.update_vuln(
                item["finding_id"],
                ai_severity=item["ai_severity"],
                ai_filtered=item["ai_filtered"],
                fix_advice=item.get("fix_advice"),
                ai_processed=True,
                ai_reason=item.get("reason"),
                ai_processed_at=now_iso,
            )
            analyzed_ids.add(item["finding_id"])
        except Exception as exc:
            logger.warning(
                "llm_update_failed",
                finding_id=item["finding_id"],
                error=str(exc) or type(exc).__name__,
            )

    # 2026-07-29 UX upgrade: any finding whose batch failed (LLM error)
    # gets a fallback write so its ai_* fields are still meaningful.
    failed = [f for f in findings if getattr(f, "finding_id", "") not in analyzed_ids]
    if failed:
        # V10 1.3: delegated to _write_fallback. Dropped the
        # defensive isinstance(f, dict) -- collected_findings is
        # always a list[dict] per state.py.
        await _write_fallback(failed, reason="LLM batch failed, awaiting rescan", now_iso=now_iso)

    return {"status": "reporting", "ai_processed": bool(analyzed_ids) and not failed}


def _build_analysis_prompt(findings: list) -> str:
    """Build the LLM analysis prompt for a batch of findings."""
    import json

    # findings may be Pydantic VulnFinding models or plain dicts (state.py
    # types collected_findings as list[dict]); _finding_field covers both.
    findings_json = []
    for f in findings:
        findings_json.append(
            {
                "finding_id": _finding_field(f, "finding_id", "") or "",
                "name": _finding_field(f, "name", "") or "",
                "cve": _finding_field(f, "cve", None),
                "severity": _finding_field(f, "severity", "info") or "info",
                "category": str(_finding_field(f, "category", "") or ""),
                "evidence": (_finding_field(f, "evidence", "") or "")[:300],
            }
        )

    return f"""You are a senior vulnerability analyst for an enterprise security team. For each finding below:

1. **False positive filter**: Mark ai_filtered=true if the finding is clearly benign (e.g. informational port scan results, expected configurations, non-exploitable CVEs on unreachable services). Give a one-sentence reason.

2. **Risk reassessment**: Based on real-world exploitability, CVSS context, asset context, assign ai_severity:
   - critical: actively exploited, remote code execution, no auth required
   - high: high impact but difficult to exploit, or requires auth
   - medium: moderate impact, limited scope
   - low: minor information disclosure, defense-in-depth gaps
   - info: purely informational

3. **Remediation advice**: Provide specific, actionable fix steps (update commands, config changes, compensating controls).

Findings:
{json.dumps(findings_json, ensure_ascii=False)}

Return JSON with "analyzed" array of: finding_id, ai_severity, ai_filtered, reason, fix_advice."""


async def _pub_progress(task_id: str, step: str, status: str, message: str) -> None:
    """Publish analysis progress to Redis for SSE subscribers."""
    try:
        import json as _json

        await _get_redis().publish(
            f"vulnscan:task:{task_id}",
            _json.dumps(
                {
                    "type": "scan_step",
                    "task_id": task_id,
                    "step": step,
                    "status": status,
                    "message": message,
                }
            ),
        )
    except Exception:
        pass


async def _confirm_cancellation(task_id: str) -> bool:
    """Re-check a cancellation tombstone before persisting "cancelled".

    ``_is_task_cancelled`` is fail-closed: a transient redis blip reads as
    "cancelled" so a user-initiated cancellation is never dropped. That is
    the right default for *short-circuiting* a node, but persisting
    ``status="cancelled"`` on a healthy running task is destructive -- the
    agent-side scan keeps executing and its results get orphaned. Re-check
    after a short delay: only when both checks agree the tombstone exists
    do we let the caller persist the cancellation.
    """
    if not await _is_task_cancelled(task_id):
        return False
    await asyncio.sleep(1)
    if await _is_task_cancelled(task_id):
        return True
    # First check said cancelled but the second did not -- most likely a
    # redis blip, not a real user cancellation. Surface it so operators
    # can see the near-miss instead of a silently killed healthy scan.
    get_logger(__name__).warning(
        "cancellation_check_unconfirmed_treating_as_healthy",
        task_id=task_id,
    )
    await get_audit_logger().log(
        event_id=task_id,
        node="vulnscan.subgraph",
        action="cancellation_check_degraded",
        details={
            "task_id": task_id,
            "detail": "first check said cancelled, second did not; treated as healthy",
        },
    )
    return False


async def _is_task_cancelled(task_id: str) -> bool:
    """Return the cross-worker cancellation tombstone state.

    Failure policy: FAIL-CLOSED. If the redis lookup raises for any
    reason (connection refused, timeout, auth error, etc.) we treat the
    task as cancelled and short-circuit the current node. The alternative
    (fail-open) silently drops user-initiated cancellations whenever redis
    blips, leaving zombie scans running. Operators can monitor redis
    health separately; fail-closed on a non-critical dependency is the
    safer default for a security product.

    The cancellation tombstone itself is set by the cancel API; the
    expensive thing we protect here is the dispatch / collect / report
    work that would otherwise run for an already-cancelled task and
    waste agent bandwidth."""
    redis = None
    try:
        from src.common.logging.logger import get_logger
        from src.orchestration.task_queue.keys import cancel_key

        redis = _get_redis()
        return bool(await redis.exists(cancel_key(task_id)))
    except Exception as exc:
        get_logger(__name__).warning(
            "nacos_cancellation_check_unavailable_treating_as_cancelled",
            error=str(exc),
            error_type=type(exc).__name__,
            task_id=task_id,
        )
        return True  # fail-closed: abort the node rather than run a cancelled task


async def generate_report(state: dict) -> dict:
    """Generate the final ScanReport with AI-generated summary and publish completion."""
    task_id = state["task_id"]
    store = get_vulnscan_store()
    # S-P1-9 (V12): same double-check as collect -- the fail-closed
    # cancellation check must not persist "cancelled" on a redis blip.
    if state.get("status") == "cancelled" or await _confirm_cancellation(task_id):
        await store.update_task(
            task_id,
            status="cancelled",
            finished_at=datetime.now(UTC).isoformat(),
        )
        await _pub_progress(task_id, "cancel", "done", "Scan cancelled")
        return {"report": None, "status": "cancelled"}

    # Read final vulns
    vulns = await store.list_vulns(VulnFilter(task_id=task_id, limit=10000))
    if not vulns:
        # Edge case: no findings at all. ai_processed=False because no LLM
        # call has happened; ai_overall_advice is left empty intentionally.
        report = ScanReport(
            task_id=task_id,
            summary="Scan completed: no vulnerabilities found.",
            ai_analysis="",
            stats={"by_severity": {}, "by_category": {}, "total": 0, "filtered_out": 0},
            top_vulns=[],
            recommendations=["No issues detected - system within expected security baseline."],
            generated_at=datetime.now(UTC).isoformat(),
            ai_processed=False,
            ai_model="",
            ai_overall_advice="",
            ai_processed_at="",
        )
        await store.save_report(report)
        await store.update_task(
            task_id, status="completed", finished_at=datetime.now(UTC).isoformat()
        )
        await _pub_progress(task_id, "report", "done", "Report generated: 0 findings")
        return {"report": report, "status": "completed"}

    # Calculate stats
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for v in vulns:
        cat = str(v.category)
        by_category[cat] = by_category.get(cat, 0) + 1
        # 修复：by_severity 按ai_severity(优先) 或severity 统计，原代码漏填致报告
        # 严重等级分布恒为空。
        sev = str(v.ai_severity or v.severity or "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # Non-filtered vulns, sorted by severity
    not_filtered = [v for v in vulns if not v.ai_filtered]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    not_filtered.sort(key=lambda x: severity_order.get(str(x.severity), 99))
    top_vulns = []
    for v in not_filtered[:20]:
        top_vulns.append(
            {
                "finding_id": v.finding_id,
                "hostname": v.hostname,
                "name": v.name,
                "cve": v.cve,
                "severity": v.severity,
                "ai_severity": v.ai_severity,
                "category": str(v.category),
                "fix_advice": v.fix_advice,
            }
        )

    # Generate recommendations
    recommendations: list[str] = []
    sev_set = {v.severity for v in not_filtered}
    if "critical" in sev_set:
        recommendations.append(
            "Critical: immediate emergency patching required - schedule change window within 24 hours"
        )
    if "high" in sev_set:
        recommendations.append(
            "High: schedule patching within 7 days, apply compensating controls in interim"
        )
    if "medium" in sev_set:
        recommendations.append("Medium: include in next regular patch cycle (within 30 days)")
    # The dict key uses str(ScanModule.BASELINE) == "ScanModule.BASELINE"
    # (Python's str() on a str-Enum returns the member name, not the value).
    # Tests rely on this so we keep the same lookup.
    if by_category.get(str(ScanModule.BASELINE), 0) > 0:
        recommendations.append(
            "Baseline: review and harden system configurations per CIS benchmarks"
        )
    recommendations.append("Re-scan affected hosts after remediation to verify fixes")

    # AI summary generation (lightweight, non-blocking). The summary is
    # 2-3 sentences; the SEPARATE ai_overall_advice block below answers
    # "why this matters and what to do next" from a business angle. They
    # live in the same card on the UI but as two distinct blocks so the
    # operator can tell the difference at a glance.
    summary = f"Scan completed: {len(vulns)} findings ({len(not_filtered)} non-filtered) across {len(by_category)} categories"
    ai_analysis_text = ""
    ai_overall_advice_text = ""
    # V10 2.2 (2026-07-30): ai_processed used to be computed locally
    # from whether the summary LLM call returned a non-empty string,
    # which silently disagreed with the upstream llm_analysis node --
    # that node already returns ai_processed=True once any finding
    # was scored. Read the upstream value from state so the report
    # badge matches what the operator saw on the findings table. The
    # summary text and ai_analysis block below still reflect this
    # node own LLM call; on failure the fallback summary and empty
    # ai_analysis text surface the difference.
    ai_processed = bool(state.get("ai_processed", False))
    ai_model_name = ""
    try:
        from src.knowledge.models.adapter import get_model_adapter

        adapter = get_model_adapter()
        summary_prompt = f"""Summarise this vulnerability scan result in 2-3 sentences in Chinese.

Total findings: {len(vulns)}
After AI filtering: {len(not_filtered)}
By severity: {by_severity}
By category: {by_category}
Top risk: {top_vulns[0].get("name", "N/A") if top_vulns else "None"}

Focus on actionable risk posture and top remediation priority."""
        # V9 3.4 (2026-07-30): summary_prompt + advice_prompt are two
        # independent LLM calls; run them concurrently via asyncio.gather
        # so wall-clock drops from (summary + advice) to max(summary, advice).
        advice_prompt = f"""Based on the following scan summary, give 2-4 sentences of executive advice in Chinese.
Focus on business impact, attack chains across hosts (if any), and what
the security team should prioritise in the next 24-72 hours.

Total findings: {len(vulns)}
After AI filtering: {len(not_filtered)}
By severity: {by_severity}
By category: {by_category}
Top risk: {top_vulns[0].get("name", "N/A") if top_vulns else "None"}
Top hosts affected: {sorted({str(v.get("hostname") or "") for v in top_vulns if v.get("hostname")})[:5]}"""
        summary_result, advice_result = await asyncio.gather(
            adapter.chat_completion(messages=[{"role": "user", "content": summary_prompt}]),
            adapter.chat_completion(messages=[{"role": "user", "content": advice_prompt}]),
            return_exceptions=True,
        )
        if isinstance(summary_result, Exception):
            logger.warning("report_summary_llm_failed", task_id=task_id, error=str(summary_result))
            ai_analysis_text = ""
        elif isinstance(summary_result, str) and len(summary_result) > 5:
            summary = summary_result
            ai_analysis_text = summary_result
        else:
            ai_analysis_text = ""
        if isinstance(advice_result, Exception):
            logger.warning("report_advice_llm_failed", task_id=task_id, error=str(advice_result))
        elif isinstance(advice_result, str) and len(advice_result) > 5:
            ai_overall_advice_text = advice_result
        ai_model_name = adapter.current_model_name() or ""
    except Exception as exc:
        logger.warning("report_summary_llm_failed", task_id=task_id, error=str(exc))

    report = ScanReport(
        task_id=task_id,
        summary=summary[:500],
        ai_analysis=ai_analysis_text[:1000],
        stats={
            "by_severity": by_severity,
            "by_category": by_category,
            "total": len(vulns),
            "filtered_out": len([v for v in vulns if v.ai_filtered]),
        },
        top_vulns=top_vulns,
        recommendations=recommendations,
        generated_at=datetime.now(UTC).isoformat(),
        ai_processed=ai_processed,
        ai_model=ai_model_name,
        ai_overall_advice=ai_overall_advice_text[:1000],
        ai_processed_at=datetime.now(UTC).isoformat() if ai_processed else "",
    )

    await store.save_report(report)
    await store.update_task(task_id, status="completed", finished_at=datetime.now(UTC).isoformat())

    # Publish completion event
    await _pub_progress(
        task_id,
        "report",
        "done",
        f"Report generated: {len(vulns)} findings, {len(recommendations)} recommendations",
    )

    # Clean up collect counter (S-P1-1: shared client).
    try:
        await _get_redis().delete(f"vulnscan:collect:{task_id}")
    except Exception:
        pass

    logger.info("vulnscan_report_generated", task_id=task_id, total=len(vulns))
    return {"report": report, "status": "completed"}
