""""VulnScan subgraph node implementations."""
import uuid
from datetime import UTC, datetime

from src.agents.models import (
    ScanPolicy,
    ScanReport,
    ScanTask,
    VulnFinding,
)
from src.agents.store import get_vulnscan_store
from src.agents.ws_gateway import get_agent_gateway
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


def _default_state(
    source: str,
    intent_text: str | None = None,
    targets: list[str] | None = None,
    modules: list[str] | None = None,
    task_id: str | None = None,
) -> dict:
    """Build the initial VulnScanState from input params.

    ``task_id`` is taken from the caller when provided so the API can return
    the SAME identifier the subgraph uses (P0-VS-2). When None (e.g. dialog-driven
    scans started from the orchestrator), generate a fresh uuid.
    """
    task_id = task_id or str(uuid.uuid4())
    return {
        "task_id": task_id,
        "source": source,
        "intent_text": intent_text,
        "targets": targets or [],
        "modules": modules or ["sys_vuln", "baseline"],
        "resource_limit": {"cpu_percent": 30, "mem_percent": 30},
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


async def dispatch(state: dict) -> dict:
    """Create ScanTask in ES, resolve targets to agent_ids, dispatch scan_command via gateway."""

    store = get_vulnscan_store()
    gateway = get_agent_gateway()

    task_id = state["task_id"]
    targets = state["targets"]
    modules = state["modules"]

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
        status="dispatching",
        created_at=datetime.now(UTC).isoformat(),
        stats={"total": len(agent_ids), "done": 0, "failed": 0},
    )
    await store.save_task(task)

    if not agent_ids:
        return {"error": "No target agents found", "status": "failed", "task": task}

    # Broadcast scan command
    scan_cmd = {
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
        },
    }
    result = await gateway.broadcast(agent_ids, scan_cmd)

    # Update task status
    await store.update_task(
        task_id,
        status="scanning",
        stats={"total": len(agent_ids), "done": result["sent"], "failed": result["failed"]},
    )

    # Store collection tracking in Redis
    import redis.asyncio as aioredis

    from src.common.config.settings import get_settings
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    await r.hset(f"vulnscan:collect:{task_id}", mapping={
        "total": str(len(agent_ids)),
        "received": "0",
    })
    if state.get("policy"):
        await r.expire(f"vulnscan:collect:{task_id}", state.get("policy", ScanPolicy()).timeout_sec)

    logger.info("scan_dispatched", task_id=task_id, target_count=len(agent_ids))
    return {
        "task": task,
        "dispatched": True,
        "total_targets": len(agent_ids),
        "received_results": result["sent"],
        "status": "scanning",
    }


async def _resolve_targets(targets: list[str]) -> list[str]:
    """Resolve target names (hostname/IP/group) to agent_ids."""
    store = get_vulnscan_store()
    all_hosts = await store.list_hosts(status="online", limit=1000)

    agent_ids: list[str] = []
    for target in targets:
        # Check if target is already an agent_id
        for h in all_hosts:
            if h.agent_id == target:
                agent_ids.append(target)
                break
            if h.hostname == target or h.ip == target or h.group == target:
                agent_ids.append(h.agent_id)
                break

    # If no matches found, try to use targets as-is (might be agent_ids)
    if not agent_ids:
        return targets

    return agent_ids


async def collect(state: dict) -> dict:
    """Wait for agents to report scan results (or timeout).

    P1-VS-3: previously this node returned "scanning" immediately after the
    first read. Because the graph was linear, the subgraph walked past collect
    long before any agent had finished scanning -- reports were always empty.
    We now poll ES for ``is_final`` batches with a bounded wait bounded by
    ``ScanPolicy.timeout_sec``. When the deadline passes we proceed with the
    partial results so we never deadlock the orchestrator.
    """
    import asyncio
    task_id = state["task_id"]
    store = get_vulnscan_store()
    total = state.get("total_targets", 0)
    failed = state["task"].stats.get("failed", 0)
    timeout_sec = int((state["task"].policy.timeout_sec or 1800) if state.get("task") else 1800)
    poll_interval = 5  # seconds
    deadline = asyncio.get_running_loop().time() + timeout_sec

    done_count = 0
    while True:
        results = await store.list_results(task_id=task_id)
        is_final_batches = [r for r in results if r.is_final]
        done_count = len(set(r.agent_id for r in is_final_batches))
        await store.update_task(
            task_id,
            stats={"total": total, "done": done_count, "failed": failed},
        )

        if total > 0 and (done_count >= total or done_count + failed >= total):
            await store.update_task(task_id, status="analyzing")
            return {"status": "analyzing", "received_results": done_count}

        if asyncio.get_running_loop().time() >= deadline:
            logger.warning(
                "vulnscan_collect_timeout", task_id=task_id,
                done=done_count, total=total, failed=failed,
            )
            await store.update_task(task_id, status="analyzing")
            return {"status": "analyzing", "received_results": done_count}

        await asyncio.sleep(poll_interval)
async def aggregate(state: dict) -> dict:
    """Aggregate findings from all agents, deduplicate, store as VulnFindings."""
    task_id = state["task_id"]
    store = get_vulnscan_store()

    # Read all scan results for this task
    results = await store.list_results(task_id=task_id)

    # Collect all findings, deduplicate by (agent_id, cve, name)
    seen: set[tuple] = set()
    findings: list[VulnFinding] = []
    for result in results:
        for f in result.findings:
            key = (f.agent_id, f.cve or "", f.name)
            if key not in seen:
                seen.add(key)
                findings.append(f)

    # Bulk save vulns
    if findings:
        await store.save_vulns(findings)

    logger.info("aggregated_findings", task_id=task_id, count=len(findings))
    return {
        "collected_findings": findings,
        "status": "analyzing",
    }


async def llm_analysis(state: dict) -> dict:
    """Use LLM to filter false positives, assign AI severity, and generate fix advice.

    Processes findings in batches and publishes progress via Redis pub/sub.
    Per-batch error handling ensures one batch failure does not stop the rest.
    """
    findings = state.get("collected_findings", [])
    task_id = state["task_id"]
    if not findings:
        return {"status": "reporting"}

    batch_size = 15
    all_analyzed: list[dict] = []
    batches_total = (len(findings) + batch_size - 1) // batch_size

    try:
        from src.knowledge.models.adapter import get_model_adapter
        adapter = get_model_adapter()
    except Exception:
        logger.warning("llm_adapter_unavailable")
        return {"status": "reporting"}

    # Publish analysis start
    await _pub_progress(task_id, "analysis", "running", f"LLM analysing {len(findings)} findings in {batches_total} batches")

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
        batch = findings[start:start + batch_size]

        try:
            prompt = _build_analysis_prompt(batch)
            result = await adapter.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                schema=AnalyzedResult,
            )
            for af in result.analyzed:
                all_analyzed.append({
                    "finding_id": af.finding_id,
                    "ai_severity": af.ai_severity,
                    "ai_filtered": af.ai_filtered,
                    "reason": af.reason,
                    "fix_advice": af.fix_advice,
                })
            await _pub_progress(
                task_id, "analysis", "running",
                f"Batch {batch_idx + 1}/{batches_total} done ({len(result.analyzed)} analysed)",
            )
        except Exception as exc:
            logger.warning("llm_batch_failed", batch=batch_idx, error=str(exc))
            await _pub_progress(
                task_id, "analysis", "running",
                f"Batch {batch_idx + 1}/{batches_total} failed, continuing",
            )
            continue

    # Write back AI analysis to vulns
    store = get_vulnscan_store()
    for item in all_analyzed:
        await store.update_vuln(
            item["finding_id"],
            ai_severity=item["ai_severity"],
            ai_filtered=item["ai_filtered"],
            fix_advice=item.get("fix_advice"),
        )

    logger.info("llm_analysis_complete", count=len(all_analyzed), task_id=task_id)
    await _pub_progress(task_id, "analysis", "done", f"AI analysis complete: {len(all_analyzed)} findings analysed")
    return {"status": "reporting"}


def _build_analysis_prompt(findings: list) -> str:
    """Build the LLM analysis prompt for a batch of findings."""
    import json
    findings_json = []
    for f in findings:
        fid = f.get("finding_id", "") if isinstance(f, dict) else f.finding_id
        fname = f.get("name", "") if isinstance(f, dict) else f.name
        fcve = f.get("cve") if isinstance(f, dict) else f.cve
        fsev = f.get("severity", "info") if isinstance(f, dict) else f.severity
        if hasattr(fsev, "value"):
            fsev = str(fsev.value)
        fcat = f.get("category", "") if isinstance(f, dict) else f.category
        if hasattr(fcat, "value"):
            fcat = str(fcat.value)
        fev = f.get("evidence", "")[:300] if isinstance(f, dict) else (f.evidence or "")[:300]
        findings_json.append({
            "finding_id": fid,
            "name": fname,
            "cve": fcve,
            "severity": fsev,
            "category": fcat,
            "evidence": fev,
        })

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

        import redis.asyncio as aioredis

        from src.common.config.settings import get_settings
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        await r.publish(f"vulnscan:task:{task_id}", _json.dumps({
            "type": "scan_step",
            "task_id": task_id,
            "step": step,
            "status": status,
            "message": message,
        }))
    except Exception:
        pass



async def generate_report(state: dict) -> dict:
    """Generate the final ScanReport with AI-generated summary and publish completion."""
    task_id = state["task_id"]
    store = get_vulnscan_store()

    # Read final vulns
    vulns = await store.list_vulns(task_id=task_id, limit=10000)
    if not vulns:
        # Edge case: no findings at all
        report = ScanReport(
            task_id=task_id,
            summary="Scan completed: no vulnerabilities found.",
            ai_analysis="",
            stats={"by_severity": {}, "by_category": {}, "total": 0, "filtered_out": 0},
            top_vulns=[],
            recommendations=["No issues detected - system within expected security baseline."],
            generated_at=datetime.now(UTC).isoformat(),
        )
        await store.save_report(report)
        await store.update_task(task_id, status="completed", finished_at=datetime.now(UTC).isoformat())
        await _pub_progress(task_id, "report", "done", "Report generated: 0 findings")
        return {"report": report, "status": "completed"}

    # Calculate stats
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for v in vulns:
        cat = str(v.category)
        by_category[cat] = by_category.get(cat, 0) + 1

    # Non-filtered vulns, sorted by severity
    not_filtered = [v for v in vulns if not v.ai_filtered]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    not_filtered.sort(key=lambda x: severity_order.get(str(x.severity), 99))
    top_vulns = []
    for v in not_filtered[:20]:
        top_vulns.append({
            "finding_id": v.finding_id,
            "hostname": v.hostname,
            "name": v.name,
            "cve": v.cve,
            "severity": v.severity,
            "ai_severity": v.ai_severity,
            "category": str(v.category),
            "fix_advice": v.fix_advice,
        })

    # Generate recommendations
    recommendations: list[str] = []
    sev_set = {v.severity for v in not_filtered}
    if "critical" in sev_set:
        recommendations.append("Critical: immediate emergency patching required - schedule change window within 24 hours")
    if "high" in sev_set:
        recommendations.append("High: schedule patching within 7 days, apply compensating controls in interim")
    if "medium" in sev_set:
        recommendations.append("Medium: include in next regular patch cycle (within 30 days)")
    if by_category.get("ScanModule.BASELINE", 0) > 0:
        recommendations.append("Baseline: review and harden system configurations per CIS benchmarks")
    recommendations.append("Re-scan affected hosts after remediation to verify fixes")

    # AI summary generation (lightweight, non-blocking)
    summary = f"Scan completed: {len(vulns)} findings ({len(not_filtered)} non-filtered) across {len(by_category)} categories"
    ai_analysis_text = ""
    try:
        from src.knowledge.models.adapter import get_model_adapter
        adapter = get_model_adapter()
        summary_prompt = f"""Summarise this vulnerability scan result in 2-3 sentences in Chinese.

Total findings: {len(vulns)}
After AI filtering: {len(not_filtered)}
By severity: {by_severity}
By category: {by_category}
Top risk: {top_vulns[0].get('name', 'N/A') if top_vulns else 'None'}

Focus on actionable risk posture and top remediation priority."""
        ai_analysis_text = await adapter.chat_completion(
            messages=[{"role": "user", "content": summary_prompt}],
        )
        if isinstance(ai_analysis_text, str) and len(ai_analysis_text) > 5:
            summary = ai_analysis_text
        else:
            ai_analysis_text = ""
    except Exception:
        logger.warning("report_summary_llm_failed", task_id=task_id)

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
    )

    await store.save_report(report)
    await store.update_task(task_id, status="completed", finished_at=datetime.now(UTC).isoformat())

    # Publish completion event
    await _pub_progress(task_id, "report", "done", f"Report generated: {len(vulns)} findings, {len(recommendations)} recommendations")

    # Clean up collect counter
    try:
        import redis.asyncio as aioredis

        from src.common.config.settings import get_settings
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        await r.delete(f"vulnscan:collect:{task_id}")
    except Exception:
        pass

    logger.info("vulnscan_report_generated", task_id=task_id, total=len(vulns))
    return {"report": report, "status": "completed"}


