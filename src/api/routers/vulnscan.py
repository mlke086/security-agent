"""Vulnscan API routes.

P2 (2026-07-18): ``POST /api/v1/vulnscan/tasks`` now enqueues the task onto
the Redis Stream and returns ``{task_id}`` immediately. The previous
behaviour (``asyncio.create_task(run_vulnscan(...))`` inside the request
goroutine) coupled request lifetime to subgraph runtime and blocked the
API when the subgraph got slow. The actual execution now happens in the
``TaskWorker`` background process.
"""

import json
import uuid
from datetime import UTC, datetime

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel as _PydanticBaseModel

from src.agents.models import ScanIntent, ScanReport, ScanTask, VulnFinding
from src.agents.store import get_vulnscan_store
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.subgraphs.vulnscan.graph import run_vulnscan
from src.orchestration.task_queue import (
    enqueue_task,
    pending_count,
    stream_depth,
)
from src.orchestration.task_queue.keys import (
    CANCEL_TTL_SEC,
    STATUS_TTL_SEC,
    cancel_key,
    status_key,
)


# 2026-07-29: response models for the OpenAPI schema.
# FastAPI only emits a schema for a route when it sees a Pydantic
# model in the signature. These thin wrappers let /vulnscan/*
# appear in the generated openapi.json so the frontend
# gen:types pipeline picks up the new AI / fix-time fields.
class _TaskListResponse(_PydanticBaseModel):
    items: list[ScanTask]


class _VulnListResponse(_PydanticBaseModel):
    items: list[VulnFinding]


class _VulnDetailResponse(VulnFinding):
    """GET /vulnscan/vulns/{id} response. The router attaches
    an optional host dict when the agent_id / hostname lookup
    succeeds; otherwise the field is absent. Modelling the host
    as Optional keeps the OpenAPI schema honest about the union.
    """

    host: dict | None = None


class _HostStatsItem(_PydanticBaseModel):
    group: str
    member_count: int
    total: int
    by_severity: dict[str, int] = {}


class _HostStatsResponse(_PydanticBaseModel):
    items: list[_HostStatsItem]
    cached: bool = False


router = APIRouter(prefix="/api/v1/vulnscan", tags=["vulnscan"])
logger = get_logger(__name__)


@router.post("/tasks/parse")
async def api_parse_intent(
    body: dict,
    current_user=Depends(require_role("admin", "analyst")),
):
    from src.knowledge.models.adapter import get_model_adapter

    adapter = get_model_adapter()
    intent_text = body.get("intent_text", "")
    result = await adapter.chat_completion(
        messages=[{"role": "user", "content": f"Parse: {intent_text}"}],
        schema=ScanIntent,
    )
    return result


@router.post("/tasks")
async def api_create_task(
    body: dict,
    sync: bool = Query(False, description="Synchronous path; bypass queue"),
    current_user=Depends(require_role("admin", "analyst")),
):
    """Enqueue a vulnscan task. Returns ``{task_id, status: "queued"}`` immediately.

    P2: the actual subgraph execution runs in a background ``TaskWorker``
    subscribed to the Redis Stream. Multiple uvicorn workers spread the
    load automatically through the consumer group. The legacy in-process
    path is kept behind ``?sync=1`` for tests / debugging.
    """
    # P0 (2026-07-18): the "engine" field picks the agent-side scanner.
    #   "matcher" -> own rule-based CVE matcher (legacy, default)
    #   "nuclei"  -> os/exec wrapper around projectdiscovery/nuclei CLI
    source = body.get("source", "manual")
    intent_text = body.get("intent_text")
    targets = body.get("targets", [])
    modules = body.get("modules", ["sys_vuln", "baseline"])
    engine = body.get("engine", "matcher")
    if engine not in ("matcher", "nuclei"):
        raise HTTPException(
            status_code=422,
            detail=f"unsupported engine {engine!r}; expected matcher or nuclei",
        )

    # 2026-07-29 UX upgrade: resolve the targets to their business
    # group(s) ONCE at enqueue time, then persist on the ScanTask so
    # the task list page does not need an N+1 list_hosts() join.
    # V9 3.2 (2026-07-30): cache the hostname/agent_id -> group map
    # for 30s in-process so burst task creates don't each issue a
    # list_hosts() query. Best-effort: a Redis/PG blip or a target
    # that points at a decommissioned host simply leaves target_groups
    # empty.
    target_groups: list[str] = []
    try:
        import time as _time_target_groups

        now = _time_target_groups.monotonic()
        cached = _HOST_STATS_CACHE
        if (
            now - cached.get("ts_target_groups", 0.0) >= _HOST_STATS_TTL_SEC
            or "host_to_group" not in cached
        ):
            # S-P1-3: use the shared singleton instead of constructing a
            # new VulnscanStore() (which leaks an Elasticsearch client
            # per request).
            _all_hosts = await get_vulnscan_store().list_hosts(limit=2000)
            _name_to_group: dict[str, str] = {}
            for _h in _all_hosts:
                if _h.group:
                    if _h.hostname:
                        _name_to_group[_h.hostname] = _h.group
                    if _h.agent_id:
                        _name_to_group[_h.agent_id] = _h.group
            cached["host_to_group"] = _name_to_group
            cached["ts_target_groups"] = now
        _name_to_group = cached["host_to_group"]
        target_groups = sorted(
            {_name_to_group[t] for t in (targets or []) if t in _name_to_group}
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("target_groups_resolve_failed", error=str(exc))

    # Legacy path: still allow sync execution for tests / debugging.
    if sync or body.get("sync"):
        task_id = str(uuid.uuid4())
        await run_vulnscan(
            source=source,
            intent_text=intent_text,
            targets=targets,
            modules=modules,
            task_id=task_id,
            engine=engine,
            nuclei_severity=body.get("nuclei_severity", []),
            nuclei_tags=body.get("nuclei_tags", []),
            nuclei_templates=body.get("nuclei_templates", []),
            nuclei_timeout_sec=int(body.get("nuclei_timeout_sec", 0) or 0),
            target_groups=target_groups,
        )
        return {
            "task_id": task_id,
            "status": "completed",
            "engine": engine,
            "sync": True,
            "target_groups": target_groups,
        }

    # P2 async path: enqueue to Redis Stream, return immediately.
    envelope = await enqueue_task(
        source=source,
        targets=targets,
        intent_text=intent_text,
        modules=modules,
        engine=engine,
        nuclei_severity=body.get("nuclei_severity", []),
        nuclei_tags=body.get("nuclei_tags", []),
        nuclei_templates=body.get("nuclei_templates", []),
        nuclei_timeout_sec=int(body.get("nuclei_timeout_sec", 0) or 0),
        target_groups=target_groups,
        actor=current_user.username,
    )

    await get_audit_logger().log(
        event_id=envelope.task_id,
        node="vulnscan.router",
        action="create_task",
        actor=current_user.username,
        details={"source": source, "targets": targets, "engine": engine, "queued": True},
    )
    return {"task_id": envelope.task_id, "status": "queued", "engine": engine}


@router.get("/tasks", response_model=_TaskListResponse)
async def api_list_tasks(
    status: str | None = Query(None),
    current_user=Depends(require_role("admin", "analyst")),
):
    store = get_vulnscan_store()
    tasks = await store.list_tasks(status=status)
    return {"items": [t.model_dump() for t in tasks]}


@router.get("/tasks/{task_id}")
async def api_get_task(
    task_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    """Return task record from ES. P2 also consults the Redis side-channel
    so callers see ``queued`` / ``running`` before the subgraph has finished
    writing the canonical record."""
    store = get_vulnscan_store()
    task = await store.get_task(task_id)
    if not task:
        # Fall back to the side-channel; covers the brief window between
        # enqueue and the subgraph\'s first ES write.
        try:
            r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
            try:
                payload = await r.get(status_key(task_id))
            finally:
                await r.aclose()
            if payload:
                data = json.loads(payload)
                return {
                    "task_id": task_id,
                    "status": data.get("status", "queued"),
                    "targets": data.get("targets", []),
                    "error": data.get("error"),
                    "side_channel": True,
                    "worker": data.get("worker", ""),
                    "submitted_at": data.get("ts", ""),
                }
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.get("/tasks/{task_id}/stream")
async def api_task_stream(task_id: str, token: str = Query(...)):
    from src.api.auth.jwt import decode_token

    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    async def sse_gen():
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        pubsub = r.pubsub()
        await pubsub.subscribe(f"vulnscan:task:{task_id}")
        # Phase-3 UX fix (2026-07-28 e2e sweep): push a status_change
        # event on ANY transition, not just terminal. Without this, when
        # the agent finishes the scan phase and the subgraph moves the
        # task to `analyzing`, the agent stops pushing events at the
        # same moment -- so the only reliable signal to the monitor
        # page is the canonical task.status write. The page used to
        # sit on stale "scanning" + the same "等待 agent 上报..."
        # message during the analysis phase, which was misleading.
        # We now mirror the canonical status into SSE on every change.
        # Terminal transitions still send `task_done` for backwards
        # compatibility with the existing client close logic.
        store = get_vulnscan_store()
        last_status = ""
        try:
            while True:
                msg = await pubsub.get_message(timeout=10, ignore_subscribe_messages=True)
                if msg:
                    yield f"data: {msg['data']}\n\n"
                else:
                    yield ": heartbeat\n\n"
                # 每 10s 检查任务状态；状态变化时推 status_change，
                # 终态则发 task_done 并 break 关闭连接。
                try:
                    task = await store.get_task(task_id)
                    if task and task.status != last_status:
                        import json as _json

                        if task.status in ("completed", "failed", "cancelled"):
                            yield f"data: {_json.dumps({'type': 'task_done', 'task_id': task_id, 'status': task.status})}\n\n"
                            last_status = task.status
                            # 终态后发一次结束事件即 break，关闭连接
                            break
                        else:
                            yield f"data: {_json.dumps({'type': 'status_change', 'task_id': task_id, 'status': task.status})}\n\n"
                            last_status = task.status
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            await pubsub.unsubscribe(f"vulnscan:task:{task_id}")
            await pubsub.close()
            await r.aclose()

    return StreamingResponse(
        sse_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/tasks/{task_id}/cancel")
async def api_cancel_task(task_id: str, current_user=Depends(require_role("admin", "analyst"))):
    """Cancel queued or running work and notify every assigned Agent."""
    store = get_vulnscan_store()
    task = await store.get_task(task_id)
    redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    queue_state: dict = {}
    sent = 0
    failed = 0
    now = datetime.now(UTC).isoformat()

    try:
        if task is None:
            raw = await redis.get(status_key(task_id))
            if raw:
                queue_state = json.loads(raw)
            else:
                raise HTTPException(status_code=404, detail="Task not found")

        current_status = task.status if task is not None else queue_state.get("status", "queued")
        if current_status == "cancelled":
            return {"status": "cancelled", "sent": 0, "failed": 0}
        if current_status in ("completed", "failed"):
            raise HTTPException(status_code=409, detail=f"Task is already {current_status}")

        await redis.set(
            cancel_key(task_id),
            json.dumps({"actor": current_user.username, "cancelled_at": now}),
            ex=CANCEL_TTL_SEC,
        )

        if task is not None:
            await store.update_task(task_id, status="cancelling")
            agent_ids = list(dict.fromkeys(task.targets))
            if agent_ids:
                from src.agents.ws_gateway import get_agent_gateway

                result = await get_agent_gateway().broadcast(
                    agent_ids,
                    {
                        "v": 1,
                        "type": "scan_cancel",
                        "ts": now,
                        "payload": {"task_id": task_id},
                    },
                )
                sent = int(result.get("sent", 0))
                failed = int(result.get("failed", 0))
            await store.update_task(
                task_id,
                status="cancelled",
                error=f"Cancelled by {current_user.username}",
                finished_at=now,
            )

        side_channel = {
            **queue_state,
            "status": "cancelled",
            "cancelled_at": now,
            "actor": current_user.username,
        }
        await redis.set(
            status_key(task_id),
            json.dumps(side_channel, ensure_ascii=False),
            ex=STATUS_TTL_SEC,
        )
        await redis.publish(
            f"vulnscan:task:{task_id}",
            json.dumps(
                {
                    "type": "task_done",
                    "task_id": task_id,
                    "status": "cancelled",
                    "message": "Scan cancelled by operator",
                },
                ensure_ascii=False,
            ),
        )
    finally:
        await redis.aclose()

    await get_audit_logger().log(
        event_id=task_id,
        node="vulnscan.router",
        action="cancel_task",
        actor=current_user.username,
        details={"task_id": task_id, "sent": sent, "failed": failed},
    )
    return {"status": "cancelled", "sent": sent, "failed": failed}


@router.delete("/tasks/{task_id}")
async def api_delete_task(task_id: str, current_user=Depends(require_role("admin", "analyst"))):
    """删除扫描任务记录及其关联数据（results/vulns/report）。"""
    store = get_vulnscan_store()
    task = await store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await store.delete_task(task_id)
    await get_audit_logger().log(
        event_id=task_id,
        node="vulnscan.router",
        action="delete_task",
        actor=current_user.username,
        details={"task_id": task_id},
    )
    return {"status": "ok"}


@router.get("/results", response_model=_VulnListResponse)
async def api_list_results(
    task_id: str | None = Query(None),
    hostname: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    # 2026-07-29 UX upgrade: extended filter set. All optional, so the
    # caller (vuln list page) can drop in the new controls without
    # breaking existing dashboards that only pass the old params.
    cve: str | None = Query(None, description="Exact CVE id, e.g. CVE-2024-0001"),
    cve_keyword: str | None = Query(None, description="Case-insensitive substring on CVE id"),
    hostname_keyword: str | None = Query(
        None, description="Case-insensitive substring on hostname"
    ),
    name_keyword: str | None = Query(
        None, description="Case-insensitive substring on finding name"
    ),
    group: str | None = Query(None, description="Filter by business group (host.group)"),
    ai_processed: bool | None = Query(None, description="Filter by AI processing state"),
    date_from: str | None = Query(None, description="ISO 8601, e.g. 2026-07-01T00:00:00Z"),
    date_to: str | None = Query(None, description="ISO 8601, e.g. 2026-07-29T23:59:59Z"),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_vulnscan_store()
    # 2026-07-29 UX upgrade: when the caller passes ``group``, we look up
    # the host list for that business group and push it into the ES query
    # as a server-side ``terms`` filter (handled in store.list_vulns via
    # the ``hostnames`` param). The group lives on hosts, not on vulns, so
    # this is the cleanest place to do the join without materialising it
    # in ES. S-P1-4: filtering server-side (instead of fetching a capped
    # 200-row page and filtering in memory) stops silent truncation that
    # could hide critical findings in large groups.
    hostname_terms: list[str] | None = None
    if group:
        hosts = await store.list_hosts(group=group, limit=2000)
        if not hosts:
            # Group has no hosts (yet) -> explicit empty result, so the
            # frontend doesn't accidentally show all vulns.
            return {"items": []}
        hostname_terms = [h.hostname for h in hosts if h.hostname]
    findings = await store.list_vulns(
        task_id=task_id,
        hostname=hostname,
        hostnames=hostname_terms,
        severity=severity,
        status=status,
        cve=cve,
        cve_keyword=cve_keyword,
        hostname_keyword=hostname_keyword,
        name_keyword=name_keyword,
        ai_processed=ai_processed,
        date_from=date_from,
        date_to=date_to,
        # Generous limit for the group view so realistic groups are not
        # truncated; full pagination is a separate follow-up.
        limit=2000 if group else 200,
    )
    return {"items": [f.model_dump() for f in findings]}


@router.get("/reports/{task_id}", response_model=ScanReport)
async def api_get_report(
    task_id: str, current_user=Depends(require_role("admin", "analyst", "viewer"))
):
    store = get_vulnscan_store()
    report = await store.get_report(task_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/reports/{task_id}/export")
async def api_export_report(
    task_id: str,
    format: str = Query("html", description="导出格式：html"),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """导出扫描报告为可下载文件。

    需求6：扫描任务完成后，监控页提供"下载报告"按钮，调用本接口。
    当前支持 HTML（自包含模板渲染，无外部依赖）；PDF 留待后续批次。
    """
    store = get_vulnscan_store()
    report = await store.get_report(task_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if format != "html":
        raise HTTPException(status_code=422, detail=f"unsupported format {format!r}; expected html")

    html_content = _render_report_html(task_id, report)
    await get_audit_logger().log(
        event_id=task_id,
        node="vulnscan.router",
        action="export_report",
        actor=current_user.username,
        details={"format": format},
    )
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'attachment; filename="scan-report-{task_id}.html"'},
    )


def _render_report_html(task_id: str, report) -> str:
    """渲染自包含 HTML 扫描报告。"""
    import html as _html

    def esc(v) -> str:
        return _html.escape(str(v)) if v is not None else ""

    stats = report.stats or {}
    by_sev = stats.get("by_severity", {}) or {}
    sev_rows = (
        "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in by_sev.items())
        or '<tr><td colspan="2">无数据</td></tr>'
    )

    top_rows = (
        "".join(
            f"<tr><td>{esc(item.get('hostname', ''))}</td>"
            f"<td>{esc(item.get('name', ''))}</td>"
            f"<td>{esc(item.get('cve') or '基线检查')}</td>"
            f"<td>{esc(item.get('ai_severity') or item.get('severity', ''))}</td>"
            f"<td>{esc(item.get('fix_advice', ''))}</td></tr>"
            for item in (report.top_vulns or [])
        )
        or '<tr><td colspan="5">未发现漏洞</td></tr>'
    )

    rec_items = (
        "".join(f"<li>{esc(r)}</li>" for r in (report.recommendations or [])) or "<li>无</li>"
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>扫描报告 - {esc(task_id)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 32px; color: #333; }}
  h1 {{ color: #1677ff; border-bottom: 2px solid #1677ff; padding-bottom: 8px; }}
  h2 {{ margin-top: 28px; color: #001529; }}
  .meta {{ color: #888; font-size: 13px; margin-bottom: 16px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 14px; }}
  th {{ background: #fafafa; }}
  .summary {{ background: #f6ffed; padding: 16px; border-radius: 6px; margin: 12px 0; }}
  .ai {{ color: #555; line-height: 1.6; }}
</style>
</head>
<body>
  <h1>漏洞扫描报告</h1>
  <div class="meta">任务 ID：{esc(task_id)}　|　生成时间：{esc(report.generated_at or "")}</div>

  <h2>扫描摘要</h2>
  <div class="summary">
    {esc(report.summary or "无摘要")}
  </div>
  {f'<div class="ai"><strong>AI 分析：</strong>{esc(report.ai_analysis)}</div>' if report.ai_analysis else ""}

  <h2>统计概览</h2>
  <table>
    <tr><th>严重等级</th><th>数量</th></tr>
    {sev_rows}
    <tr><td>已过滤(误报)</td><td>{esc(stats.get("filtered_out", 0))}</td></tr>
  </table>

  <h2>Top 漏洞</h2>
  <table>
    <tr><th>主机</th><th>漏洞名称</th><th>CVE</th><th>严重等级</th><th>修复建议</th></tr>
    {top_rows}
  </table>

  <h2>修复建议</h2>
  <ul>{rec_items}</ul>
</body>
</html>"""


@router.get("/vulns/{finding_id}", response_model=_VulnDetailResponse)
async def api_get_vuln(
    finding_id: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """Return the finding with the host it belongs to.

    2026-07-29 UX upgrade (host meta): the vuln detail drawer needs the
    host's business group / owner / env / ip / os so the operator can
    see the asset context without leaving the page. We look up the host
    by ``agent_id`` (preferred) and fall back to ``hostname`` so we
    still get useful context for findings whose agent has been
    decommissioned since the scan.

    The host field is added alongside the existing vuln record -- the
    base shape is unchanged, so old clients that only read the vuln
    fields keep working.
    """
    store = get_vulnscan_store()
    # P2-8 淇锛氱洿鎺?ES _id get锛屼笉鍐?list_vulns(10000) 鍏ㄩ噺鎷夊彇鍐嶉亶鍘嗐€?
    f = await store.get_vuln(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    host_meta = None
    try:
        if f.agent_id:
            host_meta = await store.get_host(f.agent_id)
    except Exception:
        host_meta = None
    if host_meta is None and f.hostname:
        # Fallback: try by hostname. list_hosts returns a list, we take
        # the first match. Best-effort; if the agent was decommissioned
        # long ago we just leave host_meta = None.
        try:
            matches = await store.list_hosts(hostname=f.hostname, limit=1)
            host_meta = matches[0] if matches else None
        except Exception:
            host_meta = None

    if host_meta is not None:
        # Return the host as a plain dict (model_dump) so it serialises
        # with the same field names the Host pydantic model uses.
        return {**f.model_dump(), "host": host_meta.model_dump()}
    return f


@router.patch("/vulns/{finding_id}")
async def api_update_vuln_status(
    finding_id: str,
    body: dict,
    current_user=Depends(require_role("admin", "analyst")),
):
    store = get_vulnscan_store()
    new_status = body.get("status", "")
    if new_status not in ("open", "fixed", "accepted"):
        raise HTTPException(status_code=422, detail="Invalid status")
    # P2-8 修复：直接 ES _id get 校验存在性，不再全量拉取。
    existing = await store.get_vuln(finding_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")
    # 2026-07-29 UX upgrade: stamp first/last_fixed_at on fix-class
    # transitions so operators can track SLA and re-open history from
    # the vuln list page without joining the audit log.
    update_fields: dict = {"status": new_status}
    if new_status in ("fixed", "accepted"):
        now_iso = datetime.now(UTC).isoformat()
        if not existing.first_fixed_at:
            update_fields["first_fixed_at"] = now_iso
        update_fields["last_fixed_at"] = now_iso
    await store.update_vuln(finding_id, **update_fields)
    await get_audit_logger().log(
        event_id=finding_id,
        node="vulnscan.router",
        action="update_status",
        actor=current_user.username,
        details={"new_status": new_status, "fields_updated": list(update_fields.keys())},
    )
    return {"status": "ok"}


# -- host stats (2026-07-29 UX upgrade) ---------------------------------------

# Lightweight in-process cache so the host-onboarding page and the
# /host-stats call don't each trigger N ES round-trips. Operators refresh
# the page every few seconds; 30s is a good balance.
_HOST_STATS_CACHE: dict = {"ts": 0.0, "items": []}
_HOST_STATS_TTL_SEC = 30.0


@router.get("/host-stats", response_model=_HostStatsResponse)
async def api_host_stats(current_user=Depends(require_role("admin", "analyst", "viewer"))):
    """Per-group vuln counts and by-severity breakdown.

    Used by the host-onboarding page to render the "业务分布" bar chart
    and by the scan-task list to display a host's business group.

    V9 3.1 (2026-07-30): was an N+1 (one list_hosts call per group);
    now does a fixed number of queries regardless of group count:
      1. list_groups()       -> [{name, member_count, ...}, ...]
      2. list_hosts(group=*) -> build hostname -> group map once
      3. list_vulns(limit=N) -> bucket by hostname once, then group
    Result is still cached for 30s in-process; the cache is per-worker
    so the gain is most visible when groups grow past ~20.
    """
    import time

    now = time.monotonic()
    if now - _HOST_STATS_CACHE["ts"] < _HOST_STATS_TTL_SEC and _HOST_STATS_CACHE["items"]:
        return {"items": _HOST_STATS_CACHE["items"], "cached": True}

    # S-P1-3: shared singleton (was VulnscanStore(), leaking an ES client
    # per /host-stats poll -- this endpoint is hit every 30s by operators).
    store = get_vulnscan_store()
    try:
        groups = await store.list_groups()
    except Exception as exc:
        logger.warning("host_stats_list_groups_failed", error=str(exc))
        groups = []

    # Build hostname -> group map once.
    try:
        all_hosts = await store.list_hosts(limit=2000)
    except Exception as exc:
        logger.warning("host_stats_list_hosts_failed", error=str(exc))
        all_hosts = []
    host_to_group: dict[str, str] = {}
    for h in all_hosts:
        if h.hostname and h.group:
            host_to_group[h.hostname] = h.group

    # Pre-fetch all vulns once; bucket by group in one pass.
    try:
        all_vulns = await store.list_vulns(limit=10000)
    except Exception as exc:
        logger.warning("host_stats_list_vulns_failed", error=str(exc))
        all_vulns = []

    # groups_by_name = {name: {total: n, by_severity: {sev: n}}}
    groups_by_name: dict[str, dict] = {}
    # Seed from list_groups() so empty groups still appear in the
    # response (with member_count from the JOIN).
    for g in groups:
        name = g.get("name") or ""
        if not name:
            continue
        groups_by_name[name] = {
            "member_count": g.get("member_count", 0),
            "total": 0,
            "by_severity": {},
        }
    for v in all_vulns:
        g = host_to_group.get(v.hostname or "")
        if g is None or g not in groups_by_name:
            continue
        sev = v.ai_severity or v.severity or "info"
        groups_by_name[g]["total"] += 1
        groups_by_name[g]["by_severity"][sev] = groups_by_name[g]["by_severity"].get(sev, 0) + 1

    out = [{"group": name, **stats} for name, stats in groups_by_name.items()]

    _HOST_STATS_CACHE["ts"] = now
    _HOST_STATS_CACHE["items"] = out
    return {"items": out, "cached": False}


# -- queue ops (P2) -----------------------------------------------------------


@router.get("/queue/stats")
async def api_queue_stats(current_user=Depends(require_role("admin", "analyst"))):
    """Return queue depth and pending counts. Diagnostic only."""
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        depth = await stream_depth(r)
        pending = await pending_count(r)
    finally:
        await r.aclose()
    return {"depth": depth, "pending": pending}


@router.get("/queue/status/{task_id}")
async def api_queue_status(task_id: str, current_user=Depends(require_role("admin", "analyst"))):
    """Read the short-lived side-channel status. Useful when the canonical
    ES record hasn\'t been written yet."""
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        import json

        raw = await r.get(f"vulnscan:queue:status:{task_id}")
    finally:
        await r.aclose()
    if not raw:
        raise HTTPException(status_code=404, detail="No queue status for task")
    return json.loads(raw)
