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

from src.agents.models import (
    ScanIntent,
)
from src.agents.store import get_vulnscan_store
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
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

router = APIRouter(prefix="/api/v1/vulnscan", tags=["vulnscan"])


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
        )
        return {"task_id": task_id, "status": "completed", "engine": engine, "sync": True}

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


@router.get("/tasks")
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
        # 检查任务是否已终态（completed/failed），若是则推送最终事件后结束流，
        # 主动关闭连接 -- 避免监控页离开后 SSE 长连接泄漏（尤指 vite proxy
        # 转发时客户端 close 后端连接未及时断开，累积占满连接数致系统卡死）。
        store = get_vulnscan_store()
        last_status = ""
        try:
            while True:
                msg = await pubsub.get_message(timeout=10, ignore_subscribe_messages=True)
                if msg:
                    yield f"data: {msg['data']}\n\n"
                else:
                    yield ": heartbeat\n\n"
                # 每 10s 检查任务状态，终态则结束流
                try:
                    task = await store.get_task(task_id)
                    if task and task.status in ("completed", "failed", "cancelled"):
                        if last_status != task.status:
                            import json as _json

                            yield f"data: {_json.dumps({'type': 'task_done', 'task_id': task_id, 'status': task.status})}\n\n"
                            last_status = task.status
                        # 终态后发一次结束事件即 break，关闭连接
                        break
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


@router.get("/results")
async def api_list_results(
    task_id: str | None = Query(None),
    hostname: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_vulnscan_store()
    findings = await store.list_vulns(
        task_id=task_id, hostname=hostname, severity=severity, status=status
    )
    return {"items": [f.model_dump() for f in findings]}


@router.get("/reports/{task_id}")
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
  <div class="meta">任务 ID：{esc(task_id)}　|　生成时间：{esc(report.generated_at or '')}</div>

  <h2>扫描摘要</h2>
  <div class="summary">
    {esc(report.summary or '无摘要')}
  </div>
  {f'<div class="ai"><strong>AI 分析：</strong>{esc(report.ai_analysis)}</div>' if report.ai_analysis else ''}

  <h2>统计概览</h2>
  <table>
    <tr><th>严重等级</th><th>数量</th></tr>
    {sev_rows}
    <tr><td>已过滤(误报)</td><td>{esc(stats.get('filtered_out', 0))}</td></tr>
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


@router.get("/vulns/{finding_id}")
async def api_get_vuln(
    finding_id: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_vulnscan_store()
    # P2-8 修复：直接 ES _id get，不再 list_vulns(10000) 全量拉取再遍历。
    f = await store.get_vuln(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
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
    if not await store.get_vuln(finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    await store.update_vuln(finding_id, status=new_status)
    await get_audit_logger().log(
        event_id=finding_id,
        node="vulnscan.router",
        action="update_status",
        actor=current_user.username,
        details={"new_status": new_status},
    )
    return {"status": "ok"}


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
