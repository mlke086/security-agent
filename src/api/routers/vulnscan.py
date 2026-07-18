
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from src.agents.models import (
    ScanIntent,
)
from src.agents.store import get_vulnscan_store
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.orchestration.subgraphs.vulnscan.graph import run_vulnscan

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
    current_user=Depends(require_role("admin", "analyst")),
):
    source = body.get("source", "manual")
    intent_text = body.get("intent_text")
    targets = body.get("targets", [])
    modules = body.get("modules", ["sys_vuln", "baseline"])
    task_id = str(uuid.uuid4())
    import asyncio
    # Pass the same task_id to the subgraph so ES / SSE / reports use one id (P0-VS-2).
    asyncio.create_task(run_vulnscan(
        source=source, intent_text=intent_text,
        targets=targets, modules=modules,
        task_id=task_id,
    ))
    await get_audit_logger().log(
        event_id=task_id, node="vulnscan.router", action="create_task",
        actor=current_user.username,
        details={"source": source, "targets": targets},
    )
    return {"task_id": task_id, "status": "queued"}


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
    store = get_vulnscan_store()
    task = await store.get_task(task_id)
    if not task:
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
        try:
            while True:
                msg = await pubsub.get_message(timeout=15, ignore_subscribe_messages=True)
                if msg:
                    yield f"data: {msg['data']}\n\n"
                else:
                    yield ": heartbeat\n\n"
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
    store = get_vulnscan_store()
    task = await store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await store.update_task(task_id, status="failed", error="Cancelled by user")
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
    findings = await store.list_vulns(task_id=task_id, hostname=hostname, severity=severity, status=status)
    return {"items": [f.model_dump() for f in findings]}


@router.get("/reports/{task_id}")
async def api_get_report(task_id: str, current_user=Depends(require_role("admin", "analyst", "viewer"))):
    store = get_vulnscan_store()
    report = await store.get_report(task_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/vulns/{finding_id}")
async def api_get_vuln(
    finding_id: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_vulnscan_store()
    findings = await store.list_vulns(limit=10000)
    for f in findings:
        if f.finding_id == finding_id:
            return f
    raise HTTPException(status_code=404, detail="Finding not found")


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
    findings = await store.list_vulns(limit=10000)
    found = False
    for f in findings:
        if f.finding_id == finding_id:
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail="Finding not found")
    await store.update_vuln(finding_id, status=new_status)
    await get_audit_logger().log(
        event_id=finding_id, node="vulnscan.router", action="update_status",
        actor=current_user.username,
        details={"new_status": new_status},
    )
    return {"status": "ok"}

