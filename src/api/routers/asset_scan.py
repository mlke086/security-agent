"""Asset-scan API routes (需求②: 内网资产扫描, agentless).

与 vulnscan 路由归属决策一致：gateway 只做 CRUD + 入队 + SSE 转发，
不跑扫描。扫描由 asset-scan 服务的 TaskWorker 消费 ``assetscan:queue:tasks``
执行（LangGraph 子图 + nmap/masscan/nuclei 子进程）。

参数校验（P2-VULN-05 同款防护）：
- targets: IP 或 CIDR，数量 ≤500，单个网段 ≤ /22（防误扫大段）
- ports: 1-65535 整数，≤100 个
- engine: fast | full | global
"""

from __future__ import annotations

import ipaddress
import json

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from src.api.auth.routes import require_role
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.orchestration.task_queue import enqueue_asset_task
from src.orchestration.task_queue.keys import (
    asset_cancel_key,
    asset_status_key,
)

router = APIRouter(prefix="/api/v1/asset-scan", tags=["asset-scan"])
logger = get_logger(__name__)

ENGINES = ("fast", "full", "global")
MODULES = ("discovery", "fingerprint", "cve", "nuclei", "brute")
MAX_TARGETS = 500
MAX_PORTS = 100
MAX_CIDR_PREFIX = 22  # 单网段最小 /22（防误扫 /16 之类大段）


class _AssetTaskCreate(BaseModel):
    targets: list[str] = Field(..., description="IP 或 CIDR 列表")
    ports: list[int] = Field(default_factory=list)
    engine: str = "fast"
    modules: list[str] = Field(default_factory=lambda: ["discovery", "fingerprint", "cve", "nuclei"])
    schedule: str = ""
    source: str = "manual"

    @field_validator("targets")
    @classmethod
    def _check_targets(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("targets 不能为空")
        if len(v) > MAX_TARGETS:
            raise ValueError(f"targets 最多 {MAX_TARGETS} 个")
        for t in v:
            t = t.strip()
            if not t:
                raise ValueError("targets 含空项")
            if "/" in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                except ValueError as exc:
                    raise ValueError(f"无效网段 {t!r}") from exc
                if net.version != 4:
                    raise ValueError("暂仅支持 IPv4")
                if net.prefixlen < MAX_CIDR_PREFIX:
                    raise ValueError(
                        f"网段 {t!r} 前缀 /{net.prefixlen} 过宽，上限 /{MAX_CIDR_PREFIX}"
                    )
            else:
                try:
                    ipaddress.ip_address(t)
                except ValueError as exc:
                    raise ValueError(f"无效 IP {t!r}") from exc
        return [t.strip() for t in v]

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, v: list[int]) -> list[int]:
        if len(v) > MAX_PORTS:
            raise ValueError(f"ports 最多 {MAX_PORTS} 个")
        bad = [p for p in v if not (isinstance(p, int) and 1 <= p <= 65535)]
        if bad:
            raise ValueError(f"ports 越界: {bad}")
        return v

    @field_validator("engine")
    @classmethod
    def _check_engine(cls, v: str) -> str:
        if v not in ENGINES:
            raise ValueError(f"engine 必须是 {'/'.join(ENGINES)}")
        return v

    @field_validator("modules")
    @classmethod
    def _check_modules(cls, v: list[str]) -> list[str]:
        bad = [m for m in v if m not in MODULES]
        if bad:
            raise ValueError(f"modules 含未知项: {bad}")
        return v


def _redis() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


# -- 任务 CRUD ----------------------------------------------------------------


@router.post("/tasks")
async def api_create_asset_task(
    body: _AssetTaskCreate,
    current_user=Depends(require_role("admin", "analyst")),
):
    """入队一个资产扫描任务。返回 ``{task_id, status: "queued"}`` 立即返回。"""
    try:
        envelope = await enqueue_asset_task(
            source=body.source,
            targets=body.targets,
            ports=body.ports,
            engine=body.engine,
            modules=body.modules,
            schedule=body.schedule,
            actor=current_user.username,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset_task_enqueue_failed", error=str(exc))
        raise HTTPException(status_code=503, detail="任务入队失败") from exc
    return {"task_id": envelope.task_id, "status": "queued"}


@router.get("/tasks")
async def api_list_asset_tasks(
    status: str | None = None,
    source: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user=Depends(require_role("admin", "analyst")),
):
    """任务列表（分页/筛选）。"""
    from src.asset_scan.store import get_asset_store

    store = get_asset_store()
    offset = (page - 1) * page_size
    items = await store.list_tasks(
        status=status, source=source, limit=page_size, offset=offset
    )
    total = len(items)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/tasks/{task_id}")
async def api_get_asset_task(
    task_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    """任务详情；enqueue 后 ES 尚未写盘时回退 Redis side-channel。"""
    from src.asset_scan.store import get_asset_store

    store = get_asset_store()
    task = await store.get_task(task_id)
    if not task:
        try:
            r = _redis()
            try:
                payload = await r.get(asset_status_key(task_id))
                if payload:
                    data = json.loads(payload)
                    return {
                        "task_id": task_id,
                        "status": data.get("status", "queued"),
                        "targets": data.get("targets", []),
                        "engine": data.get("engine", ""),
                        "actor": data.get("actor", ""),
                        "side_channel": True,
                        "submitted_at": data.get("submitted_at", ""),
                    }
            finally:
                await r.aclose()
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.post("/tasks/{task_id}/cancel")
async def api_cancel_asset_task(
    task_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    """写取消墓碑（Redis, 24h TTL）。子图各节点入口二次确认后中止。"""
    r = _redis()
    try:
        await r.set(asset_cancel_key(task_id), "1", ex=24 * 3600)
    finally:
        await r.aclose()
    logger.info("asset_task_cancelled", task_id=task_id, actor=current_user.username)
    return {"task_id": task_id, "status": "cancelling"}


@router.delete("/tasks/{task_id}")
async def api_delete_asset_task(
    task_id: str,
    current_user=Depends(require_role("admin")),
):
    """删除任务及其资产/漏洞/报告（ES 级联）。"""
    from src.asset_scan.store import get_asset_store

    store = get_asset_store()
    existing = await store.get_task(task_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Task not found")
    await store.delete_task(task_id)
    r = _redis()
    try:
        await r.delete(asset_cancel_key(task_id), asset_status_key(task_id))
    finally:
        await r.aclose()
    return {"task_id": task_id, "status": "deleted"}


# -- SSE 实时进度 -------------------------------------------------------------


@router.get("/tasks/{task_id}/stream")
async def api_asset_task_stream(task_id: str, token: str = Query(...)):
    from src.api.auth.jwt import decode_token

    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    async def sse_gen():
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        pubsub = r.pubsub()
        try:
            await pubsub.subscribe(f"assetscan:task:{task_id}")
            while True:
                msg = await pubsub.get_message(timeout=10, ignore_subscribe_messages=True)
                if msg:
                    yield f"data: {msg['data']}\n\n"
                else:
                    yield ": heartbeat\n\n"
        finally:
            try:
                await pubsub.unsubscribe(f"assetscan:task:{task_id}")
                await pubsub.close()
            except Exception:  # noqa: BLE001
                pass
            await r.aclose()

    return StreamingResponse(
        sse_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# -- 结果查询 ----------------------------------------------------------------


@router.get("/tasks/{task_id}/assets")
async def api_asset_task_assets(
    task_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    from src.asset_scan.store import get_asset_store

    assets = await get_asset_store().list_assets(task_id)
    return {"task_id": task_id, "items": assets, "count": len(assets)}


@router.get("/tasks/{task_id}/vulns")
async def api_asset_task_vulns(
    task_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    from src.asset_scan.store import get_asset_store

    vulns = await get_asset_store().list_vulns(task_id)
    return {"task_id": task_id, "items": vulns, "count": len(vulns)}


@router.get("/tasks/{task_id}/report")
async def api_asset_task_report(
    task_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    from src.asset_scan.store import get_asset_store

    report = await get_asset_store().get_report(task_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated yet")
    return report
