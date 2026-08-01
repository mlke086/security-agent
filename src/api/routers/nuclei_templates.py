"""Nuclei 模板库 REST API：列表/搜索、详情、编辑、联网更新、手动导入、版本。

模板元数据 + 原文存 ES（nuclei-templates 索引）。编辑只改 ES（本地），
不下发到 agent（agent 仍走整包 nuclei_templates_update）。
"""

import zipfile
from io import BytesIO

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from src.agents import nuclei_templates as nt
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger

router = APIRouter(prefix="/api/v1/nuclei-templates", tags=["nuclei-templates"])

# S-P1-6 (V12): a legitimate 13k-template bundle is 50-200MB; anything over
# 500MB is a zip bomb / misconfigured mirror and must be rejected before the
# body is buffered or inflated.
MAX_TEMPLATES_UPLOAD_BYTES = 500 * 1024 * 1024


@router.get("")
async def api_list_templates(
    category: str | None = Query(
        None, description="按分类过滤：cves / exposures / workflows / ..."
    ),
    q: str | None = Query(None, description="按名称 / 模板ID / 路径模糊搜索"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """模板列表（ES manifest，支持分类 + 全文搜索 + 分页）。"""
    return await nt.list_templates(category, q, page, page_size)


@router.get("/version")
async def api_version(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """当前模板库版本。"""
    return {"version": await nt.current_version()}


@router.post("/sync")
async def api_sync_from_mirror(
    current_user=Depends(require_role("admin")),
):
    """联网更新：从内网下载站拉取 nuclei-templates-{version}.zip 并入库。"""
    try:
        result = await nt.sync_from_mirror()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    await get_audit_logger().log(
        event_id="nuclei-templates",
        node="nuclei_templates.router",
        action="sync",
        actor=current_user.username,
        details={"version": result["version"], "count": result["count"]},
    )
    return result


@router.post("/import")
async def api_import_zip(
    file: UploadFile = File(..., description="nuclei-templates zip 压缩包"),
    current_user=Depends(require_role("admin")),
):
    """手动导入 zip：解析 + 版本校验 + 入库 ES。"""
    # S-P1-6 (V12): reject oversized uploads by Content-Length before the
    # body is buffered (a zip bomb must never reach _ingest).
    if file.size is not None and file.size > MAX_TEMPLATES_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="zip 超过 500MB 上限")
    content = await file.read()
    if len(content) > MAX_TEMPLATES_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="zip 超过 500MB 上限")
    try:
        zip_obj = zipfile.ZipFile(BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=422, detail="无效的 zip 文件")
    # 仅校验可解压，真实解析交给 import_zip。
    if not zip_obj.namelist():
        raise HTTPException(status_code=422, detail="zip 内无文件")
    try:
        result = await nt.import_zip(content, file.filename or "")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    await get_audit_logger().log(
        event_id="nuclei-templates",
        node="nuclei_templates.router",
        action="import",
        actor=current_user.username,
        details={
            "version": result["version"],
            "count": result["count"],
            "upgraded": result.get("upgraded"),
            "filename": file.filename,
        },
    )
    return result


@router.get("/{path:path}")
async def api_get_template(
    path: str,
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """单条模板详情：元数据 + Nacos 原文内容。"""
    tmpl = await nt.get_template(path)
    if not tmpl:
        raise HTTPException(status_code=404, detail="模板不存在")
    return tmpl


@router.put("/{path:path}")
async def api_save_template(
    path: str,
    body: dict,
    current_user=Depends(require_role("admin", "analyst")),
):
    """编辑保存模板：写 Nacos + 更新 manifest 元数据。不下发到 agent。"""
    content = body.get("content")
    if content is None:
        raise HTTPException(status_code=422, detail="缺少 content 字段")
    try:
        result = await nt.save_template(path, content)
    except ValueError as exc:
        # S-P1-EDIT (V12): invalid YAML / missing id is a client error -> 422
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    await get_audit_logger().log(
        event_id="nuclei-templates",
        node="nuclei_templates.router",
        action="edit",
        actor=current_user.username,
        details={"path": path, "template_id": result.get("template_id", "")},
    )
    return result
