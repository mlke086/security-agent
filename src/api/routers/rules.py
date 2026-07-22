"""Rules sync REST endpoints."""

import io
import json
import zipfile

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse

from src.agents.rules_sync import (
    current_rule_version,
    get_rule_pack,
    get_rule_pack_body,
    sync_rules,
    sync_rules_to_all_agents,
)
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


@router.get("/list")
async def api_list_rules(
    category: str | None = Query(None, description="按分类过滤：sys_vuln / baseline"),
    severity: str | None = Query(None, description="按严重等级过滤：critical/high/medium/low/info"),
    q: str | None = Query(None, description="按规则名称 / CVE 模糊搜索"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    """规则列表查询（分页）。

    需求7：规则管理页浏览/搜索具体规则条目。纯查询当前版本 RulePack，无侵入。
    若尚未同步过规则库（version 为 "0" 或无 pack），返回空列表。
    """
    version = await current_rule_version()
    pack = await get_rule_pack(version) if version and version != "0" else None
    rules = list(pack.rules) if pack else []

    if category:
        rules = [r for r in rules if r.category == category]
    if severity:
        rules = [r for r in rules if r.severity == severity]
    if q:
        ql = q.lower()
        rules = [r for r in rules if ql in (r.name or "").lower() or ql in (r.cve or "").lower()]

    total = len(rules)
    start = (page - 1) * page_size
    items = rules[start : start + page_size]
    return {
        "version": version,
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [r.model_dump() for r in items],
    }


@router.post("/sync")
async def api_sync_rules(
    body: dict = {},
    current_user=Depends(require_role("admin")),
):
    source = body.get("source", "nvd")
    version = await sync_rules(source=source)
    pack = await get_rule_pack(version)
    count = len(pack.rules) if pack else 0
    await get_audit_logger().log(
        event_id="rules",
        node="rules.router",
        action="sync",
        actor=current_user.username,
        details={"version": version, "count": count},
    )
    return {"version": version, "count": count}


@router.post("/sync-to-agents")
async def api_sync_to_agents(
    current_user=Depends(require_role("admin", "analyst")),
):
    """需求2.1：手动同步当前规则包到所有在线 agent（强制下发，不依赖心跳）。

    返回 {synced, total, agents: [{agent_id, sent}]}。
    """
    result = await sync_rules_to_all_agents()
    await get_audit_logger().log(
        event_id="rules",
        node="rules.router",
        action="sync_to_agents",
        actor=current_user.username,
        details={"synced": result["synced"], "total": result["total"]},
    )
    return result


@router.post("/import")
async def api_import_rules(
    file: UploadFile = File(..., description="规则库 zip 压缩包"),
    current_user=Depends(require_role("admin")),
):
    """离线导入规则库 zip（需求2.2）。

    支持三种来源的 zip（自动识别）：
      1. 本系统 rulepack：zip 内含 rulepack.json（{rules:[...]}）
      2. NVD 导出：zip 内含 NVD API 导出的 json（{vulnerabilities:[...]}）
      3. GitHub advisory-database：从 github/advisory-database 下载的 zip，
         内含多个 GHSA-*.json（每个是一个 advisory）
    导入时用服务端签名密钥重新签名（agent 用同一密钥验签）。
    """
    from src.agents.rules_sync import parse_imported_data

    content = await file.read()
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=422, detail="无效的 zip 文件")

    # 收集 zip 内所有 json 文件（仅内存读取，不落盘，避免 zip-slip）。
    json_names = [
        n
        for n in zf.namelist()
        if n.endswith(".json") and not n.startswith("__MACOSX") and not n.startswith(".")
    ]
    if not json_names:
        raise HTTPException(status_code=422, detail="zip 内未找到任何 .json 文件")

    # 优先找 rulepack.json / NVD 导出（单文件聚合）；否则按 advisory 多文件聚合。
    parsed_items = []
    # 1. 找 rulepack.json（本系统格式）
    rp = next((n for n in json_names if n.endswith("rulepack.json")), None)
    if rp:
        try:
            data = json.loads(zf.read(rp))
            parsed_items = parse_imported_data(data)
        except Exception:
            pass
    # 2. 找 NVD 导出（含 vulnerabilities 的单文件）
    if not parsed_items:
        for n in json_names:
            try:
                data = json.loads(zf.read(n))
                if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
                    parsed_items = parse_imported_data(data)
                    if parsed_items:
                        break
            except Exception:
                continue
    # 3. GitHub advisory：聚合多个 GHSA-*.json 成 advisories 数组
    if not parsed_items:
        advisories = []
        for n in json_names:
            try:
                data = json.loads(zf.read(n))
                if (
                    isinstance(data, dict)
                    and isinstance(data.get("affected"), list)
                    and (data.get("id") or data.get("aliases"))
                ):
                    advisories.append(data)
            except Exception:
                continue
        if advisories:
            parsed_items = parse_imported_data({"advisories": advisories})

    if not parsed_items:
        raise HTTPException(
            status_code=422,
            detail="未能解析出规则。支持格式：rulepack.json / NVD导出 / GitHub advisory zip",
        )

    # 用解析出的 items 直接发布（已校验为 RuleItem）
    from src.agents.rules_sync import _publish_pack

    try:
        version = await _publish_pack(parsed_items)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"发布失败: {exc}")

    await get_audit_logger().log(
        event_id="rules",
        node="rules.router",
        action="import",
        actor=current_user.username,
        details={"version": version, "count": len(parsed_items), "filename": file.filename},
    )
    return {"version": version, "count": len(parsed_items)}


@router.get("/version")
async def api_current_version(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    ver = await current_rule_version()
    return {"version": ver}


@router.get("/pack/{version}")
async def api_download_pack(
    version: str,
    agent_id: str | None = Query(None, description="agent 下载时传，配合 token 鉴权"),
    token: str | None = Query(None, description="agent_token（agent 下载专用，避免与 JWT 冲突）"),
    authorization: str | None = Header(default=None),
):
    """下载规则包。支持两种鉴权：
      1. 人类用户：Authorization: Bearer <JWT>（admin/analyst）
      2. agent：?agent_id=&token=<agent_token>（复用 validate_agent_token）

    返回的 body 字节必须与 trigger_update_if_outdated 用 sign_bytes 签名的
    body 完全一致，否则 agent Ed25519 验签失败，故统一用 get_rule_pack_body。

    鉴权先于资源存在性检查：无凭证 401、角色不足 403，避免通过 404 探测资源存在。
    """
    # --- 鉴权 ---
    # 三种合法组合：
    #   1. agent: agent_id(query) + Authorization: Bearer <agent_token>(header)
    #   2. agent: agent_id(query) + token(query)  (兼容旧 agent，token 落日志有风险)
    #   3. 人类: Authorization: Bearer <JWT>(header)，角色 admin/analyst
    actor: str | None = None
    if agent_id:
        from src.agents.enroll import validate_agent_token

        # agent_token 优先取 header（不落日志），其次 query（兼容）
        agent_token = None
        if authorization:
            agent_token = authorization.removeprefix("Bearer ").strip()
        elif token:
            agent_token = token
        if agent_token and await validate_agent_token(agent_id, agent_token):
            actor = f"agent:{agent_id}"
    if actor is None and authorization:
        from src.api.auth.jwt import decode_token

        payload = decode_token(authorization.removeprefix("Bearer ").strip())
        if payload and payload.get("role") in ("admin", "analyst"):
            actor = payload.get("sub", "user")
        elif payload:
            # 提供了有效 JWT 但角色不够（如 viewer）-> 403
            raise HTTPException(status_code=403, detail="权限不足：需要 admin 或 analyst")
    if actor is None:
        raise HTTPException(status_code=401, detail="Unauthorized: 需要 JWT 或 agent_token")

    # --- 鉴权通过，取 pack body ---
    body = await get_rule_pack_body(version)
    if not body:
        raise HTTPException(status_code=404, detail="Rule pack not found")

    await get_audit_logger().log(
        event_id="rules",
        node="rules.router",
        action="pack_download",
        actor=actor,
        details={"version": version},
    )
    return PlainTextResponse(content=body, media_type="application/json")
