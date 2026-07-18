"""Rules sync REST endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from src.agents.rules_sync import (
    current_rule_version,
    get_rule_pack,
    sync_rules,
    verify_pack_signature,
)
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


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
        event_id="rules", node="rules.router", action="sync",
        actor=current_user.username,
        details={"version": version, "count": count},
    )
    return {"version": version, "count": count}


@router.get("/version")
async def api_current_version(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
):
    ver = await current_rule_version()
    return {"version": ver}


@router.get("/pack/{version}")
async def api_download_pack(
    version: str,
):
    pack = await get_rule_pack(version)
    if not pack:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    # Verify signature before serving
    valid = await verify_pack_signature(pack)
    if not valid:
        raise HTTPException(status_code=422, detail="Pack signature invalid")
    import json
    return PlainTextResponse(content=json.dumps(pack.model_dump(), ensure_ascii=False), media_type="application/json")
