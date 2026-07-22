"""Agent / Vulnscan REST API endpoints."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from src.agents.enroll import (
    create_enroll_token,
    get_install_script_content,
    peek_enroll_token,
    register_enroll_token,
    validate_enroll_token,
)
from src.agents.manager import (
    create_group,
    decommission_host,
    delete_group,
    delete_host_permanently,
    get_host,
    list_groups,
    list_hosts,
    update_host_group,
)
from src.agents.models import (
    EnrollRequest,
    EnrollResponse,
    EnrollTokenRequest,
    EnrollTokenResponse,
    Host,
    HostStatus,
)
from src.agents.signing import get_public_key_hex
from src.agents.store import get_vulnscan_store
from src.agents.ws_gateway import get_agent_gateway
from src.agents.upgrade import (
    UpgradeNotAvailableError,
    confirm_upgrade_from_heartbeat,
    get_upgrade_status,
    prepare_upgrade,
    record_upgrade_ack,
    update_upgrade_status,
)
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings


# P1 / 2026-07-19: explicit Pydantic models for /upgrade and /config so missing
# or malformed fields return 422 (instead of silently sending an empty
# agent_upgrade / config_update command).
class UpgradeRequest(BaseModel):
    # Server picks the binary and its URL; the operator only confirms the
    # packaged version. Keeping download_url server-derived means a browser
    # can't redirect the Agent to an attacker-controlled host.
    version: str | None = Field(
        default=None,
        description="Optional override; defaults to the currently packaged version",
    )


class AgentConfigRequest(BaseModel):
    heartbeat_interval: int | None = Field(default=None, ge=1, le=3600)
    log_level: str | None = Field(default=None, description="debug|info|warn|error")
    resource_limit: dict | None = None


class GroupCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Group name")


router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


class HostGroupUpdateRequest(BaseModel):
    group: str | None = Field(default=None, description="Target group name; pass null to clear")

    group: str | None = Field(default=None, description="Target group name; pass null to clear")


# ----------------------------------------------------------------------- Enrollment


@router.post("/enroll-tokens", response_model=EnrollTokenResponse)
async def api_create_enroll_token(
    req: EnrollTokenRequest,
    current_user=Depends(require_role("admin")),
):
    """Create an enrollment token (admin only)."""
    token, expires = await create_enroll_token(
        group=req.group,
        ttl_hours=req.ttl_hours,
        uses=req.uses,
    )
    await get_audit_logger().log(
        event_id="agent",
        node="agents.router",
        action="create_enroll_token",
        actor=current_user.username,
        details={"group": req.group, "ttl_hours": req.ttl_hours},
    )
    return EnrollTokenResponse(token=token, expires=expires)


@router.get("/install")
async def api_install_script(
    token: str = Query(...),
    os: str = Query("linux"),
    request: Request = None,  # type: ignore[assignment]
):
    """Return the install script for the given token and OS.

    The script is a self-contained bootstrap. The recommended flow is the two-
    step approach (download-as-file, then execute) so the operator can review
    the script before it runs and so the token never appears in shell history
    beyond the ``curl`` invocation:

        curl -fsSL "<console>/api/v1/agents/install?token=...&os=linux" \
             -o secagent-install.sh
        sudo bash secagent-install.sh

    We also set Content-Disposition so ``curl -O`` saves to a sensible name.
    """
    valid = await peek_enroll_token(token)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.",
        )
    # Prefer the configured external URL (settings.agent_console_external_url)
    # so the generated script points at the canonical, deployable console URL
    # rather than whatever hostname the operator happened to hit. Fall back to
    # the request URL only when the setting is empty (dev / first boot).
    settings = get_settings()
    configured = (settings.agent_console_external_url or "").strip()
    if configured:
        console_url = configured.rstrip("/")
    else:
        host = request.headers.get("host", str(request.url.netloc))
        console_url = f"{request.url.scheme}://{host}"
    script = get_install_script_content(token, os, console_url=console_url)
    filename = "secagent-install.ps1" if os == "windows" else "secagent-install.sh"
    return PlainTextResponse(
        content=script,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/install-helper")
async def api_install_helper(
    token: str = Query(...),
    os: str = Query("linux"),
    request: Request = None,  # type: ignore[assignment]
):
    r"""Return a single shell snippet the operator can copy-paste.

    This is the recommended UX: the snippet is a **two-step** command (download
    as a file, then execute) so the operator can ``cat secagent-install.sh``
    to review before running, and so the token does not end up embedded in
    a piped shell that could be replayed from history.

    Example response body (linux)::

        curl -fsSL "http://console/api/v1/agents/install?token=...&os=linux" \
             -o secagent-install.sh \
          && chmod +x secagent-install.sh \
          && sudo bash secagent-install.sh
    """
    valid = await peek_enroll_token(token)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.",
        )
    settings = get_settings()
    configured = (settings.agent_console_external_url or "").strip()
    if configured:
        console_url = configured.rstrip("/")
    else:
        host = request.headers.get("host", str(request.url.netloc))
        console_url = f"{request.url.scheme}://{host}"
    install_url = f"{console_url}/api/v1/agents/install?token={token}&os={os}"

    # Important: do NOT append "\n" or any newline after the snippet. In a
    # raw f-string that sequence is the two literal characters backslash + n;
    # if pasted into a terminal bash would try to run a file literally named
    # ``secagent-install.sh\n`` -> "No such file or directory". A real
    # newline (chr 10) is fine when deliberately placed between commands (e.g.
    # for PowerShell multi-step), but never at the very end.
    if os == "windows":
        # PowerShell two-step: real newlines between commands (PowerShell
        # users are used to multi-line copy-paste).
        snippet = (
            f"# Run PowerShell as Administrator, then:\n"
            f'Invoke-WebRequest -Uri "{install_url}" -OutFile secagent-install.ps1\n'
            f"Unblock-File .\\secagent-install.ps1\n"
            f".\\secagent-install.ps1"
        )
    else:
        # Linux two-step: SINGLE LINE, no continuations, no trailing newline.
        snippet = rf'curl -fsSL "{install_url}" -o secagent-install.sh && chmod +x secagent-install.sh && sudo bash secagent-install.sh'
    return PlainTextResponse(
        content=snippet,
        media_type="text/plain",
        headers={"Content-Disposition": 'inline; filename="secagent-install.txt"'},
    )


@router.post("/enroll", response_model=EnrollResponse)
async def api_enroll_host(req: EnrollRequest, request: Request):
    """Register a new agent host using an enrollment token.

    P1 (2026-07-17): if the request IP already has a host row (operator
    re-ran the installer), the old row is decommissioned first so the new
    registration replaces it cleanly. This keeps the host list de-duplicated
    by IP and prevents stale offline rows from accumulating.

    P1-6 濞ｅ浂鍠栭ˇ鏌ユ晬濞嗙硽 闁告ê顭烽崳鎼佹偨閵婏附绠涢柛鏃撶磿椤忣剟宕ｉ娆庣箚 IP闁挎稑婀?Forwarded-For 闁?request.client.host闁挎稑顧€缁?    濞戞挸绉虫穱濠冪閺勫浚鍤炴慨鐟板€风紞瀣煂瀹€鈧▓?req.ip -- 闁告熬绠戦崹顖炲绩鐠囨彃姣婇柤鏉挎噽閺併倝宕ラ崼鐔恒€?enroll token 濞寸⒈浜埀?ip 闁告鍟胯ぐ?    decommission_host_by_ip(濞寸姷绮崜鐧穚) 濞戞挸顑囬崵搴㈢缂佹ê澹堥柛锔哄妺妤犲洦绋夌紒妯荤皻闁靛棔鎷積q.ip 濞寸姴鎳嶇紞鏃€绋夐崫鍕綌缂佲偓閾忚鏆?    Host.ip 閻庢稒顨嗛灞剧┍濠靛牊娈岄柨娑樻綂gent 濞戞挸锕ユ慨銈夋儍閸曨厽鍩傞悗鍦仜閸炲绱?IP闁挎稑顒T 闁告艾瀛╁﹢鍥礉閿涘嫷浼傞柣顏勵儎缁楀宕氱敮顔剧闁?    """
    valid = await validate_enroll_token(req.token)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.",
        )

    # 闁规亽鍔岄閬嶅嫉瀹ュ懎顫ょ紒鏃戝灠瑜板弶绌?IP闁挎稒鐭槐顓㈠礂閸粌鏁╅柣鐐叉閻楀孩顨ュ畝鍐畺闁?X-Forwarded-For 濡絾鐗楅宀勬晬鐏炶姤绀€闂侇偀鍋撻柛?    # request.client.host闁靛棗鍊风悮閬嶆嚀閸涙潙鍘村☉鎾崇Т瑜版煡鎮介妸锔筋槯閻犲搫鐤囩换?IP 闁告ê顭烽崳鎼佹晬閸粎鐟濋梻鍐帛閺屽洤鈻旈妸銉ユ杸闁挎稑顦埀?    server_ip = ""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        server_ip = xff.split(",")[0].strip()
    elif request.client and request.client.host:
        server_ip = request.client.host

    # IP-based dedup: drop any previous host row with the same server-side IP.
    if server_ip:
        from src.agents.manager import decommission_host_by_ip

        removed = await decommission_host_by_ip(server_ip)
        if removed > 0:
            from src.common.logging.logger import get_logger as _log

            _log(__name__).info(
                "host_ip_replaced_during_enroll", server_ip=server_ip, removed=removed
            )

    import secrets

    agent_id = f"agent-{uuid.uuid4().hex[:12]}"
    agent_token = secrets.token_urlsafe(32)
    settings = get_settings()

    # Store host in ES + PG. last_heartbeat is set to "now" because the
    # agent just enrolled and is online; without it the Host model defaults to
    # an empty string which crashes asyncpg when written into a timestamptz
    # column -> 500 Internal Server Error on /enroll.
    host = Host(
        agent_id=agent_id,
        hostname=req.hostname,
        ip=req.ip,
        os=req.os,
        arch=req.arch,
        kernel=req.kernel,
        status=HostStatus.ONLINE,
        group=valid.get("group") or None,
        created_at=datetime.now(UTC).isoformat(),
        last_heartbeat=datetime.now(UTC).isoformat(),
        agent_version="0.1.0",
    )
    await get_vulnscan_store().save_host(host)

    # Store agent auth token in PG
    await register_enroll_token(agent_id, agent_token)

    await get_audit_logger().log(
        event_id="agent",
        node="agents.router",
        action="enroll",
        actor="agent",
        details={"agent_id": agent_id, "hostname": req.hostname, "os": req.os},
    )

    ws_url = f"{settings.agent_console_external_url}/api/v1/agents/ws?agent_id={agent_id}&token={agent_token}"
    # P1 (2026-07-17): include current rule_version so the install script
    # can persist it to config.json and the host UI shows a real value
    # immediately (without waiting for the server to push a rule_update).
    try:
        from src.agents.rules_sync import current_rule_version as _cur_ver

        rule_version = await _cur_ver()
    except Exception:
        rule_version = ""
    return EnrollResponse(
        agent_id=agent_id,
        agent_token=agent_token,
        ws_url=ws_url,
        heartbeat_interval=settings.agent_heartbeat_interval,
        # P0-GO-1: ship the server Ed25519 public key so the Go agent can verify
        # signed commands. Without it the agent cannot trust anything sent by the
        # server.
        server_public_key=get_public_key_hex(),
        rule_version=rule_version or "",
    )


# ----------------------------------------------------------------------- Binary Download


@router.get("/binary/{os}/{arch}")
async def api_download_binary(
    os: str,
    arch: str,
    token: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
):
    """Download the agent binary for ``os``/``arch``.

    The enrollment token is accepted via either the ``token`` query param (legacy,
    kept for backward compatibility with older install scripts) or the
    ``Authorization: Bearer <token>`` header. Header-based auth is preferred
    because query params leak into proxy / shell logs.
    """
    effective = _extract_token(token, authorization)
    if not effective:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again."
        )
    valid = await peek_enroll_token(effective)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.",
        )

    settings = get_settings()
    binary_dir = Path(settings.agent_binary_dir)
    ext = ".exe" if os == "windows" else ""
    binary_path = binary_dir / os / arch / f"agent{ext}"

    if not binary_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Binary not available for {os}/{arch}. Build with: cd agent && make build-{os}-{arch}",
        )

    return FileResponse(
        path=str(binary_path),
        media_type="application/octet-stream",
        filename=f"secagent-{os}-{arch}{ext}",
        headers={"X-Agent-Version": "0.1.0"},
    )


@router.get("/ca")
async def api_download_ca(
    token: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
):
    """Download the console CA certificate.

    Token accepted via Authorization header (preferred) or ``token`` query param.
    """
    effective = _extract_token(token, authorization)
    if not effective:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again."
        )
    valid = await peek_enroll_token(effective)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.",
        )

    settings = get_settings()
    ca_path = settings.agent_ca_cert
    if not ca_path or not Path(ca_path).is_file():
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")

    return FileResponse(
        path=ca_path,
        media_type="application/x-pem-file",
        filename="ca.pem",
    )


@router.get("/console-url")
async def api_console_url(request: Request) -> dict:
    """Return the canonical console URL the frontend should embed in install
    commands.

    Priority:
      1. ``settings.agent_console_external_url`` -- the configured, deployable
         URL (set via .env). Use this in production so copy-paste commands work
         from any network the operator might be on.
      2. The current request's origin (``window.location.origin``-equivalent) --
         only when the setting is empty.

    Public endpoint (no auth) so the login page can also call it.
    """
    settings = get_settings()
    configured = (settings.agent_console_external_url or "").strip()
    if configured:
        url = configured.rstrip("/")
        source = "configured"
    else:
        host = request.headers.get("host", str(request.url.netloc))
        url = f"{request.url.scheme}://{host}"
        source = "request"
    return {"console_url": url, "source": source}


# ------------------------------------------------------------------------ Host Management


@router.get("", response_model=dict)
async def api_list_hosts(
    status_filter: str | None = Query(None, alias="status"),
    group: str | None = Query(None),
    include_decommissioned: bool = Query(
        False,
        description="True=show soft-deleted hosts too (used by the admin "
        "缂佺媴绱曢幃濠勬喆閸℃绂?; False=hide them so deletion actually removes the row from the list",
    ),
    current_user=Depends(require_role("admin", "analyst")),
):
    """List enrolled hosts.

    By default ``decommissioned`` hosts are hidden -- clicking 闁告帞濞€濞?makes
    the host disappear from the table. The admin-only 鐎规瓕寮撶粭鍛棯婢剁鐦滈柡?view
    passes ``include_decommissioned=true`` to see the full roster."""
    hosts = await list_hosts(status_filter, group, include_decommissioned=include_decommissioned)
    return {"items": [h.model_dump() for h in hosts]}


# -- Host groups (declared before /{agent_id} so "groups" isn't captured as
#    an agent_id path parameter) --


@router.get("/groups")
async def api_list_groups(
    current_user=Depends(require_role("admin", "analyst")),
):
    """List host groups with member counts."""
    groups = await list_groups()
    return {"items": groups}


@router.post("/groups")
async def api_create_group(
    req: GroupCreateRequest,
    current_user=Depends(require_role("admin")),
):
    """Create a new host group (admin only)."""
    import asyncpg

    try:
        await create_group(req.name, req.description)
    except asyncpg.UniqueViolationError:
        raise HTTPException(
            status_code=409,
            detail="Group already exists",
        )
    await get_audit_logger().log(

        node="agents.router",
        action="create_group",
        actor=current_user.username,
        details={"group": req.name},
    )
    return {"status": "ok"}


@router.delete("/groups/{name}")
async def api_delete_group(
    name: str,
    current_user=Depends(require_role("admin")),
):
    """Delete a host group (admin only).

    P1-4 濞ｅ浂鍠栭ˇ鏌ユ晬濮樿京鐭嬮柛鎰噸缁盯寮垫径澶婄槣闁哄牏鍎ゅ鍌炲箯閹烘梻鍗滈柛鎺斿█濞呭酣鏁嶉崼锝囩闁?409闁挎稑顧€缁辨繈鏌嗛崹顔煎赋 hosts.group_name
    鐎殿喗娲滈弫銈咁啅閹绘帒鐏╃紓浣稿瑜板骞?legacy 閻庢稏鍊曢崝褰掑Υ閸屾稒鎯欏ù锝嗙矊閹叉娊妫侀埀顒勫礂閸絿璁ｇ紒澶岀帛閸ㄣ劍绋夌€ｎ剙娈犵紓浣稿閸炲瓨绋夌紒妯荤皻闁?    """
    remaining = await delete_group(name)
    if remaining > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Group still has {remaining} hosts; remove or reassign them first.",
        )
    await get_audit_logger().log(
        event_id="agent",
        node="agents.router",
        action="delete_group",
        actor=current_user.username,
        details={"group": name},
    )
    return {"status": "ok"}


@router.patch("/{agent_id}")
async def api_update_host(
    agent_id: str,
    body: HostGroupUpdateRequest,
    current_user=Depends(require_role("admin")),
):
    """Move a host to a different group (admin only)."""
    host = await update_host_group(agent_id, body.group)
    if not host:
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")
    await get_audit_logger().log(
        event_id="agent",
        node="agents.router",
        action="update_host_group",
        actor=current_user.username,
        details={"agent_id": agent_id, "group": body.group},
    )
    return {"status": "ok", "host": host.model_dump()}


@router.get("/{agent_id}/token-status")
async def api_agent_token_status(
    agent_id: str,
    current_user=Depends(require_role("admin")),
):
    """Diagnostic: does PG have an agent_token for this agent, and is it
    currently active? Use this when an agent keeps failing the WS handshake
    with 403 -- the three possible outcomes map 1:1 to the agent_auth_*
    warnings emitted by enroll.validate_agent_token.

    Returns:
      { status: "missing" | "revoked" | "active",
        agent_id: ...,
        token_hash_prefix: "ab12cd34" | null,
        issued_at: ISO string | null,
        revoked_at: ISO string | null }
    """
    from src.common.db.pg import get_pg_pool

    pool = await get_pg_pool()
    row = await pool.fetchrow(
        "SELECT token_hash, issued_at, revoked_at FROM agent_tokens WHERE agent_id = $1",
        agent_id,
    )
    if row is None:
        return {
            "status": "missing",
            "agent_id": agent_id,
            "token_hash_prefix": None,
            "issued_at": None,
            "revoked_at": None,
        }
    if row["revoked_at"] is not None:
        return {
            "status": "revoked",
            "agent_id": agent_id,
            "token_hash_prefix": row["token_hash"][:8],
            "issued_at": row["issued_at"].isoformat() if row["issued_at"] else None,
            "revoked_at": row["revoked_at"].isoformat(),
        }
    return {
        "status": "active",
        "agent_id": agent_id,
        "token_hash_prefix": row["token_hash"][:8],
        "issued_at": row["issued_at"].isoformat() if row["issued_at"] else None,
        "revoked_at": None,
    }


@router.get("/{agent_id}", response_model=Host)
async def api_get_host(
    agent_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    """Get a specific host."""
    host = await get_host(agent_id)
    if not host:
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")
    return host


@router.delete("/{agent_id}")
async def api_delete_host(
    agent_id: str,
    purge: bool = Query(False, description="description"),
    current_user=Depends(require_role("admin")),
):
    """Delete a host (admin only).

    闂傚洠鍋撴慨?.4闁挎稒顒猽rge=True 闁哄啫澧庢晶鍧楁偠閸℃鐏╅梻鍕╁€х槐娆愮?decommissioned 濞戞挾绮┃鈧柛蹇庢祰椤斿繘鏁嶆径娑氱purge=False 闁哄啯鍎奸拏瀣礆閻樼粯鐝熼柨娑樼墔缁楀懐鐥崠锛勭闁?    """
    host = await get_host(agent_id)
    if not host:
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")
    if purge:
        # 闁绘せ鏅濋幃濠囧礆閻樼粯鐝熼柨娑欑煯缁骸顔忛煫顓犵憮缂佹儳銇樼€靛矂寮甸崫鍕笒閻犱線娼荤槐婵嬫焼閸喖甯抽悹鍥跺灠閸ㄥ綊宕烽妸褍娈犲☉鎾剁帛濠р偓
        ok = await delete_host_permanently(agent_id)
        if not ok:
            raise HTTPException(
                status_code=422,
                detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.",
            node="agents.router",
            action="delete_permanent",
            actor=current_user.username,
            details={"agent_id": agent_id},
        )
        return {"status": "ok", "purged": True}
    # P1 (F4) -- revoke the persisted token and tell every worker to
    # drop the live WS so a heartbeat or stale scan_result cannot keep
    # the host appearing online. Decommission is still reversible by an
    # explicit re-activate / re-enroll later (see plan V7 1.4).
    from src.agents.revoke import revoke_agent

    await decommission_host(agent_id)
    await revoke_agent(agent_id)
    await get_audit_logger().log(
        event_id="agent",
        node="agents.router",
        action="decommission",
        actor=current_user.username,
        details={"agent_id": agent_id},
    )
    return {"status": "ok"}


@router.post("/{agent_id}/upgrade")
async def api_upgrade_agent(
    agent_id: str,
    body: UpgradeRequest,
    current_user=Depends(require_role("admin")),
):
    """Stage a server-controlled agent_upgrade and dispatch it.

    The signed payload is built from the on-disk Agent binary so the operator
    can't redirect the Agent to an attacker-controlled URL. We also persist a
    Redis status row that the UI polls and the heartbeat handler uses to mark
    the upgrade confirmed once the Agent's new version appears in a heartbeat.
    """
    host = await get_host(agent_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")
    try:
        prepared = prepare_upgrade(host, body.version)
    except UpgradeNotAvailableError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    delivered = await get_agent_gateway().send_to_agent(agent_id, prepared.message)
    state = "sent" if delivered else "queued_for_delivery"
    await update_upgrade_status(
        agent_id,
        state=state,
        target_version=prepared.version,
        message="Upgrade command sent to Agent" if delivered else "Agent offline; will retry on reconnect",
        error="",
    )
    await get_audit_logger().log(
        event_id="agent",
        node="agents.router",
        action="upgrade",
        actor=current_user.username,
        details={"agent_id": agent_id, "version": prepared.version, "delivered": delivered},
    )
    return {
        "status": "ok",
        "version": prepared.version,
        "delivered": delivered,
        "binary_path": str(prepared.binary_path),
    }


@router.get("/{agent_id}/upgrade")
async def api_upgrade_status(
    agent_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    """Return the latest upgrade record for this host (operator UI)."""
    if await get_host(agent_id) is None:
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")
    status = await get_upgrade_status(agent_id)
    return {"agent_id": agent_id, "upgrade": status or {"state": "idle"}}


@router.patch("/{agent_id}/config")
async def api_update_agent_config(
    agent_id: str,
    body: AgentConfigRequest,
    current_user=Depends(require_role("admin")),
):
    """Trigger a config_update command via the WS gateway."""
    from datetime import UTC, datetime

    from src.agents.ws_gateway import get_agent_gateway

    gateway = get_agent_gateway()
    msg = {
        "v": 1,
        "type": "config_update",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "heartbeat_interval": body.heartbeat_interval
            if body.heartbeat_interval is not None
            else 60,
            "log_level": body.log_level,
            "resource_limit": body.resource_limit
            if body.resource_limit is not None
            else {"cpu_percent": 30, "mem_percent": 30},
        },
    }
    ok = await gateway.send_to_agent(agent_id, msg)
    if not ok:
        raise HTTPException(status_code=404, detail="Enroll token mint rate limit exceeded. Wait a few minutes and try again.")
    return {"status": "ok"}


def _extract_token(query_token, authorization_header):
    """Resolve the enrollment token from query param or Authorization header.

    Returns the bearer token if the Authorization header is well-formed and
    contains a non-empty value. Otherwise falls back to the ``token`` query
    parameter. Returns ``None`` if neither is usable.
    """
    if authorization_header:
        scheme, _, value = authorization_header.partition(" ")
        if scheme.lower() == "bearer" and value:
            return value.strip()
    if query_token:
        return query_token.strip()
    return None

