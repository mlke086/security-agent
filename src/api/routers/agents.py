"""Agent / Vulnscan REST API endpoints."""
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, PlainTextResponse

from src.agents.enroll import (
    create_enroll_token,
    get_install_script_content,
    peek_enroll_token,
    register_enroll_token,
    validate_enroll_token,
)
from src.agents.manager import decommission_host, get_host, list_hosts
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
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


# ----------------------------------------------------------------------- Enrollment

@router.post("/enroll-tokens", response_model=EnrollTokenResponse)
async def api_create_enroll_token(
    req: EnrollTokenRequest,
    current_user=Depends(require_role("admin")),
):
    """Create an enrollment token (admin only)."""
    token, expires = await create_enroll_token(
        group=req.group, ttl_hours=req.ttl_hours, uses=req.uses,
    )
    await get_audit_logger().log(
        event_id="agent", node="agents.router", action="create_enroll_token",
        actor=current_user.username,
        details={"group": req.group, "ttl_hours": req.ttl_hours},
    )
    return EnrollTokenResponse(token=token, expires=expires)


@router.get("/install")
async def api_install_script(
    token: str = Query(...), os: str = Query("linux"),
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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid or expired enrollment token")
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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid or expired enrollment token")
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
            f'# Run PowerShell as Administrator, then:\n'
            f'Invoke-WebRequest -Uri "{install_url}" -OutFile secagent-install.ps1\n'
            f'Unblock-File .\\secagent-install.ps1\n'
            f'.\\secagent-install.ps1'
        )
    else:
        # Linux two-step: SINGLE LINE, no continuations, no trailing newline.
        snippet = (
            rf'curl -fsSL "{install_url}" -o secagent-install.sh && chmod +x secagent-install.sh && sudo bash secagent-install.sh'
        )
    return PlainTextResponse(
        content=snippet,
        media_type="text/plain",
        headers={"Content-Disposition": 'inline; filename="secagent-install.txt"'},
    )


@router.post("/enroll", response_model=EnrollResponse)
async def api_enroll_host(req: EnrollRequest):
    """Register a new agent host using an enrollment token.

    P1 (2026-07-17): if the request IP already has a host row (operator
    re-ran the installer), the old row is decommissioned first so the new
    registration replaces it cleanly. This keeps the host list de-duplicated
    by IP and prevents stale offline rows from accumulating.
    """
    valid = await validate_enroll_token(req.token)
    if not valid:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid or expired enrollment token")

    # IP-based dedup: drop any previous host row with the same IP BEFORE
    # creating the new row so PG keeps a single current record per IP.
    # We keep the new agent_id; the agent_token on the old host is no
    # longer useful since the operator has the new one.
    if req.ip:
        from src.agents.manager import decommission_host_by_ip
        removed = await decommission_host_by_ip(req.ip)
        if removed > 0:
            from src.common.logging.logger import get_logger as _log
            _log(__name__).info("host_ip_replaced_during_enroll", ip=req.ip, removed=removed)

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
        event_id="agent", node="agents.router", action="enroll",
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
    os: str, arch: str,
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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Missing enrollment token")
    valid = await peek_enroll_token(effective)
    if not valid:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid or expired enrollment token")

    settings = get_settings()
    binary_dir = Path(settings.agent_binary_dir)
    ext = ".exe" if os == "windows" else ""
    binary_path = binary_dir / os / arch / f"agent{ext}"

    if not binary_path.is_file():
        raise HTTPException(status_code=404, detail=f"Binary not available for {os}/{arch}. Build with: cd agent && make build-{os}-{arch}")

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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Missing enrollment token")
    valid = await peek_enroll_token(effective)
    if not valid:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid or expired enrollment token")

    settings = get_settings()
    ca_path = settings.agent_ca_cert
    if not ca_path or not Path(ca_path).is_file():
        raise HTTPException(status_code=404, detail="CA certificate not configured or not found")

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
    current_user=Depends(require_role("admin", "analyst")),
):
    """List enrolled hosts."""
    hosts = await list_hosts(status_filter, group)
    return {"items": [h.model_dump() for h in hosts]}


@router.get("/{agent_id}", response_model=Host)
async def api_get_host(
    agent_id: str,
    current_user=Depends(require_role("admin", "analyst")),
):
    """Get a specific host."""
    host = await get_host(agent_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.delete("/{agent_id}")
async def api_delete_host(
    agent_id: str,
    current_user=Depends(require_role("admin")),
):
    """Decommission a host (admin only)."""
    host = await get_host(agent_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    await decommission_host(agent_id)
    await get_audit_logger().log(
        event_id="agent", node="agents.router", action="decommission",
        actor=current_user.username,
        details={"agent_id": agent_id},
    )
    return {"status": "ok"}


@router.post("/{agent_id}/upgrade")
async def api_upgrade_agent(
    agent_id: str,
    body: dict,
    current_user=Depends(require_role("admin")),
):
    """Trigger an agent_upgrade command via the WS gateway."""
    from datetime import UTC, datetime

    from src.agents.ws_gateway import get_agent_gateway
    gateway = get_agent_gateway()
    version = body.get("version", "")
    download_url = body.get("download_url", "")
    msg = {
        "v": 1,
        "type": "agent_upgrade",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {"version": version, "download_url": download_url},
    }
    ok = await gateway.send_to_agent(agent_id, msg)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not connected or unreachable")
    return {"status": "ok"}


@router.patch("/{agent_id}/config")
async def api_update_agent_config(
    agent_id: str,
    body: dict,
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
            "heartbeat_interval": body.get("heartbeat_interval", 60),
            "resource_limit": body.get("resource_limit", {"cpu_percent": 30, "mem_percent": 30}),
        },
    }
    ok = await gateway.send_to_agent(agent_id, msg)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not connected or unreachable")
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
