"""Pydantic models for the vulnerability scanning subsystem."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

# V9 4.3 / V10 4.3 (2026-07-30): re-export the canonical ``Role``
# alias from src.api.auth.jwt so there is one role literal in the
# codebase. Defining it here as well would let the two drift apart
# silently. The canonical definition lives in
# ``src/api/auth/jwt.py:Role`` -- new code SHOULD import that one
# directly (``from src.api.auth.jwt import Role``). The
# ``RoleLiteral`` name here is kept for back-compat with modules
# that pre-date the V9 4.3 re-export; do not add new callers of it.
from src.api.auth.jwt import Role as RoleLiteral  # noqa: F401


class HostStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    DECOMMISSIONED = "decommissioned"


class Host(BaseModel):
    agent_id: str
    hostname: str
    ip: str
    os: str
    arch: str
    kernel: str
    status: HostStatus = HostStatus.ONLINE
    agent_version: str = ""
    rule_version: str = ""
    # 2026-07-29 UX upgrade: business groups this scan targets,
    # derived from the targets at enqueue time so the task list page
    # can render the column without an N+1 host lookup. Optional /
    # empty for legacy / dialog-driven tasks where the group isn't
    # known up front.
    target_groups: list[str] = []
    last_heartbeat: str = ""
    group: str | None = None
    owner: str | None = None
    env: str | None = None
    created_at: str = ""


class ScanModule(StrEnum):
    SYS_VULN = "sys_vuln"
    BASELINE = "baseline"
    # V9 5.3 (2026-07-30): preserve the engine source on the wire.
    # Previously a Nuclei finding arriving with category="nuclei"
    # was silently rewritten to "sys_vuln" because the ws_gateway
    # whitelist only knew about those two values. Frontend already
    # special-cases "nuclei" in scan reports.
    NUCLEI = "nuclei"


class ScanPolicy(BaseModel):
    modules: list[ScanModule] = [ScanModule.SYS_VULN, ScanModule.BASELINE]
    resource_limit: dict = {"cpu_percent": 30, "mem_percent": 30}
    time_window: str | None = None
    timeout_sec: int = 1800


class ScanTask(BaseModel):
    task_id: str
    # Default to "manual" so callers (tests, internal builders) don't have to
    # pass it explicitly. "dialog" is still accepted when the orchestrator
    # starts a scan from a natural-language intent.
    source: Literal["dialog", "manual"] = "manual"
    intent_text: str | None = None
    targets: list[str] = []
    # 2026-07-29 UX upgrade: business groups this scan targets,
    # derived from the targets at enqueue time so the task list page
    # can render the column without an N+1 host lookup. Optional /
    # empty for legacy / dialog-driven tasks where the group is not
    # known up front.
    target_groups: list[str] = []
    policy: ScanPolicy = ScanPolicy()
    rule_version: str = ""

    # P0 (2026-07-18): engine selector for nuclei integration.
    engine: Literal["matcher", "nuclei", "global"] = "matcher"

    # Nuclei-only knobs. Ignored when engine == "matcher".
    nuclei_severity: list[str] = []  # ["critical","high",...]
    nuclei_tags: list[str] = []  # ["rce","auth-bypass",...]
    nuclei_templates: list[str] = []  # ["cves/2024/CVE-...","exposures/..."]
    nuclei_timeout_sec: int = 0  # 0 = runner default (600s)
    # Nuclei ???????? = agent ??????????????
    # ?????????????? nuclei ???agent ? ss -tlnpH ????
    nuclei_ports: list[int] = []

    status: Literal[
        "queued",
        "dispatching",
        "scanning",
        "analyzing",
        "cancelling",
        "cancelled",
        "completed",
        "failed",
    ] = "queued"
    stats: dict = {"total": 0, "done": 0, "failed": 0}
    created_at: str = ""
    finished_at: str | None = None
    error: str | None = None


class VulnFinding(BaseModel):
    finding_id: str
    task_id: str
    agent_id: str
    hostname: str
    category: ScanModule
    cve: str | None = None
    name: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    ai_severity: str | None = None
    ai_filtered: bool = False
    evidence: str = ""
    fix_advice: str | None = None
    status: Literal["open", "fixed", "accepted"] = "open"
    detected_at: str = ""
    # ---- Scan consolidation (2026-07-31 UX upgrade) ----
    # scan_history records the detection timestamps from earlier scans of the
    # same (agent, cve, name) on the same host. It deliberately excludes the
    # current detected_at (which is the latest scan); the frontend shows
    # detected_at + scan_history as the full "scanned at" timeline. Old docs
    # that lack the field load with scan_history=[] so the merge logic treats
    # them as first-time finds.
    scan_history: list[str] = []
    # V12 阶段 5.7 (2026-08-02): the reconcile merge used to OVERWRITE
    # task_id with the latest scanning task, so the task that first found
    # the vuln could no longer see it (monitor page showed 0 findings while
    # the report -- a completion snapshot -- still had them). task_id now
    # keeps its ORIGINAL owner; last_seen_task_id records the most recent
    # scan that confirmed the vuln. Query layer matches either.
    last_seen_task_id: str | None = None
    # ---- AI evidence (2026-07-29 UX upgrade) ----
    # ai_processed distinguishes "AI handled this row" from "the row was
    # never seen by AI" (e.g. LLM unavailable -> fallback in the subgraph).
    # Old documents that lack the field load with ai_processed=False and
    # ai_reason=None, so the frontend can render the "AI 待分析" badge.
    ai_processed: bool = False
    ai_reason: str | None = None
    ai_fix_summary: str | None = None
    # V13 fix: None instead of "" -- ES mapped this as a date; an empty
    # string is not a parseable date and 400s the whole document write.
    ai_processed_at: str | None = None
    # ---- Fix tracking (2026-07-29 UX upgrade) ----
    # first_fixed_at is the first time status transitioned to fixed/accepted;
    # last_fixed_at is the most recent such transition. Operators can use
    # these to track SLA / re-open history without joining the audit log.
    first_fixed_at: str | None = None
    last_fixed_at: str | None = None


@dataclass(frozen=True)
class VulnFilter:
    """Filter bundle for ``VulnscanStore.list_vulns`` (V10 阶段 1.1).

    Replaces 11 positional kwargs (Data Clump) with one immutable
    container so the router / store / test layers can't drift out
    of sync silently. ``frozen=True`` prevents a caller from
    mutating the filter after construction (the store reads it more
    than once during ES query building). Use ``dataclasses.replace``
    to derive a paged variant.
    """

    task_id: str | None = None
    hostname: str | None = None
    hostnames: list[str] | None = None
    # Server-side batch fetch of all existing vulns for a set of agents
    # (used by the aggregate reconcile step; avoids per-finding N+1).
    agent_ids: list[str] | None = None
    # Exact single-agent filter (host drill-down view). agent_id is the
    # stable unique host key, unlike hostname which can repeat across
    # groups/renames, so the drill-down always targets one host.
    agent_id: str | None = None
    severity: str | None = None
    status: str | None = None
    cve: str | None = None
    cve_keyword: str | None = None
    hostname_keyword: str | None = None
    name_keyword: str | None = None
    ai_processed: bool | None = None
    date_from: str | None = None
    date_to: str | None = None
    limit: int = 200
    offset: int = 0
    # Cursor paging (Spec-P1-RECON): when set, the store scrolls with
    # search_after instead of from_/size, so callers can page through
    # the full result set without the 10k default window. The cursor
    # value comes verbatim from the previous page's last hit sort keys.
    search_after: list | None = None


class ScanResult(BaseModel):
    task_id: str
    agent_id: str
    hostname: str
    findings: list[VulnFinding]
    batch: int
    is_final: bool
    ts: str = ""
    # Categories this agent actually completed scanning (sys_vuln / baseline /
    # nuclei). Reported by the agent on its is_final result. Empty for legacy
    # agents -> the server conservatively skips auto-fix for that agent so a
    # module that failed collection is not misjudged as "fixed".
    scanned_categories: list[str] = []


class ScanReport(BaseModel):
    task_id: str
    summary: str = ""
    ai_analysis: str = ""
    stats: dict = {}
    top_vulns: list[dict] = []
    recommendations: list[str] = []
    generated_at: str = ""
    # ---- AI evidence (2026-07-29 UX upgrade) ----
    # ai_processed separates AI-generated reports from the LLM-unavailable
    # template fallback. ai_overall_advice is the business-level "why this
    # matters and what to do next" content, separate from the structured
    # recommendations[] list (which is rule-driven by severity). The UI
    # renders both in the same card but as two blocks so operators can tell
    # the difference at a glance.
    ai_processed: bool = False
    ai_model: str = ""
    ai_overall_advice: str = ""
    # V13 fix: None instead of "" (ES date mapping rejects empty string).
    ai_processed_at: str | None = None


class ScanIntent(BaseModel):
    targets: list[str] = []
    modules: list[ScanModule] = [ScanModule.SYS_VULN, ScanModule.BASELINE]
    # V13: three engines -- matcher (own CVE rule engine), nuclei (Nuclei
    # CLI, default all ports), global (matcher + nuclei together). The
    # tasks endpoint accepts the same three values; keep the parse
    # contract in sync (Spec-P2-ENGINE).
    engine: Literal["matcher", "nuclei", "global"] = "matcher"
    resource_limit: dict = {"cpu_percent": 30, "mem_percent": 30}
    schedule: str | None = None
    # V13: nuclei knobs carried from the intent parse so the confirm card
    # pre-fills them (empty = defaults). nuclei_ports: empty = all ports,
    # else explicit 1-65535 list ("nuclei 默认全部端口，可指定端口").
    # Element constraint = model-level backstop; the router and frontend
    # also filter before the value reaches the agent command line.
    nuclei_ports: list[Annotated[int, Field(ge=1, le=65535)]] = []
    nuclei_severity: list[str] = []
    nuclei_tags: list[str] = []
    nuclei_templates: list[str] = []
    nuclei_timeout_sec: int = 0


class EnrollTokenRequest(BaseModel):
    group: str | None = None
    # ttl_hours: 0 falls back to the server default (24h); max 168h = 1 week.
    ttl_hours: int = Field(
        default=24, ge=0, le=168, description="Token lifetime in hours; 0 falls back to the default"
    )
    uses: int = Field(
        default=1,
        ge=1,
        le=10000,
        description="Max number of agents that can enroll with this token",
    )


class EnrollTokenResponse(BaseModel):
    token: str
    expires: str


class EnrollRequest(BaseModel):
    token: str
    hostname: str
    os: str
    arch: str
    ip: str
    kernel: str


class EnrollResponse(BaseModel):
    agent_id: str
    agent_token: str
    ws_url: str
    heartbeat_interval: int
    # P0-GO-1: server Ed25519 public key (hex).
    server_public_key: str = ""
    # P1 (2026-07-17): current rule_version the agent should bootstrap with.
    # Without this the host UI shows "-" until the server pushes a
    # rule_update command (which may never happen if the agent never gets
    # that command).
    rule_version: str = ""


class RulesSyncRequest(BaseModel):
    source: str = "nvd"


class RulesSyncResponse(BaseModel):
    version: str
    count: int


class WSMessage(BaseModel):
    v: int = 1
    type: str
    ts: str = ""
    sig: str = ""
    payload: dict = {}


class ScanStep(BaseModel):
    task_id: str
    step: str
    status: str
    message: str = ""


class RuleCheck(BaseModel):
    type: str
    name: str = ""
    op: str = "lt"
    value: str = ""
    file: str = ""
    pattern: str = ""
    expect: str = ""


class RuleItem(BaseModel):
    id: str
    category: str
    cve: str | None = None
    name: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    check: RuleCheck
    fix: str = ""


class RulePack(BaseModel):
    version: str
    rules: list[RuleItem]
    signature: str = ""
    published_at: str = ""


# ============================================================
# Agent monitoring / EDR alert model (Phase 0 of
# docs/Agent监控告警改造方案.md). All fields are source-agnostic;
# edr_adapter/* in src/preprocessing normalizes vendor JSON into
# this shape before persistence.
# ============================================================
from enum import StrEnum as _StrEnum  # noqa: E402,I001 -- project convention: section-scoped dependency marker (V10 4.4)


class AlertSeverity(_StrEnum):
    """Standard severity levels across all EDR sources."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(_StrEnum):
    """Operator workflow state for an alert."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertSource(_StrEnum):
    """Where the alert originated. Phase 1 wires Wazuh/Elkeid/Syslog;
    Phase 2 adds the in-house secagent source; Phase 4 adds the rest."""

    WAZUH = "wazuh"
    ELKEID = "elkeid"
    ELASTIC = "elastic"
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    SYSLOG = "syslog"
    SECAGENT = "secagent"
    UNKNOWN = "unknown"


class AlertIOC(BaseModel):
    """Indicators of Compromise extracted from the alert payload."""

    ips: list[str] = []
    domains: list[str] = []
    hashes: list[str] = []
    urls: list[str] = []
    emails: list[str] = []
    users: list[str] = []


class Alert(BaseModel):
    """Normalized alert. One row per source alert, regardless of vendor."""

    alert_id: str  # primary key; deterministic from source when possible
    source: AlertSource
    title: str
    description: str = ""
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.NEW
    occurred_at: str  # when the alert happened in the source system
    received_at: str  # when SecAgent received it (ISO 8601 UTC)
    hostname: str = ""
    host_ip: str = ""
    agent_id: str = ""
    rule_id: str = ""
    rule_name: str = ""
    category: str = ""
    mitre_attack: list[str] = []  # ATT&CK technique IDs, e.g. T1059
    iocs: AlertIOC = AlertIOC()
    tags: list[str] = []
    source_url: str = ""
    # Original payload kept for audit / forensic. May be large; PG stores as JSONB,
    # ES has a separate field with mapping disabled to keep size bounded.
    raw: dict = {}


class AlertIngestRequest(BaseModel):
    """Webhook payload from a third-party EDR. The "source" field tells
    the server which adapter to use for normalization. Vendors that do not
    supply source metadata may rely on the URL path (see router)."""

    source: str = ""  # any vendor name; normalize() maps UNKNOWN on miss
    payload: dict


class AlertIngestResponse(BaseModel):
    alert_id: str
    received_at: str
    severity: AlertSeverity


# ---- User management (Phase 6, 2026-07-28) ----
# V9 4.3 / V10 4.3 (2026-07-30): RoleLiteral re-exported from
# src.api.auth.jwt (top-of-module import below) so the two
# definitions can't drift apart silently. New code should use
# ``Role`` directly; ``RoleLiteral`` is preserved for back-compat
# and SHOULD NOT gain new callers.


class UserPublic(BaseModel):
    """API representation of a user (no password)."""

    username: str
    role: RoleLiteral
    disabled: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_login_at: datetime | None = None
    deleted_at: datetime | None = None


class UserCreate(BaseModel):
    """POST /api/v1/users body. Admin only."""

    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=12, max_length=128)
    role: RoleLiteral = "viewer"


class UserUpdate(BaseModel):
    """PATCH /api/v1/users/{username} body. Admin only."""

    username: str | None = Field(
        default=None, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$"
    )
    role: RoleLiteral | None = None
    disabled: bool | None = None


class ChangePasswordRequest(BaseModel):
    """POST /api/v1/users/me/password body. Any user."""

    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class UserListResponse(BaseModel):
    items: list[UserPublic]
    count: int
