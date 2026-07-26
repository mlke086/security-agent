"""Pydantic models for the vulnerability scanning subsystem."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel


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
    last_heartbeat: str = ""
    group: str | None = None
    owner: str | None = None
    env: str | None = None
    created_at: str = ""


class ScanModule(StrEnum):
    SYS_VULN = "sys_vuln"
    BASELINE = "baseline"


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
    policy: ScanPolicy = ScanPolicy()
    rule_version: str = ""

    # P0 (2026-07-18): engine selector for nuclei integration.
    engine: Literal["matcher", "nuclei"] = "matcher"

    # Nuclei-only knobs. Ignored when engine == "matcher".
    nuclei_severity: list[str] = []  # ["critical","high",...]
    nuclei_tags: list[str] = []  # ["rce","auth-bypass",...]
    nuclei_templates: list[str] = []  # ["cves/2024/CVE-...","exposures/..."]
    nuclei_timeout_sec: int = 0  # 0 = runner default (600s)

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


class ScanResult(BaseModel):
    task_id: str
    agent_id: str
    hostname: str
    findings: list[VulnFinding]
    batch: int
    is_final: bool
    ts: str = ""


class ScanReport(BaseModel):
    task_id: str
    summary: str = ""
    ai_analysis: str = ""
    stats: dict = {}
    top_vulns: list[dict] = []
    recommendations: list[str] = []
    generated_at: str = ""


class ScanIntent(BaseModel):
    targets: list[str] = []
    modules: list[ScanModule] = [ScanModule.SYS_VULN, ScanModule.BASELINE]
    resource_limit: dict = {"cpu_percent": 30, "mem_percent": 30}
    schedule: str | None = None


class EnrollTokenRequest(BaseModel):
    group: str | None = None
    ttl_hours: int = 24
    uses: int = 1


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
from enum import StrEnum as _StrEnum


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
    source: AlertSource = AlertSource.UNKNOWN
    payload: dict


class AlertIngestResponse(BaseModel):
    alert_id: str
    received_at: str
    severity: AlertSeverity
