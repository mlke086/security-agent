"""Pydantic models for the vulnerability scanning subsystem."""
from enum import Enum
from typing import Literal

from pydantic import BaseModel


class HostStatus(str, Enum):
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


class ScanModule(str, Enum):
    SYS_VULN = "sys_vuln"
    BASELINE = "baseline"


class ScanPolicy(BaseModel):
    modules: list[ScanModule] = [ScanModule.SYS_VULN, ScanModule.BASELINE]
    resource_limit: dict = {"cpu_percent": 30, "mem_percent": 30}
    time_window: str | None = None
    timeout_sec: int = 1800


class ScanTask(BaseModel):
    task_id: str
    source: Literal["dialog", "manual"]
    intent_text: str | None = None
    targets: list[str] = []
    policy: ScanPolicy = ScanPolicy()
    rule_version: str = ""
    status: Literal["queued","dispatching","scanning","analyzing","completed","failed"] = "queued"
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
    server_public_key: str = ''
    # P1 (2026-07-17): current rule_version the agent should bootstrap with.
    # Without this the host UI shows "-" until the server pushes a
    # rule_update command (which may never happen if the agent never gets
    # that command).
    rule_version: str = ''

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
