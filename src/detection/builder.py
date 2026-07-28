"""Alert builder (Phase 3 of monitoring plan).

When a Sigma rule matches, build an Alert with:
  alert_id from rule_id + event_id (stable)
  severity from rule.level mapped onto AlertSeverity
  IOC list pulled from the rule declared fields
  hostname/host_ip/agent_id best-effort extracted from event
  source = secagent (our own Agent in this MVP)
"""
import hashlib
from datetime import datetime, UTC

from src.agents.models import Alert, AlertIOC, AlertSeverity, AlertSource
from src.detection.sigma import RuleLevel, SigmaRule, matches


_LEVEL_TO_SEVERITY = {
    RuleLevel.INFORMATIONAL: AlertSeverity.INFO,
    RuleLevel.LOW: AlertSeverity.LOW,
    RuleLevel.MEDIUM: AlertSeverity.MEDIUM,
    RuleLevel.HIGH: AlertSeverity.HIGH,
    RuleLevel.CRITICAL: AlertSeverity.CRITICAL,
}


def _event_get(event, path, default=None):
    node = event
    for part in path.split("."):
        if not isinstance(node, dict):
            return default
        node = node.get(part)
        if node is None:
            return default
    return node


def _event_hostname(event):
    for path in ("agent.name", "host.name", "hostname"):
        v = _event_get(event, path)
        if isinstance(v, str) and v:
            return v
    return ""


def _event_host_ip(event):
    for path in ("agent.ip", "host.ip"):
        v = _event_get(event, path)
        if isinstance(v, str) and v:
            return v
    return ""


def _event_agent_id(event):
    for path in ("agent.id", "agent_id"):
        v = _event_get(event, path)
        if isinstance(v, str) and v:
            return v
    return ""


def _ioc_from_event(rule, event, matched):
    ips = []
    domains = []
    hashes = []
    urls = []
    emails = []
    for path in rule.detection_fields:
        value = matched.get(path) if path in matched else None
        if value is None or not isinstance(value, str):
            continue
        leaf = path.split(".")[-1]
        if leaf == "ip" or path in ("srcip", "dstip"):
            ips.append(value)
        elif leaf == "domain" or "domain" in path:
            domains.append(value)
        elif leaf in ("hash", "sha256", "md5") or leaf.startswith("sha"):
            hashes.append(value)
        elif leaf == "url" or "url" in path:
            urls.append(value)
        elif leaf == "email" or "@" in value:
            emails.append(value)
    return AlertIOC(
        ips=sorted(set(ips)),
        domains=sorted(set(domains)),
        hashes=sorted(set(hashes)),
        urls=sorted(set(urls)),
        emails=sorted(set(emails)),
    )


def _extract_mitre(tags):
    """Extract MITRE ATT&CK technique ids from Sigma rule tags.

    Sigma tags look like `attack.t1059` (technique) or
    `attack.t1059.004` (sub-technique). We normalize to the MITRE
    canonical form: `T1059` / `T1059.004`. Non-technique tags such
    as `attack.credential_access` (tactic) are skipped.
    """
    out = []
    for t in tags:
        if not isinstance(t, str) or not t.lower().startswith("attack."):
            continue
        parts = t.split(".")
        if len(parts) < 2:
            continue
        # attack.t1059.004 -> parts = ["attack", "t1059", "004"]
        # attack.t1059     -> parts = ["attack", "t1059"]
        if len(parts) == 3 and parts[2].isdigit():
            head = parts[1].upper()
            if head.startswith("T") and head[1:].isdigit():
                out.append(head + "." + parts[2])
        else:
            head = parts[-1].upper()
            if head.startswith("T") and head[1:].isdigit():
                out.append(head)
    return out


def build_alert(rule, event, event_id):
    is_match, matched = matches(rule, event)
    if not is_match:
        return None
    raw = (rule.rule_id + ":" + event_id).encode("utf-8")
    alert_id = "sigma:" + hashlib.sha256(raw).hexdigest()[:32]
    return Alert(
        alert_id=alert_id,
        source=AlertSource.SECAGENT,
        title=rule.title,
        description=rule.description,
        severity=_LEVEL_TO_SEVERITY.get(rule.level, AlertSeverity.MEDIUM),
        occurred_at=str(event.get("timestamp") or event.get("ts") or datetime.now(UTC).isoformat()),
        received_at=datetime.now(UTC).isoformat(),
        hostname=_event_hostname(event),
        host_ip=_event_host_ip(event),
        agent_id=_event_agent_id(event),
        rule_id=rule.rule_id,
        rule_name=rule.title,
        category=rule.category,
        mitre_attack=_extract_mitre(rule.tags),
        iocs=_ioc_from_event(rule, event, matched),
        tags=list(rule.tags),
        source_url="",
        raw={"rule_id": rule.rule_id, "event_id": event_id, "event": event, "matched": matched},
    )
