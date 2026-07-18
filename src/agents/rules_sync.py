""""Rules online sync -- fetch CVEs from NVD, transform into rule packs, sign, and distribute."""
import hashlib
import hmac
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import redis.asyncio as aioredis

from src.agents.models import RuleCheck, RuleItem, RulePack
from src.agents.store import get_vulnscan_store
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# NVD API 2.0 base URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Default: fetch CVEs modified in the last 24 hours
DEFAULT_LOOKBACK_HOURS = 24

# Static baseline rules (always included in every pack)
BASELINE_RULES: list[dict[str, Any]] = [
    {
        "id": "BL-001", "category": "baseline", "name": "SSH root login not disabled",
        "severity": "high",
        "check": {"type": "config_check", "file": "/etc/ssh/sshd_config",
                   "pattern": "^PermitRootLogin", "expect": "no"},
        "fix": "Set PermitRootLogin no in /etc/ssh/sshd_config",
    },
    {
        "id": "BL-002", "category": "baseline", "name": "Password policy: min length too short",
        "severity": "medium",
        "check": {"type": "config_check", "file": "/etc/login.defs",
                   "pattern": "^PASS_MIN_LEN", "expect": "8"},
        "fix": "Set PASS_MIN_LEN 8 or higher in /etc/login.defs",
    },
    {
        "id": "BL-003", "category": "baseline", "name": "Firewall not active",
        "severity": "medium",
        "check": {"type": "config_check", "file": "/proc/net/ip_tables_names",
                   "pattern": "filter", "expect": "filter"},
        "fix": "Enable iptables firewall service",
    },
    {
        "id": "BL-004", "category": "baseline", "name": "Audit logging not enabled",
        "severity": "low",
        "check": {"type": "config_check", "file": "/etc/audit/auditd.conf",
                   "pattern": "^log_format", "expect": "ENRICHED"},
        "fix": "Enable and configure auditd service",
    },
    {
        "id": "BL-005", "category": "baseline", "name": "Core dumps not restricted",
        "severity": "low",
        "check": {"type": "config_check", "file": "/etc/security/limits.conf",
                   "pattern": "^\\*\\s+hard\\s+core\\s+0", "expect": "0"},
        "fix": "Add '* hard core 0' to /etc/security/limits.conf",
    },
]


def _redis():
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


def _sign_pack(pack_data: str) -> str:
    """HMAC-SHA256 sign the rule pack using the agent signing key."""
    key = get_settings().agent_signing_key or "dev-signing-key"
    return hmac.new(key.encode(), pack_data.encode(), hashlib.sha256).hexdigest()


async def current_rule_version() -> str:
    """Get the current active rule version from Redis."""
    r = _redis()
    version = await r.get("rules:current_version")
    return version or "0"


async def get_rule_pack(version: str) -> RulePack | None:
    """Retrieve a rule pack by version from ES."""
    store = get_vulnscan_store()
    try:
        resp = await store._es.get(index="vulnscan-rules", id=version, ignore=[404])  # type: ignore[call-arg]
        if resp.get("found"):
            return RulePack(**resp["_source"])
    except Exception:
        pass
    return None


async def diff_versions(agent_version: str) -> dict | None:
    """Check if agent rule version is outdated. Returns None if up-to-date."""
    current_ver = await current_rule_version()
    if not current_ver or agent_version == current_ver:
        return None
    pack = await get_rule_pack(current_ver)
    if pack:
        return {"version": current_ver, "download_url": f"/api/v1/rules/pack/{current_ver}"}
    return None


async def sync_rules(source: str = "nvd", since: str | None = None) -> str:
    """Sync rules from external source (NVD/CNNVD). Returns new version string.

    Flow:
    1. Fetch CVEs from NVD since last sync
    2. Transform CVEs into rule items
    3. Merge with baseline rules
    4. Sign the pack
    5. Store in ES
    6. Update Redis current_version
    """
    version = datetime.now(UTC).strftime("%Y.%m.%d-%H%M%S")
    logger.info("rules_sync_started", source=source, version=version)

    # Fetch CVEs
    if source == "nvd":
        cve_items = await _fetch_nvd_cves(since)
    else:
        cve_items = []

    # Transform to rules
    vuln_rules = _transform_cves_to_rules(cve_items)

    # Merge with baseline rules
    all_rules = BASELINE_RULES.copy()
    for rule in vuln_rules:
        all_rules.append(rule)

    # Build pack
    rule_items = []
    for r in all_rules:
        rule_items.append(RuleItem(
            id=r["id"],
            category=r["category"],
            cve=r.get("cve"),
            name=r["name"],
            severity=r["severity"],
            check=RuleCheck(**r["check"]),
            fix=r.get("fix", ""),
        ))

    pack = RulePack(
        version=version,
        rules=rule_items,
        published_at=datetime.now(UTC).isoformat(),
    )

    # Sign
    pack_data = pack.model_dump_json(exclude={"signature"})
    pack.signature = _sign_pack(pack_data)

    # Store in ES
    store = get_vulnscan_store()
    try:
        if not await store._es.indices.exists(index="vulnscan-rules"):
            await store._es.indices.create(index="vulnscan-rules", body={
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {"properties": {
                    "version": {"type": "keyword"},
                    "published_at": {"type": "date"},
                }},
            })
        await store._es.index(index="vulnscan-rules", id=version, document=pack.model_dump())
    except Exception as exc:
        logger.error("rules_store_failed", error=str(exc))
        raise

    # Update current version
    r = _redis()
    await r.set("rules:current_version", version)  # type: ignore[attr-defined]

    logger.info("rules_sync_complete", version=version, rule_count=len(rule_items))
    return version


async def _fetch_nvd_cves(since: str | None) -> list[dict[str, Any]]:
    """Fetch CVEs from NVD API 2.0. Returns list of CVE item dicts."""
    if since is None:
        since = (datetime.now(UTC) - timedelta(hours=DEFAULT_LOOKBACK_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.000")

    params: dict[str, str] = {
        "pubStartDate": since.replace(" ", "T"),
        "resultsPerPage": "100",
    }
    settings = get_settings()
    headers = {"User-Agent": "Security-Agent/0.1.0"}
    if hasattr(settings, "_nvd_api_key"):  # Optional: NVD API key for higher rate limits
        headers["apiKey"] = getattr(settings, "_nvd_api_key", "")

    all_items: list[dict[str, Any]] = []
    start_index = 0

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            params["startIndex"] = str(start_index)
            try:
                resp = await client.get(NVD_API_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    # Only import CVEs with CVSS v3 scores for filtering
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                    if cvss_v3:
                        score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0)
                        if score >= 4.0:  # Skip low/info CVEs
                            all_items.append(cve)

                total = data.get("totalResults", 0)
                start_index += len(vulnerabilities)
                if start_index >= total:
                    break

                # Rate limit: NVD allows 5 req/30s without key
                time.sleep(6.1)

            except httpx.HTTPError as exc:
                logger.warning("nvd_fetch_failed", error=str(exc))
                break

    logger.info("nvd_cves_fetched", count=len(all_items))
    return all_items


def _transform_cves_to_rules(cve_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Transform NVD CVE items into internal rule format."""
    rules: list[dict[str, Any]] = []
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    for cve in cve_items:
        cve_id = cve.get("id", "")
        if not cve_id.startswith("CVE-"):
            continue

        # Extract severity from CVSS v3
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        sev = "medium"
        if cvss_v3:
            base_severity = cvss_v3[0].get("cvssData", {}).get("baseSeverity", "MEDIUM")
            sev = severity_map.get(base_severity, "medium")

        # Extract CPE matches for package/version info
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if not criteria:
                        continue
                    # Parse CPE: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
                    parts = criteria.split(":")
                    if len(parts) < 6:
                        continue
                    product = parts[4]
                    version_end = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding", "*")

                    description = cve.get("descriptions", [{}])[0].get("value", cve_id)[:200]

                    rule = {
                        "id": cve_id,
                        "category": "sys_vuln",
                        "cve": cve_id,
                        "name": f"{product}: {description}",
                        "severity": sev,
                        "check": {
                            "type": "package_version",
                            "name": product,
                            "op": "lt",
                            "value": version_end,
                        },
                        "fix": f"Upgrade {product} to version >= {version_end}",
                    }
                    rules.append(rule)
                    break  # One rule per CVE is enough for MVP

    return rules


async def verify_pack_signature(pack: RulePack) -> bool:
    """Verify the signature of a rule pack."""
    data = pack.model_dump_json(exclude={"signature"})
    expected = _sign_pack(data)
    return hmac.compare_digest(expected, pack.signature)


async def trigger_update_if_outdated(agent_id: str, agent_rule_version: str) -> None:
    """If agent's rule version is behind, send rule_update via gateway."""
    diff = await diff_versions(agent_rule_version)
    if diff is None:
        return
    from src.agents.ws_gateway import get_agent_gateway
    gateway = get_agent_gateway()
    msg = {
        "v": 1,
        "type": "rule_update",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "rule_version": diff["version"],
            "download_url": diff["download_url"],
            "signature": "",  # Signature embedded in pack itself
        },
    }
    await gateway.send_to_agent(agent_id, msg)
    logger.info("rule_update_triggered", agent_id=agent_id, version=diff["version"])
