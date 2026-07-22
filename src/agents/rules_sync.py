""" "Rules online sync -- fetch CVEs from NVD, transform into rule packs, sign, and distribute."""

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


# F4 (2026-07-21): operator-extensible baseline rules. Set the env var
# ``BASELINE_RULES_FILE`` to a YAML file containing a top-level list of rule
# dicts (same shape as BASELINE_RULES items). Useful for adding CIS-derived
# rules without modifying source. Falls back to the inline 5-rule starter
# pack when the env var is unset / the file is missing / malformed.
def _load_extra_baseline_rules() -> list[dict[str, Any]]:
    """Load operator-supplied baseline rules from $BASELINE_RULES_FILE.

    Returns [] on any error (missing file, no PyYAML, malformed list) so a
    misconfigured deployment never blocks rule sync -- it just falls back
    to the inline pack and logs a warning.
    """
    import os

    path = os.environ.get("BASELINE_RULES_FILE")
    if not path:
        return []
    try:
        import yaml  # noqa: F401
    except ImportError:
        logger.warning(
            "baseline_rules_yaml_missing", note="pip install pyyaml to load BASELINE_RULES_FILE"
        )
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        if not isinstance(data, list):
            logger.warning("baseline_rules_yaml_not_list", path=path)
            return []
        cleaned: list[dict[str, Any]] = []
        for r in data:
            if isinstance(r, dict) and r.get("id") and r.get("name"):
                cleaned.append(r)
        logger.info("baseline_rules_loaded", path=path, count=len(cleaned))
        return cleaned
    except Exception as exc:
        logger.warning("baseline_rules_yaml_load_failed", path=path, error=str(exc))
        return []


# Static baseline rules (always included in every pack).
# 需求7：基线规则中文化（name/fix），与全站中文 UI 保持一致。
BASELINE_RULES: list[dict[str, Any]] = [
    {
        "id": "BL-001",
        "category": "baseline",
        "name": "SSH 未禁止 root 登录",
        "severity": "high",
        "check": {
            "type": "config_check",
            "file": "/etc/ssh/sshd_config",
            "pattern": "^PermitRootLogin",
            "expect": "no",
        },
        "fix": "在 /etc/ssh/sshd_config 中设置 PermitRootLogin no",
    },
    {
        "id": "BL-002",
        "category": "baseline",
        "name": "密码策略：最小长度过短",
        "severity": "medium",
        "check": {
            "type": "config_check",
            "file": "/etc/login.defs",
            "pattern": "^PASS_MIN_LEN",
            "expect": "8",
        },
        "fix": "在 /etc/login.defs 中设置 PASS_MIN_LEN 8 或更高",
    },
    {
        "id": "BL-003",
        "category": "baseline",
        "name": "防火墙未启用",
        "severity": "medium",
        "check": {
            "type": "config_check",
            "file": "/proc/net/ip_tables_names",
            "pattern": "filter",
            "expect": "filter",
        },
        "fix": "启用 iptables 防火墙服务",
    },
    {
        "id": "BL-004",
        "category": "baseline",
        "name": "审计日志未启用",
        "severity": "low",
        "check": {
            "type": "config_check",
            "file": "/etc/audit/auditd.conf",
            "pattern": "^log_format",
            "expect": "ENRICHED",
        },
        "fix": "启用并配置 auditd 服务",
    },
    {
        "id": "BL-005",
        "category": "baseline",
        "name": "未限制 core dump",
        "severity": "low",
        "check": {
            "type": "config_check",
            "file": "/etc/security/limits.conf",
            "pattern": "^\\*\\s+hard\\s+core\\s+0",
            "expect": "0",
        },
        "fix": "在 /etc/security/limits.conf 中添加 '* hard core 0'",
    },
]


def _redis():
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


def _sign_pack(pack_data: str) -> str:
    """HMAC-SHA256 sign the rule pack.

    P2-1 修复：用独立的 agent_hmac_key（任意串），与 Ed25519 私钥
    (agent_signing_key, 需 64 hex) 分离。留空时回退到 agent_signing_key
    保持向后兼容。
    """
    s = get_settings()
    key = s.agent_hmac_key or s.agent_signing_key or "dev-signing-key"
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


async def get_rule_pack_body(version: str) -> bytes | None:
    """Return the raw rule-pack document bytes as stored in ES.

    The agent downloads this exact body via /rules/pack/{version} and verifies
    the Ed25519 signature against it, so the bytes we sign here must match the
    bytes served byte-for-byte (same JSON encoding / key order). Returning the
    stored source re-serialized with the same fields keeps them in sync.
    """
    store = get_vulnscan_store()
    try:
        resp = await store._es.get(index="vulnscan-rules", id=version, ignore=[404])  # type: ignore[call-arg]
        if resp.get("found"):
            import json

            # Re-serialize with ensure_ascii=False + sort_keys to match what the
            # /pack endpoint serves (PlainTextResponse of model_dump).
            return json.dumps(resp["_source"], ensure_ascii=False).encode()
    except Exception:
        pass
    return None


async def diff_versions(agent_version: str) -> dict | None:
    """Check if agent rule version is outdated. Returns None if up-to-date."""
    current_ver = await current_rule_version()
    if not current_ver or agent_version == current_ver:
        return None
    pack = await get_rule_pack(current_ver)
    if not pack:
        return None
    # 修复(需求7/P2-4)：download_url 必须是绝对 URL，否则 agent http.Get 会
    # 因协议错误失败（相对路径没有 scheme/host）。agent_console_external_url
    # 未配置时返回 None（不下发），并告警，避免 agent 拿到相对 URL 必然失败。
    base = (get_settings().agent_console_external_url or "").strip().rstrip("/")
    if not base:
        logger.error(
            "rule_update_skipped_no_console_url",
            note="AGENT_CONSOLE_EXTERNAL_URL 未配置，无法生成绝对下载 URL，"
            "规则将无法下发。请在 .env 设置该变量。",
        )
        return None
    return {
        "version": current_ver,
        "download_url": f"{base}/api/v1/rules/pack/{current_ver}",
    }


async def _publish_pack(rule_items: list[RuleItem], version: str | None = None) -> str:
    """Sign a rule pack, store it in ES, and update the current-version pointer.

    Shared by ``sync_rules`` (NVD online) and ``import_rules_from_pack``
    (offline zip). Returns the version string.
    """
    if version is None:
        version = datetime.now(UTC).strftime("%Y.%m.%d-%H%M%S")

    pack = RulePack(
        version=version,
        rules=rule_items,
        published_at=datetime.now(UTC).isoformat(),
    )
    # Sign with the server signing key (agent verifies with the same key).
    pack_data = pack.model_dump_json(exclude={"signature"})
    pack.signature = _sign_pack(pack_data)

    store = get_vulnscan_store()
    try:
        if not await store._es.indices.exists(index="vulnscan-rules"):
            await store._es.indices.create(
                index="vulnscan-rules",
                body={
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {
                        "properties": {
                            "version": {"type": "keyword"},
                            "published_at": {"type": "date"},
                        }
                    },
                },
            )
        await store._es.index(index="vulnscan-rules", id=version, document=pack.model_dump())
    except Exception as exc:
        logger.error("rules_store_failed", error=str(exc))
        raise

    r = _redis()
    await r.set("rules:current_version", version)
    logger.info("rules_pack_published", version=version, rule_count=len(rule_items))
    return version


async def import_rules_from_pack(pack_data: dict) -> tuple[str, int]:
    """Import rules from an uploaded zip (offline update, 需求2.2).

    支持三种格式（自动识别）：
      1. 本系统 rulepack：含 ``rules`` 数组（完整 RulePack 或裸 {rules:[...]}）
      2. NVD json：含 ``vulnerabilities`` 数组（NVD API 导出格式）
      3. GitHub advisory：含 ``id``/``affected``（单个 advisory）或 ``advisories``
         数组；导入 advisory zip 时聚合多个 advisory。

    用服务端密钥重新签名后发布。Returns ``(version, rule_count)``。
    """
    rule_items = parse_imported_data(pack_data)
    if not rule_items:
        raise ValueError("未能从导入数据中解析出任何规则，请检查格式")
    version = await _publish_pack(rule_items)
    logger.info("rules_imported_offline", version=version, count=len(rule_items))
    return version, len(rule_items)


def parse_imported_data(data: dict) -> list[RuleItem]:
    """识别导入数据的格式并转成 RuleItem 列表。

    格式判定优先级：
      - 含 'rules' -> 本系统 rulepack（直接 RuleItem 校验）
      - 含 'vulnerabilities' -> NVD 导出（走 _transform_cves_to_rules）
      - 含 'id'+'affected' 或 'advisories' -> GitHub advisory（走 _transform_advisories_to_rules）
    """
    # 1. 本系统 rulepack
    if isinstance(data.get("rules"), list):
        items: list[RuleItem] = []
        for r in data["rules"]:
            try:
                items.append(RuleItem(**r))
            except Exception:
                continue
        return items

    # 2. NVD 导出（vulnerabilities 数组）
    if isinstance(data.get("vulnerabilities"), list):
        cve_items = []
        for v in data["vulnerabilities"]:
            cve = v.get("cve", v) if isinstance(v, dict) else v
            if isinstance(cve, dict):
                cve_items.append(cve)
        raw_rules = _transform_cves_to_rules(cve_items)
        return _raw_rules_to_items(raw_rules)

    # 3. GitHub advisory（单个或数组）
    if isinstance(data.get("affected"), list) and (data.get("id") or data.get("aliases")):
        raw_rules = _transform_advisories_to_rules([data])
        return _raw_rules_to_items(raw_rules)
    if isinstance(data.get("advisories"), list):
        raw_rules = _transform_advisories_to_rules(data["advisories"])
        return _raw_rules_to_items(raw_rules)

    return []


def _raw_rules_to_items(raw_rules: list[dict[str, Any]]) -> list[RuleItem]:
    """把转换后的 raw rule dict 列表转成 RuleItem（校验，跳过非法条目）。"""
    items: list[RuleItem] = []
    for r in raw_rules:
        try:
            items.append(
                RuleItem(
                    id=r["id"],
                    category=r["category"],
                    cve=r.get("cve"),
                    name=r["name"],
                    severity=r["severity"],
                    check=RuleCheck(**r["check"]),
                    fix=r.get("fix", ""),
                )
            )
        except Exception:
            continue
    return items


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
        vuln_rules = _transform_cves_to_rules(cve_items)
    elif source == "github":
        # 需求2.2：GitHub advisory-database（国内可访问 GitHub）
        advisories = await _fetch_github_advisories()
        vuln_rules = _transform_advisories_to_rules(advisories)
    else:
        vuln_rules = []

    # Merge with baseline rules. Inline 5-rule starter pack + any
    # operator-supplied BASELINE_RULES_FILE entries (F4).
    all_rules = BASELINE_RULES.copy() + _load_extra_baseline_rules()
    for rule in vuln_rules:
        all_rules.append(rule)

    # Build rule items, then publish (sign + store + update pointer).
    rule_items = [
        RuleItem(
            id=r["id"],
            category=r["category"],
            cve=r.get("cve"),
            name=r["name"],
            severity=r["severity"],
            check=RuleCheck(**r["check"]),
            fix=r.get("fix", ""),
        )
        for r in all_rules
    ]
    version = await _publish_pack(rule_items, version=version)
    logger.info("rules_sync_complete", version=version, rule_count=len(rule_items))
    return version


async def _fetch_nvd_cves(since: str | None) -> list[dict[str, Any]]:
    """Fetch CVEs from NVD API 2.0. Returns list of CVE item dicts."""
    if since is None:
        if DEFAULT_LOOKBACK_HOURS:
            since = (datetime.now(UTC) - timedelta(hours=DEFAULT_LOOKBACK_HOURS)).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )
        else:
            now = datetime.now(UTC)
            since = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )
    pub_end = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.999")

    params: dict[str, str] = {
        "pubStartDate": since.replace(" ", "T"),
        "pubEndDate": pub_end,
        "resultsPerPage": "100",
    }
    settings = get_settings()
    headers = {"User-Agent": "Security-Agent/0.1.0"}
    # 需求2.2：NVD apiKey 提升限速(匿名 5req/30s -> 带 key 50req/30s)
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    all_items: list[dict[str, Any]] = []
    start_index = 0

    # 需求2.2：国内访问 NVD 常超时，支持代理（settings.nvd_proxy）
    client_kwargs: dict[str, Any] = {"timeout": 30.0}
    if settings.nvd_proxy:
        client_kwargs["proxy"] = settings.nvd_proxy
        logger.info("nvd_fetch_via_proxy", proxy=settings.nvd_proxy)

    async with httpx.AsyncClient(**client_kwargs) as client:
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


async def _fetch_github_advisories() -> list[dict[str, Any]]:
    """需求2.2：从 GitHub advisory-database 拉取近 N 天的 reviewed advisory。

    仓库 github/advisory-database，结构 advisories/github-reviewed/{年}/{月}/GHSA-xxx/GHSA-xxx.json
    （全量 28530 条）。按 advisory_lookback_days 只拉近期，避免全量下载。
    返回原始 advisory dict 列表（供 _transform_advisories_to_rules 消费）。
    """
    import re
    from datetime import timedelta

    settings = get_settings()
    lookback = settings.advisory_lookback_days or 30
    cutoff = datetime.now(UTC) - timedelta(days=lookback)
    # advisory 按发布年份分目录。30 天 lookback 扫今年目录即可（今年发布的在今年目录）。
    # 若 lookback 跨年（>365）则多扫一年。
    now_year = datetime.now(UTC).year
    years = [now_year] if lookback <= 365 else list(range(now_year - 1, now_year + 1))

    client_kwargs: dict[str, Any] = {"timeout": 30.0}
    if settings.nvd_proxy:
        client_kwargs["proxy"] = settings.nvd_proxy
    headers = {"User-Agent": "Security-Agent/0.1.0", "Accept": "application/vnd.github+json"}

    all_advisories: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            # 用 git tree 列出 github-reviewed 下所有 json 路径（1 次请求）
            tree_url = (
                "https://api.github.com/repos/github/advisory-database/git/trees/main?recursive=1"
            )
            resp = await client.get(tree_url, headers=headers)
            resp.raise_for_status()
            tree = resp.json().get("tree", [])
            # 筛选 github-reviewed 下的 json，且路径年份在范围内
            # 路径格式：advisories/github-reviewed/{年}/{月}/GHSA-xxx/GHSA-xxx.json
            pat = re.compile(
                r"^advisories/github-reviewed/(\d{4})/\d+/GHSA-[^/]+/GHSA-[^/]+\.json$"
            )
            candidates = []
            for t in tree:
                path = t.get("path", "")
                m = pat.match(path)
                if m and int(m.group(1)) in years:
                    candidates.append(path)
            # 限制数量避免下载过多。取末尾（tree 按时间顺序，末尾是最新的 advisory）。
            candidates = candidates[-800:]
            logger.info("advisory_candidates", total=len(candidates), years=years)

            # 并发下载（raw.githubusercontent.com 不限速），按 published 过滤近期
            import asyncio as _asyncio

            sem = _asyncio.Semaphore(20)

            async def fetch_one(path: str) -> dict[str, Any] | None:
                async with sem:
                    try:
                        raw = await client.get(
                            f"https://raw.githubusercontent.com/github/advisory-database/main/{path}",
                            headers=headers,
                        )
                        if raw.status_code != 200:
                            return None
                        return raw.json()
                    except Exception:
                        return None

            results = await _asyncio.gather(*[fetch_one(p) for p in candidates])
            all_downloaded = [a for a in results if a]
            # 按 published 过滤近期；若过滤后为空则保留全部（不空手，让用户拿到规则）
            recent = []
            for adv in all_downloaded:
                pub = adv.get("published") or adv.get("modified") or ""
                if pub:
                    try:
                        pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                        if pub_dt >= cutoff:
                            recent.append(adv)
                    except ValueError:
                        recent.append(adv)
                else:
                    recent.append(adv)
            all_advisories = recent if recent else all_downloaded
    except Exception as exc:
        logger.warning("advisory_fetch_failed", error=str(exc))
        return []

    logger.info("advisories_fetched", count=len(all_advisories))
    return all_advisories


def _transform_advisories_to_rules(advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把 GitHub advisory JSON 转成内部规则格式。

    advisory 结构：{id: GHSA-xxx, aliases: [CVE-xxx], summary, severity,
    affected: [{package: {ecosystem, name}, versions: [...]}], ...}
    版本转换：advisory 的 affected.versions 是离散版本列表（非范围），取最大版本
    作 package_version lt 阈值（含误差但可用）。
    """
    rules: list[dict[str, Any]] = []
    for adv in advisories:
        # id：优先 CVE（从 aliases），否则 GHSA
        rule_id = ""
        for alias in adv.get("aliases") or []:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                rule_id = alias
                break
        if not rule_id:
            rule_id = adv.get("id") or ""
        if not rule_id:
            continue

        sev = _advisory_severity(adv.get("severity"))
        summary = (adv.get("summary") or rule_id)[:200]

        # 每个 affected package 生成一条规则
        affected = adv.get("affected") or []
        if not affected:
            continue
        for aff in affected:
            pkg = aff.get("package") or {}
            pkg_name = pkg.get("name") or ""
            if not pkg_name:
                continue
            # 版本阈值：优先 ranges.events 的 fixed，其次 last_affected；再次 versions 最大值
            threshold = _advisory_version_threshold(aff)
            if not threshold:
                continue
            rules.append(
                {
                    "id": rule_id,
                    "category": "sys_vuln",
                    "cve": rule_id if rule_id.startswith("CVE-") else None,
                    "name": f"{pkg_name}: {summary}",
                    "severity": sev,
                    "check": {
                        "type": "package_version",
                        "name": pkg_name,
                        "op": "lt",
                        "value": threshold,
                    },
                    "fix": f"升级 {pkg_name} 到 {threshold} 及之后版本",
                }
            )
            break  # 一个 CVE 一条规则足够（取第一个 affected）
    return rules


def _advisory_severity(severity_field: Any) -> str:
    """从 advisory.severity 字段推断严重等级。

    GitHub advisory 的 severity 是 [{type: "CVSS_V3", score: "CVSS:3.1/AV:N/.../C:H/I:L/A:N"}]。
    从 CVSS 向量粗判：网络可达(AV:N)+高机密性/完整性/可用性影响 -> critical/high。
    无法解析时默认 high（advisory 多为高危）。
    """
    if isinstance(severity_field, str):
        return {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "moderate": "medium",
        }.get(severity_field.lower(), "high")
    if isinstance(severity_field, list):
        for entry in severity_field:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score", "")
            # CVSS 向量粗判：提取 C/I/A 影响等级
            import re

            c = re.search(r"/C:([HML])", score)
            i = re.search(r"/I:([HML])", score)
            a = re.search(r"/A:([HML])", score)
            impacts = [m.group(1) if m else "N" for m in (c, i, a)]
            high_count = impacts.count("H")
            if high_count >= 2:
                return "critical"
            if high_count >= 1:
                return "high"
            if "M" in impacts:
                return "medium"
            return "low"
    return "high"


def _advisory_version_threshold(aff: dict[str, Any]) -> str:
    """从 affected 提取版本阈值（优先 fixed，其次 last_affected，再次 versions 最大值）。"""
    # 1. ranges.events 的 fixed / last_affected
    for rng in aff.get("ranges") or []:
        if not isinstance(rng, dict):
            continue
        for ev in rng.get("events") or []:
            if not isinstance(ev, dict):
                continue
            if ev.get("fixed"):
                return str(ev["fixed"])
        # 没找到 fixed，找 last_affected
        for ev in rng.get("events") or []:
            if isinstance(ev, dict) and ev.get("last_affected"):
                return str(ev["last_affected"])
    # 2. versions 列表最大值
    versions = aff.get("versions") or []
    if versions:
        return max(versions)
    return ""


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
                    version_end = cpe_match.get("versionEndExcluding") or cpe_match.get(
                        "versionEndIncluding", "*"
                    )

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
    # 修复(需求7)：agent 用 Ed25519 公钥验签「下载到的 pack body」，因此
    # payload.signature 必须是服务端 Ed25519 私钥对 pack body 的签名
    # （signing.sign_bytes），而非 pack 自身的 HMAC 签名。原代码传空串被
    # agent 直接拒绝。WS 命令本身的 Ed25519 签名由 send_to_agent 自动加到
    # msg.sig，无需在此处理。
    from src.agents.signing import sign_bytes

    body = await get_rule_pack_body(diff["version"])
    pack_signature = sign_bytes(body) if body else ""
    from src.agents.ws_gateway import get_agent_gateway

    gateway = get_agent_gateway()
    msg = {
        "v": 1,
        "type": "rule_update",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "rule_version": diff["version"],
            "download_url": diff["download_url"],
            "signature": pack_signature,
        },
    }
    await gateway.send_to_agent(agent_id, msg)
    logger.info("rule_update_triggered", agent_id=agent_id, version=diff["version"])


async def force_rule_update(agent_id: str) -> bool:
    """强制向单个 agent 下发当前规则包（不判断版本是否落后）。

    需求2.1：手动同步规则到 agent。返回 True=已下发，False=无 pack 或 agent 不在线。
    """
    current_ver = await current_rule_version()
    if not current_ver or current_ver == "0":
        return False
    base = (get_settings().agent_console_external_url or "").strip().rstrip("/")
    if not base:
        logger.error("force_rule_update_no_console_url", agent_id=agent_id)
        return False
    from src.agents.signing import sign_bytes

    body = await get_rule_pack_body(current_ver)
    if not body:
        return False
    pack_signature = sign_bytes(body)
    from src.agents.ws_gateway import get_agent_gateway

    gateway = get_agent_gateway()
    msg = {
        "v": 1,
        "type": "rule_update",
        "ts": datetime.now(UTC).isoformat(),
        "payload": {
            "rule_version": current_ver,
            "download_url": f"{base}/api/v1/rules/pack/{current_ver}",
            "signature": pack_signature,
        },
    }
    ok = await gateway.send_to_agent(agent_id, msg)
    logger.info("force_rule_update_sent", agent_id=agent_id, version=current_ver, sent=ok)
    return ok


async def sync_rules_to_all_agents() -> dict:
    """需求2.1：对所有在线 agent 强制下发当前规则包。

    从 Redis 枚举 agent:online:* 取在线 agent_id，逐个 force_rule_update。
    返回 {synced: n, total: n, agents: [{agent_id, sent}]}。
    """
    r = _redis()
    # SCAN 匹配 agent:online:*（避免 KEYS 阻塞）
    online_ids: list[str] = []
    async for key in r.scan_iter(match="agent:online:*", count=200):
        if isinstance(key, bytes):
            key = key.decode()
        online_ids.append(key.replace("agent:online:", ""))
    results = []
    synced = 0
    for agent_id in online_ids:
        sent = await force_rule_update(agent_id)
        results.append({"agent_id": agent_id, "sent": sent})
        if sent:
            synced += 1
    logger.info("sync_rules_to_all_agents_done", total=len(online_ids), synced=synced)
    return {"synced": synced, "total": len(online_ids), "agents": results}
