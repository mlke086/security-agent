"""漏洞匹配（需求②: agentless 扫描）。

两条路径：
1. **CPE→CVE**（离线）: 指纹得到的 product/version 对 vulnscan-rules
   索引（rules_sync 产物, check.type=package_version）做 dpkg 风格
   版本区间匹配——与 Go agent 端 matcher 同语义, 服务端实现。
2. **nuclei 模板**（在线）: 对存活 HTTP(S) 端口跑 nuclei 二进制,
   -jsonl 结构化输出解析。

``match_by_cpe`` / ``parse_nuclei_jsonl`` / ``_rule_product_matches`` 为
纯逻辑, 可离线单测。
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from src.asset_scan.scanner.runner import ScannerRunner
from src.asset_scan.scanner.version import normalize_cpe_version, version_matches
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# rules_sync 的规则包索引（rules_sync.py 内直接使用字符串, 无导出常量）。
RULES_INDEX = "vulnscan-rules"

# 每任务最多匹配条数（防止规则库膨胀导致内存暴涨）
MAX_MATCHES_PER_TASK = 2000


# -- 纯逻辑 -------------------------------------------------------------------


def _rule_product_matches(rule_name: str, product: str) -> bool:
    """product 与规则包名匹配：完全相等或 product 是 name/version 组合。"""
    rname = (rule_name or "").strip().lower()
    prod = (product or "").strip().lower()
    if not rname or not prod:
        return False
    if rname == prod:
        return True
    # "nginx" vs "nginx/1.18.0" / "nginx 1.18.0" / "nginx-1.18.0"
    return prod.startswith(rname + "/") or prod.startswith(rname + " ") or prod.startswith(rname + "-")


def match_by_cpe(services: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """对每个服务的 product/version 匹配 package_version 规则。

    ``rules`` 为 vulnscan-rules 索引的文档列表（字段: id/cve/name/
    severity/check{type,name,op,value}/fix）。返回匹配结果列表, 每项
    携带 ip/port/服务信息作 evidence。
    """
    out: list[dict[str, Any]] = []
    for svc in services:
        product = (svc.get("product") or svc.get("name") or "").strip()
        version = normalize_cpe_version(svc.get("version") or "")
        if not product or not version:
            continue
        for rule in rules:
            if len(out) >= MAX_MATCHES_PER_TASK:
                logger.warning("asset_match_cap_hit", cap=MAX_MATCHES_PER_TASK)
                return out
            check = rule.get("check") or {}
            if check.get("type") != "package_version":
                continue
            if not _rule_product_matches(check.get("name", ""), product):
                continue
            op = check.get("op", "lt")
            threshold = str(check.get("value", "") or "")
            if not threshold:
                continue
            if not version_matches(version, op, threshold):
                continue
            out.append(
                {
                    "vuln_id": f"{svc.get('ip', '?')}:{svc.get('port', 0)}:{rule.get('id', '')}",
                    "ip": svc.get("ip", ""),
                    "port": svc.get("port", 0),
                    "service": svc.get("name", ""),
                    "cve": rule.get("cve"),
                    "template_id": None,
                    "name": rule.get("name", ""),
                    "severity": rule.get("severity", "unknown"),
                    "evidence": (
                        f"{product} {svc.get('version', '')} ({op} {threshold})"
                    ),
                    "fix_advice": rule.get("fix", ""),
                    "status": "open",
                    "detected_at": datetime.now(UTC).isoformat(),
                }
            )
    return out


# -- nuclei -------------------------------------------------------------------


def parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    """nuclei -jsonl 每行一个结果: 提取 template/severity/cve/matched-at。"""
    results: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        classification = info.get("classification") or {}
        cve = classification.get("cve-id") or None
        matched_at = obj.get("matched-at") or ""
        ip = ""
        port: int = 0
        # matched-at 形如 http://1.2.3.4:8080/path
        if "://" in matched_at:
            rest = matched_at.split("://", 1)[1]
            hostport = rest.split("/", 1)[0]
            if ":" in hostport:
                ip, _, port_str = hostport.rpartition(":")
                if port_str.isdigit():
                    port = int(port_str)
            else:
                ip = hostport
        results.append(
            {
                "ip": ip,
                "port": port,
                "template_id": obj.get("template-id") or obj.get("templateID") or "",
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "cve": cve,
                "matched_at": matched_at,
                "matcher": obj.get("matcher-name", ""),
                "extracted": obj.get("extracted-results") or [],
            }
        )
    return results


async def run_nuclei(
    host_ports: dict[str, list[int]],
    *,
    runner: ScannerRunner,
    task_id: str | None = None,
    severity: str = "critical,high,medium",
    timeout_sec: int = 600,
) -> list[dict[str, Any]]:
    """对每个 (ip, port) 探测 http/https, 跑 nuclei 模板。"""
    if not host_ports:
        return []
    found: list[dict[str, Any]] = []
    # V13 P3-F (2026-08-07): 显式传模板目录 (Dockerfile 中 NUCLEI_TEMPLATES
    # 已预置到 /opt/secagent/templates), 避免 nuclei 首次跑自动下到
    # ~/.local/nuclei-templates 失败。env 为空时 (-t 不传) 沿用 nuclei 默认行为.
    templates_dir = os.environ.get("NUCLEI_TEMPLATES", "").strip()
    for ip, ports in host_ports.items():
        for port in ports:
            for scheme in ("http", "https"):
                target = f"{scheme}://{ip}:{port}"
                args = ["nuclei", "-u", target, "-severity", severity, "-jsonl", "-silent", "-nc"]
                if templates_dir:
                    args += ["-t", templates_dir]
                try:
                    rc, out, err = await runner.run(
                        args, timeout_sec=timeout_sec, task_id=task_id
                    )
                except TimeoutError:
                    logger.warning("nuclei_timeout", target=target)
                    continue
                if rc != 0 and not out.strip():
                    logger.debug("nuclei_skipped", target=target, rc=rc, stderr=err[:200])
                    continue
                hits = parse_nuclei_jsonl(out)
                for h in hits:
                    if not h["ip"]:
                        h["ip"] = ip
                        h["port"] = port
                    h["detected_at"] = datetime.now(UTC).isoformat()
                    h["status"] = "open"
                    found.append(h)
    logger.info("asset_nuclei_hits", count=len(found))
    return found


# -- 规则加载 ----------------------------------------------------------------


async def load_cve_rules(es: AsyncElasticsearch | None = None, limit: int = 10000) -> list[dict[str, Any]]:
    """从 vulnscan-rules 索引拉取 package_version 规则（search_after 分页）。"""
    if es is None:
        es = AsyncElasticsearch(hosts=[get_settings().es_hosts])
    rules: list[dict[str, Any]] = []
    try:
        cursor: list | None = None
        while True:
            kwargs: dict[str, Any] = {
                "index": RULES_INDEX,
                "query": {"term": {"check.type": "package_version"}},
                # V13 P3-F (2026-08-07): ES 默认禁用 _id 字段的 fielddata,
                # 用 _doc 排序 + search_after 是官方推荐的分页方式,
                # 且对 _id 排序的索引修改失效更具弹性.
                "sort": [{"_doc": {"order": "asc"}}],
                "size": 500,
            }
            if cursor is not None:
                kwargs["search_after"] = cursor
            resp = await es.search(**kwargs)
            hits = resp["hits"]["hits"]
            if not hits:
                break
            rules.extend(h["_source"] for h in hits)
            cursor = hits[-1]["sort"]
            if len(hits) < 500 or len(rules) >= limit:
                break
        return rules[:limit]
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset_cve_rules_load_failed", error=str(exc))
        return rules
