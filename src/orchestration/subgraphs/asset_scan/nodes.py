"""Asset-scan subgraph nodes (需求②).

每个节点入口先做 Redis 墓碑取消检查（``_confirm_cancellation``，仿
vulnscan 的二次确认模式——取消是显式操作，不因存储抖动误判）。
扫描执行统一走 scanner.runner.ScannerRunner（超时/取消/限流）。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from src.asset_scan.scanner import discovery as scanner_discovery
from src.asset_scan.scanner.fingerprint import parse_nmap_services
from src.asset_scan.scanner.runner import get_runner
from src.asset_scan.scanner.vuln_match import load_cve_rules, match_by_cpe, run_nuclei
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# LLM 研判批大小（与 vulnscan llm_analysis 一致）
AI_BATCH_SIZE = 15


async def _confirm_cancellation(task_id: str) -> bool:
    """Redis 墓碑二次确认：取消是显式操作，连接抖动不误判。"""
    try:
        from src.orchestration.task_queue.keys import asset_cancel_key

        redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            return bool(await redis.exists(asset_cancel_key(task_id)))
        finally:
            await redis.aclose()
    except Exception:  # noqa: BLE001
        return False


async def _pub_progress(task_id: str, step: str, detail: dict[str, Any]) -> None:
    """向 Redis pub/sub 发进度（SSE 订阅 assetscan:task:{id}）。"""
    try:
        redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            import json

            await redis.publish(
                f"assetscan:task:{task_id}",
                json.dumps(
                    {"type": "step", "step": step, "ts": datetime.now(UTC).isoformat(), **detail},
                    ensure_ascii=False,
                ),
            )
        finally:
            await redis.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.debug("asset_progress_pub_failed", task_id=task_id, error=str(exc))


def _default_state(envelope: Any) -> dict[str, Any]:
    """从 envelope 构建初始状态。"""
    return {
        "task_id": envelope.task_id,
        "source": getattr(envelope, "source", "manual"),
        "targets": list(getattr(envelope, "targets", [])),
        "ports": list(getattr(envelope, "ports", [])),
        "engine": getattr(envelope, "engine", "fast"),
        "modules": list(getattr(envelope, "modules", ["discovery", "fingerprint", "cve", "nuclei"])),
        "schedule": getattr(envelope, "schedule", ""),
        "actor": getattr(envelope, "actor", ""),
        "alive_hosts": [],
        "host_ports": {},
        "services": [],
        "vulns": [],
        "ai_results": [],
        "report": None,
        "status": "running",
        "error": None,
        "ai_processed": False,
    }


async def parse_intent(state: dict[str, Any]) -> dict[str, Any]:
    """规范化输入：去空/去重 targets，校验 engine 合法性。"""
    task_id = state["task_id"]
    if await _confirm_cancellation(task_id):
        return {"status": "cancelled"}

    targets = [t.strip() for t in state.get("targets", []) if t and t.strip()]
    if not targets:
        raise ValueError("asset scan requires at least one target (IP or CIDR)")
    engine = state.get("engine", "fast")
    if engine not in ("fast", "full", "global"):
        raise ValueError(f"unsupported engine: {engine}")
    await _pub_progress(task_id, "parse", {"targets": targets, "engine": engine})
    return {"targets": list(dict.fromkeys(targets)), "engine": engine}


async def discover(state: dict[str, Any]) -> dict[str, Any]:
    """存活探测 + 端口扫描 → host_ports。"""
    task_id = state["task_id"]
    if await _confirm_cancellation(task_id):
        return {"status": "cancelled"}
    runner = get_runner()

    targets = state["targets"]
    ports = state.get("ports") or []
    engine = state["engine"]

    await _pub_progress(task_id, "discover", {"phase": "alive", "targets": targets})
    hosts = await scanner_discovery.discover_hosts(targets, runner=runner, task_id=task_id)
    if not hosts:
        return {"alive_hosts": [], "host_ports": {}, "services": [], "vulns": [], "status": "completed"}

    settings = get_settings()
    host_ports = await scanner_discovery.scan_ports(
        hosts,
        engine=engine,
        ports=ports,
        runner=runner,
        task_id=task_id,
        masscan_rate=settings.asset_scan_masscan_rate,
        nmap_max_rate=settings.asset_scan_nmap_max_rate,
    )
    await _pub_progress(task_id, "discover", {"phase": "ports", "hosts": len(host_ports)})
    # V13 P3-F (2026-08-07): 把存活主机(无开放端口也算)写 ES assetscan-assets,
    # 使 GET /tasks/{id}/assets 能返回存活主机列表(不仅是开了端口的).
    try:
        from src.asset_scan.store import get_asset_store

        assets = [
            {
                "ip": ip,
                "hostname": "",
                "os_guess": "",
                "ports": list(ports),  # 空 list 表示存活但无开放端口
                "services": [],
            }
            for ip, ports in host_ports.items()
        ]
        # 存活但全 0 端口的也写一份
        for ip in hosts:
            if ip not in host_ports:
                assets.append({"ip": ip, "hostname": "", "os_guess": "", "ports": [], "services": []})
        if assets:
            await get_asset_store().save_assets(task_id, assets)
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset_discover_save_assets_failed", task_id=task_id, error=str(exc))
    return {"alive_hosts": hosts, "host_ports": host_ports}


async def fingerprint(state: dict[str, Any]) -> dict[str, Any]:
    """逐主机 nmap -sV 服务指纹 → services（补 ip 字段）。"""
    task_id = state["task_id"]
    if await _confirm_cancellation(task_id):
        return {"status": "cancelled"}
    host_ports = state.get("host_ports") or {}
    logger.info("asset_fingerprint_enter", task_id=task_id, host_count=len(host_ports), hosts=list(host_ports.keys()))
    if not host_ports:
        return {"services": []}

    runner = get_runner()
    settings = get_settings()
    services: list[dict[str, Any]] = []
    for ip, ports in host_ports.items():
        if await _confirm_cancellation(task_id):
            return {"status": "cancelled"}
        args = ["nmap", "-sV", "-sC", "-n", "--max-rate", str(settings.asset_scan_nmap_max_rate),
                "-p", ",".join(str(p) for p in ports), "-oX", "-", "--", ip]
        try:
            rc, out, err = await runner.run(args, task_id=task_id)
            logger.info("asset_fingerprint_done", task_id=task_id, ip=ip, rc=rc, out_size=len(out), err_size=len(err))
        except TimeoutError:
            logger.warning("asset_fingerprint_timeout", ip=ip)
            continue
        except Exception as exc:
            # V13 P3-F (2026-08-07): FileNotFoundError (PATH 缺 nmap) / 其他
            # 子进程异常不能让整个 fingerprint 节点崩, 单 host 失败继续下个
            logger.warning("asset_fingerprint_error", ip=ip, error=f"{type(exc).__name__}: {exc}"[:300])
            continue
        if rc != 0 and not out.strip():
            logger.debug("asset_fingerprint_skip", ip=ip, rc=rc, stderr=err[:200])
            continue
        for svc in parse_nmap_services(out):
            svc["ip"] = ip
            services.append(svc)
    await _pub_progress(task_id, "fingerprint", {"services": len(services)})
    return {"services": services}


async def match_vulns(state: dict[str, Any]) -> dict[str, Any]:
    """CPE→CVE 匹配 + nuclei 模板扫描 → vulns（写入 ES）。"""
    task_id = state["task_id"]
    if await _confirm_cancellation(task_id):
        return {"status": "cancelled"}
    services = state.get("services") or []
    modules = state.get("modules") or []

    vulns: list[dict[str, Any]] = []

    # 1) 离线 CPE→CVE（指纹服务的 product/version 对规则库）
    if "cve" in modules and services:
        rules = await load_cve_rules()
        cpe_hits = match_by_cpe(services, rules)
        vulns.extend(cpe_hits)
        logger.info("asset_cpe_matches", count=len(cpe_hits), task_id=task_id)

    # 2) nuclei 模板（在线；缺失二进制时静默跳过）
    if "nuclei" in modules and state.get("host_ports"):
        runner = get_runner()
        settings = get_settings()
        try:
            nuclei_hits = await run_nuclei(
                state["host_ports"],
                runner=runner,
                task_id=task_id,
                severity=settings.asset_scan_nuclei_severity,
            )
            vulns.extend(nuclei_hits)
        except Exception as exc:  # noqa: BLE001
            logger.warning("asset_nuclei_failed", task_id=task_id, error=str(exc))

    # 写入 ES（幂等：vuln_id 去重）
    from src.asset_scan.store import get_asset_store

    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for v in vulns:
        vid = v.get("vuln_id") or f"{v.get('ip', '?')}:{v.get('port', 0)}:{v.get('cve') or v.get('template_id') or v.get('name', '')}"
        if vid in seen:
            continue
        seen.add(vid)
        v["vuln_id"] = vid
        deduped.append(v)
    if deduped:
        await get_asset_store().save_vulns(task_id, deduped)
    await _pub_progress(task_id, "match", {"vulns": len(deduped)})
    return {"vulns": deduped}


async def llm_analysis(state: dict[str, Any]) -> dict[str, Any]:
    """批量 AI 研判：过滤误报 + AI 严重性 + 修复建议。

    复用 scan_engine.llm_analysis.chat_with_retry（两级重试 + 指标）。
    adapter 不可用或批次失败时写 fallback（ai_processed=False），
    前端显示"等待补扫"，与 vulnscan 的 UX 一致。
    """
    task_id = state["task_id"]
    if await _confirm_cancellation(task_id):
        return {"status": "cancelled"}
    vulns = state.get("vulns") or []
    if not vulns:
        return {"ai_results": [], "ai_processed": False}

    from src.asset_scan.store import get_asset_store
    from src.scan_engine.llm_analysis import chat_with_retry

    ai_results: list[dict[str, Any]] = []
    adapter = None
    try:
        from src.knowledge.models.adapter import get_model_adapter

        adapter = get_model_adapter()
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset_llm_adapter_unavailable", task_id=task_id, error=str(exc))

    def _fallback(v: dict[str, Any], reason: str) -> dict[str, Any]:
        return {
            "vuln_id": v.get("vuln_id", ""),
            "ai_severity": v.get("severity", "unknown"),
            "ai_reason": reason,
            "ai_processed": False,
        }

    if adapter is None:
        ai_results = [_fallback(v, "LLM unavailable, kept original severity") for v in vulns]
    else:
        for i in range(0, len(vulns), AI_BATCH_SIZE):
            if await _confirm_cancellation(task_id):
                return {"status": "cancelled"}
            batch = vulns[i : i + AI_BATCH_SIZE]
            prompt = {
                "role": "user",
                "content": (
                    "你是安全分析师。对以下 agentless 资产扫描漏洞列表逐条输出 JSON 数组，"
                    "每项 {\"vuln_id\": string, \"ai_severity\": \"critical|high|medium|low|info\", "
                    "\"ai_reason\": string(是否真实可利用及理由), \"fix_advice\": string}。\n"
                    + str(batch)
                ),
            }
            try:
                raw = await chat_with_retry(
                    "asset_scan_llm_analysis",
                    lambda m=prompt: adapter.chat_completion(messages=[m], schema=None, temperature=0.1),
                    task_id=task_id,
                    batch_idx=i // AI_BATCH_SIZE,
                )
                parsed = _parse_ai_json(raw)
                ai_results.extend(parsed if parsed else [_fallback(v, "AI output unparseable") for v in batch])
            except Exception as exc:  # noqa: BLE001
                logger.warning("asset_llm_batch_failed", task_id=task_id, batch=i // AI_BATCH_SIZE, error=str(exc))
                ai_results.extend(_fallback(v, f"LLM batch failed: {exc}") for v in batch)

    # 写回 ES（ai_* 字段）
    for res in ai_results:
        await get_asset_store().update_vuln(
            res.get("vuln_id", ""),
            ai_severity=res.get("ai_severity"),
            ai_reason=res.get("ai_reason", ""),
            ai_processed=res.get("ai_processed", False),
            fix_advice=res.get("fix_advice", ""),
        )
    return {"ai_results": ai_results, "ai_processed": bool(ai_results)}


def _parse_ai_json(raw: str) -> list[dict[str, Any]]:
    """解析 LLM JSON 数组输出；失败返回 []。"""
    import json
    import re

    if not raw:
        return []
    text = raw.strip()
    # 容忍 ```json 围栏
    m = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # 找第一个 [ ... ] 片段
        start, end = text.find("["), text.rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return []
    if isinstance(data, list):
        out = []
        for item in data:
            if isinstance(item, dict) and item.get("vuln_id"):
                out.append(
                    {
                        "vuln_id": item["vuln_id"],
                        "ai_severity": item.get("ai_severity", "info"),
                        "ai_reason": item.get("ai_reason", ""),
                        "fix_advice": item.get("fix_advice", ""),
                        "ai_processed": True,
                    }
                )
        return out
    return []


async def generate_report(state: dict[str, Any]) -> dict[str, Any]:
    """统计 + 报告生成（ES assetscan-reports）+ 任务收尾。"""
    task_id = state["task_id"]
    if await _confirm_cancellation(task_id):
        return {"status": "cancelled"}

    from src.asset_scan.store import get_asset_store

    store = get_asset_store()
    vulns = state.get("vulns") or []
    services = state.get("services") or []

    by_severity: dict[str, int] = {}
    for v in vulns:
        sev = v.get("ai_severity") or v.get("severity") or "unknown"
        by_severity[sev] = by_severity.get(sev, 0) + 1

    top_vulns = sorted(
        (
            {
                "ip": v.get("ip", ""),
                "port": v.get("port", 0),
                "cve": v.get("cve"),
                "name": v.get("name", ""),
                "severity": v.get("ai_severity") or v.get("severity", ""),
            }
            for v in vulns
        ),
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 9),
    )[:20]

    report = {
        "task_id": task_id,
        "summary": (
            f"扫描 {len(state.get('alive_hosts', []))} 台存活主机 / "
            f"{len(services)} 个服务 / {len(vulns)} 条漏洞"
        ),
        "ai_analysis": "",
        "stats": {
            "hosts_alive": len(state.get("alive_hosts", [])),
            "open_ports": sum(len(v) for v in state.get("host_ports", {}).values()),
            "services": len(services),
            "vulns": len(vulns),
            "by_severity": by_severity,
        },
        "top_vulns": top_vulns,
        "recommendations": _recommendations(by_severity),
        "generated_at": datetime.now(UTC).isoformat(),
    }
    await store.save_report(task_id, report)
    await store.update_task(task_id, status="completed", finished_at=datetime.now(UTC).isoformat())
    await _pub_progress(task_id, "report", {"vulns": len(vulns)})
    return {"report": report, "status": "completed"}


def _recommendations(by_severity: dict[str, int]) -> list[str]:
    out: list[str] = []
    if by_severity.get("critical", 0) > 0:
        out.append("发现严重漏洞：立即处置受影响服务，优先修复可远程利用项")
    if by_severity.get("high", 0) > 0:
        out.append("高危漏洞较多：安排近期维护窗口升级相关组件版本")
    if not out:
        out.append("未发现高危及以上漏洞，保持常规补丁节奏即可")
    return out
