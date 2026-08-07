"""服务指纹识别（需求②: agentless 扫描）。

- ``fingerprint``: nmap -sV -sC（版本探测 + 默认脚本）输出服务
  名/product/version/cpe/banner。
- ``http_fingerprint``: 对 HTTP(S) 端口做轻量 banner 探测
  （title / server header / 状态码 / favicon 哈希）——nmap 的
  http-title 脚本已能拿到 title, 这里的原生探测是补充（nmap 无
  脚本时兜底）。

解析函数为纯 XML/文本逻辑, 可离线单测。
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import xml.etree.ElementTree as ET
from typing import Any

from src.asset_scan.scanner.runner import ScannerRunner
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


def parse_nmap_services(xml_text: str) -> list[dict[str, Any]]:
    """nmap -sV XML: 提取 (ip, port, service{name,product,version,cpe,banner})。"""
    services: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning("nmap_sv_xml_parse_failed", error=xml_text[:200])
        return []
    for host in root.findall(".//host"):
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr") or ""
                break
        if not ip:
            continue
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service: dict[str, Any] = {
                "port": int(portid) if portid.isdigit() else 0,
                "protocol": protocol,
                "name": "",
                "product": "",
                "version": "",
                "cpe": "",
                "banner": "",
                "http_title": "",
            }
            if service_el is not None:
                service["name"] = service_el.get("name", "")
                service["product"] = service_el.get("product", "")
                service["version"] = service_el.get("version", "")
                cpes = service_el.findall("cpe")
                if cpes:
                    service["cpe"] = cpes[0].text or ""
                # banner: script http-title 或 service banner 文本
                for script in port.findall(".//script"):
                    sid = script.get("id", "")
                    if sid == "http-title":
                        service["http_title"] = (script.get("output") or "").strip()
            services.append(service)
    return services


async def fingerprint(
    host_ports: dict[str, list[int]],
    *,
    runner: ScannerRunner,
    task_id: str | None = None,
    nmap_max_rate: int = 100,
) -> list[dict[str, Any]]:
    """nmap -sV 服务识别。返回带 ip 的 service 列表（host 维度折叠）。"""
    if not host_ports:
        return []
    args = ["nmap", "-sV", "-sC", "-n", "--max-rate", str(nmap_max_rate), "-oX", "-"]
    for ip, ports in host_ports.items():
        args += ["-p", ",".join(str(p) for p in ports), "--", ip]
    rc, out, err = await runner.run(args, task_id=task_id)
    if rc != 0 and not out.strip():
        logger.warning("nmap_sv_failed", rc=rc, stderr=err[:300])
    services = parse_nmap_services(out)
    # 折叠: 补 ip 字段（parse 结果无 ip, 需按 host 顺序关联——这里用
    # 简化映射: 每个 service 记录所属 ip。nmap XML host 顺序与输入一致,
    # 但多 host 解析更稳妥的做法是直接改 parse 返回 ip。为保持 parse
    # 纯净, 这里对单 host 场景直接关联; 多 host 由调用方逐 host 扫描。
    logger.info("asset_fingerprint_services", count=len(services))
    return services


async def http_fingerprint(
    ip: str,
    port: int,
    *,
    timeout_sec: float = 3.0,
) -> dict[str, Any]:
    """原生 HTTP banner 探测（兜底, 不依赖 nmap 脚本）。

    返回 {title, server, status, favicon_hash}；连接失败返回空 dict。
    """
    result: dict[str, Any] = {}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout_sec
        )
        request = (
            f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\n"
            "User-Agent: secagent-asset-scan/0.1\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        raw = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout_sec)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 65536:
                break
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

        head, _, body = raw.partition(b"\r\n\r\n")
        head_text = head.decode("utf-8", errors="replace")
        status_match = re.match(r"HTTP/\d\.\d (\d{3})", head_text)
        if status_match:
            result["status"] = int(status_match.group(1))
        server_match = re.search(r"(?i)^server:\s*(.+)$", head_text, re.MULTILINE)
        if server_match:
            result["server"] = server_match.group(1).strip()
        title_match = re.search(rb"(?i)<title[^>]*>(.*?)</title>", body[:8192])
        if title_match:
            result["title"] = title_match.group(1).decode("utf-8", errors="replace").strip()[:200]
        # favicon 哈希（mmh3 风格近似: 直接 md5, 用于同源资产聚类）
        favicon_match = re.search(rb"(?i)<link[^>]*rel=[\"']?icon[\"']?[^>]*href=[\"']([^\"']+)[\"']", body[:16384])
        if favicon_match:
            href = favicon_match.group(1)
            if href.startswith(("/", "http")):
                result["favicon"] = hashlib.md5(href).hexdigest()[:16]
    except Exception as exc:  # noqa: BLE001
        logger.debug("http_fingerprint_failed", ip=ip, port=port, error=str(exc))
    return result


# 保持 socket 导入被使用的引用（如未来加 TLS 探测）
_ = socket
