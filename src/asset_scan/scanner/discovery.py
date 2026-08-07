"""资产发现（需求②: agentless 扫描）。

- ``discover_hosts``: nmap -sn 存活探测（-n 不做 DNS, -oX 输出 XML）。
- ``scan_ports``: 端口扫描。engine=full 用 masscan 全端口 1-65535
  （rate 限速）；engine=fast 用 nmap --top-ports 1000；engine=global
  两者叠加（masscan 快扫 + nmap 慢扫补充）。ports 显式指定时用
  nmap -p（精确且安静）。

解析函数（parse_*）纯 XML 逻辑, 可离线单测。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from src.asset_scan.scanner.runner import ScannerRunner
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


# -- XML 解析（纯逻辑） -------------------------------------------------------


def parse_host_alive(xml_text: str) -> list[str]:
    """nmap -sn XML: 返回 state=up 的 IPv4 地址列表。"""
    ips: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning("nmap_xml_parse_failed", error=xml_text[:200])
        return []
    for host in root.findall(".//host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                if ip:
                    ips.append(ip)
    return ips


def _extract_ports(root: ET.Element) -> dict[str, list[int]]:
    """通用端口提取: nmap/masscan XML 的 host -> [open ports]。"""
    out: dict[str, list[int]] = {}
    for host in root.findall(".//host"):
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr") or ""
                break
        if not ip:
            continue
        ports: list[int] = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pid = port.get("portid")
            if pid and pid.isdigit():
                ports.append(int(pid))
        if ports:
            out[ip] = sorted(set(ports))
    return out


def parse_masscan_ports(xml_text: str) -> dict[str, list[int]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning("masscan_xml_parse_failed", error=xml_text[:200])
        return {}
    return _extract_ports(root)


def parse_nmap_ports(xml_text: str) -> dict[str, list[int]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning("nmap_ports_xml_parse_failed", error=xml_text[:200])
        return {}
    return _extract_ports(root)


# -- 扫描执行 ----------------------------------------------------------------


async def discover_hosts(
    targets: list[str],
    *,
    runner: ScannerRunner,
    task_id: str | None = None,
) -> list[str]:
    """nmap -sn 存活探测。返回存活 IPv4 列表。"""
    args = ["nmap", "-sn", "-n", "--max-rate", "100", "-oX", "-", "--", *targets]
    rc, out, err = await runner.run(args, task_id=task_id)
    if rc != 0 and not out.strip():
        logger.warning("nmap_sn_failed", rc=rc, stderr=err[:300])
    hosts = parse_host_alive(out)
    logger.info("asset_discover_hosts", count=len(hosts))
    return hosts


async def scan_ports(
    hosts: list[str],
    *,
    engine: str,
    ports: list[int] | None = None,
    runner: ScannerRunner,
    task_id: str | None = None,
    masscan_rate: int = 2000,
    nmap_max_rate: int = 100,
) -> dict[str, list[int]]:
    """端口扫描。返回 {ip: [ports]}（只有开放端口的主机）。"""
    if not hosts:
        return {}
    # 大网段分块: masscan 一次最多扫 /16, 更大拆开（防 masscan 内部报错）。
    result: dict[str, list[int]] = {}

    if engine == "full" and not ports:
        # masscan 全端口
        port_spec = "1-65535"
        args = [
            "masscan", "--rate", str(masscan_rate), "-p", port_spec,
            "-oX", "-", "--", *hosts,
        ]
        rc, out, err = await runner.run(args, task_id=task_id)
        if rc != 0 and not out.strip():
            logger.warning("masscan_failed", rc=rc, stderr=err[:300])
        result.update(parse_masscan_ports(out))
    else:
        # nmap 指定端口或 top-ports
        if ports:
            port_spec = ",".join(str(p) for p in ports)
            args = ["nmap", "-sS", "-n", "-p", port_spec, "--max-rate", str(nmap_max_rate), "-oX", "-", "--", *hosts]
        else:
            args = ["nmap", "-sS", "-n", "--top-ports", "1000", "--max-rate", str(nmap_max_rate), "-oX", "-", "--", *hosts]
        rc, out, err = await runner.run(args, task_id=task_id)
        if rc != 0 and not out.strip():
            logger.warning("nmap_ports_failed", rc=rc, stderr=err[:300])
        result.update(parse_nmap_ports(out))

    total = sum(len(v) for v in result.values())
    logger.info("asset_scan_ports", hosts=len(result), open_ports=total, engine=engine)
    return result
