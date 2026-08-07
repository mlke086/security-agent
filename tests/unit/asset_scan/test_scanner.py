"""Unit tests for scanner XML/json parsers and CPE matching (需求②)."""

import json

from src.asset_scan.scanner.discovery import parse_host_alive, parse_masscan_ports, parse_nmap_ports
from src.asset_scan.scanner.fingerprint import parse_nmap_services
from src.asset_scan.scanner.vuln_match import match_by_cpe, parse_nuclei_jsonl

NMAP_SN_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
  <host><status state="down"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/></host>
</nmaprun>"""

MASSCAN_XML = """<nmaprun>
  <host endtime="1"><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port>
    <port protocol="tcp" portid="443"><state state="open"/></port>
    <port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
</nmaprun>"""

NMAP_SV_XML = """<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
        <script id="http-title" output="Welcome to nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports></host>
</nmaprun>"""

NUCLEI_JSONL = (
    json.dumps({
        "template-id": "CVE-2021-41773",
        "info": {"name": "Apache Path Traversal", "severity": "high",
                 "classification": {"cve-id": "CVE-2021-41773"}},
        "matched-at": "http://10.0.0.1:8080/cgi-bin/..%2f",
        "matcher-name": "body",
        "extracted-results": ["root:x:0:0"],
    })
    + "\n" +
    json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "Nginx Detection", "severity": "info", "classification": {}},
        "matched-at": "http://10.0.0.1/",
    })
)


class TestNmapParse:
    def test_host_alive(self):
        assert parse_host_alive(NMAP_SN_XML) == ["10.0.0.1", "10.0.0.3"]

    def test_host_alive_bad_xml(self):
        assert parse_host_alive("not xml") == []

    def test_masscan_ports(self):
        result = parse_masscan_ports(MASSCAN_XML)
        assert result == {"10.0.0.1": [80, 443]}  # closed 22 排除

    def test_nmap_ports(self):
        assert parse_nmap_ports(MASSCAN_XML) == {"10.0.0.1": [80, 443]}

    def test_nmap_services(self):
        services = parse_nmap_services(NMAP_SV_XML)
        assert len(services) == 2
        http = services[0]
        assert http["port"] == 80
        assert http["name"] == "http"
        assert http["product"] == "nginx"
        assert http["version"] == "1.18.0"
        assert http["cpe"] == "cpe:/a:nginx:nginx:1.18.0"
        assert http["http_title"] == "Welcome to nginx"
        # https 端口无 title
        assert services[1]["http_title"] == ""


class TestCpeMatch:
    def _svc(self, **over):
        base = {"ip": "10.0.0.1", "port": 80, "name": "http",
                "product": "nginx", "version": "1.18.0"}
        base.update(over)
        return base

    def _rule(self, pkg="nginx", op="lt", value="1.22.0", cve="CVE-2021-23017"):
        return {
            "id": cve,
            "cve": cve,
            "name": f"{pkg}: vuln",
            "severity": "high",
            "check": {"type": "package_version", "name": pkg, "op": op, "value": value},
            "fix": f"upgrade {pkg}",
        }

    def test_match_vulnerable_version(self):
        rules = [self._rule()]
        hits = match_by_cpe([self._svc()], rules)
        assert len(hits) == 1
        assert hits[0]["cve"] == "CVE-2021-23017"
        assert hits[0]["ip"] == "10.0.0.1"
        assert hits[0]["port"] == 80
        assert "1.18.0 (lt 1.22.0)" in hits[0]["evidence"]

    def test_no_match_when_patched(self):
        # 1.18.0 >= 1.18.0 不匹配 lt
        rules = [self._rule(value="1.18.0")]
        assert match_by_cpe([self._svc()], rules) == []

    def test_tilde_prerelease_matches_lt_release(self):
        # 预发布（~）命中 lt 规则；-rc 后缀按 dpkg 语义在 release 之后
        rules = [self._rule(value="1.18.0")]
        hits = match_by_cpe([self._svc(version="1.18.0~rc1")], rules)
        assert len(hits) == 1
        # 1.18.0-rc1 > 1.18.0 → lt 不命中（与 Go agent 端 matcher 一致）
        assert match_by_cpe([self._svc(version="1.18.0-rc1")], rules) == []

    def test_no_match_when_product_differs(self):
        rules = [self._rule(pkg="apache")]
        assert match_by_cpe([self._svc()], rules) == []

    def test_skips_non_package_rules(self):
        rules = [{"id": "x", "check": {"type": "port", "name": "nginx"}}]
        assert match_by_cpe([self._svc()], rules) == []

    def test_skips_unknown_version(self):
        assert match_by_cpe([self._svc(version="")], [self._rule()]) == []


class TestNucleiParse:
    def test_parse_jsonl(self):
        hits = parse_nuclei_jsonl(NUCLEI_JSONL)
        assert len(hits) == 2
        cve_hit = hits[0]
        assert cve_hit["template_id"] == "CVE-2021-41773"
        assert cve_hit["cve"] == "CVE-2021-41773"
        assert cve_hit["severity"] == "high"
        assert cve_hit["ip"] == "10.0.0.1"
        assert cve_hit["port"] == 8080
        assert cve_hit["extracted"] == ["root:x:0:0"]
        info_hit = hits[1]
        assert info_hit["cve"] is None
        assert info_hit["port"] == 0  # matched-at 无端口

    def test_parse_garbage_lines_skipped(self):
        assert parse_nuclei_jsonl("not json\n{\"broken\")") == []
