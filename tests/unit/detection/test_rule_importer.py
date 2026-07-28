"""Unit tests for the Sigma rule importer (Phase 6).

Uses a small fixture directory under tests/fixtures/sigma_zoo/ that
intentionally mixes supported and unsupported rules so the importer
has something real to do.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "sigma_zoo"


def test_fixture_dir_exists():
    assert FIXTURE_DIR.is_dir(), f"missing fixture: {FIXTURE_DIR}"
    yml = list(FIXTURE_DIR.rglob("*.yml"))
    assert len(yml) >= 4, f"expected >=4 fixture rules, found {len(yml)}"


def test_import_walks_recursively():
    from src.detection.rule_importer import import_from_directory

    result = import_from_directory(FIXTURE_DIR)
    assert result.total_seen == 5
    assert len(result.accepted) == 4
    assert len(result.skipped) == 1


def test_import_aggregation_rule_skipped():
    from src.detection.rule_importer import import_from_directory

    result = import_from_directory(FIXTURE_DIR)
    bad = [s for s in result.skipped if "aggregation" in s.path]
    assert len(bad) == 1
    assert "unsupported Sigma condition" in bad[0].reason


def test_import_classifies_os():
    from src.detection.rule_importer import import_from_directory

    result = import_from_directory(FIXTURE_DIR)
    by_os = result.by_os()
    assert by_os == {"linux": 1, "macos": 1, "windows": 1}


def test_import_extracts_mitre():
    from src.detection.rule_importer import import_from_directory

    result = import_from_directory(FIXTURE_DIR)
    ssh = next(r for r in result.accepted if r.rule.rule_id == "ssh-bruteforce-zoo-001")
    assert "T1110" in ssh.mitre_techniques


def test_import_extracts_subtechnique():
    from src.detection.rule_importer import import_from_directory

    result = import_from_directory(FIXTURE_DIR)
    ps = next(r for r in result.accepted if r.rule.rule_id == "ps-encoded-zoo-001")
    # T1059.001 must be preserved as a sub-technique.
    assert "T1059.001" in ps.mitre_techniques


def test_import_classifies_category():
    from src.detection.rule_importer import import_from_directory

    result = import_from_directory(FIXTURE_DIR)
    # file_event is in the supported set
    fd = next(r for r in result.accepted if r.rule.rule_id == "launchd-zoo-001")
    assert fd.category == "file_event"
    assert fd.detector_supported is True
    # the cloud rule has no logsource.category at all -> uncategorized
    cloud = next(r for r in result.accepted if r.rule.rule_id == "cloud-iam-zoo-001")
    assert cloud.category == "uncategorized"
    assert cloud.detector_supported is False


def test_import_from_single_file():
    from src.detection.rule_importer import import_from_directory

    one = FIXTURE_DIR / "linux_ssh_bruteforce.yml"
    result = import_from_directory(one)
    assert result.total_seen == 1
    assert len(result.accepted) == 1
    assert result.accepted[0].rule.rule_id == "ssh-bruteforce-zoo-001"


def test_import_from_missing_path():
    from src.detection.rule_importer import import_from_directory

    # A missing path is reported as a single SkippedRule so the
    # operator sees what was missing instead of a silent empty result.
    result = import_from_directory("/nonexistent/path/abc.yml")
    assert result.total_seen == 1
    assert len(result.accepted) == 0
    assert len(result.skipped) == 1
    assert "does not exist" in result.skipped[0].reason


def test_write_manifest_round_trip(tmp_path: Path):
    from src.detection.rule_importer import import_from_directory, write_manifest, read_manifest

    result = import_from_directory(FIXTURE_DIR)
    out = tmp_path / "manifest.json"
    write_manifest(result, out)
    assert out.exists()
    loaded = read_manifest(out)
    assert loaded is not None
    assert loaded["accepted"] == 4
    assert loaded["skipped"] == 1
    rule_ids = {r["rule_id"] for r in loaded["rules"]}
    assert "ssh-bruteforce-zoo-001" in rule_ids
    assert "ps-encoded-zoo-001" in rule_ids
    assert "launchd-zoo-001" in rule_ids


def test_mitre_normalization_drops_tactics():
    from src.detection.rule_importer import _mitre_from_tags

    out = _mitre_from_tags([
        "attack.credential_access",   # tactic -> drop
        "attack.t1110",                 # technique -> T1110
        "attack.t1059.004",             # sub-technique -> T1059.004
        "attack.execution",             # tactic -> drop
        "not_mitre",                    # unrelated -> drop
    ])
    assert out == ["T1110", "T1059.004"]


def test_mitre_normalization_dedupes():
    from src.detection.rule_importer import _mitre_from_tags

    out = _mitre_from_tags([
        "attack.t1110",
        "attack.t1110",  # exact dup
        "T1110",         # already in canonical form? actually no - it's "attack." prefix
    ])
    assert out == ["T1110"]


def test_import_idempotent(tmp_path: Path):
    """Re-importing the same source should produce the same accepted count."""
    from src.detection.rule_importer import import_from_directory

    r1 = import_from_directory(FIXTURE_DIR)
    r2 = import_from_directory(FIXTURE_DIR)
    assert len(r1.accepted) == len(r2.accepted)
    ids1 = {a.rule.rule_id for a in r1.accepted}
    ids2 = {a.rule.rule_id for a in r2.accepted}
    assert ids1 == ids2
