"""Unit tests for the TaskEnvelope dataclass (no Redis required)."""
from __future__ import annotations

import json

from src.orchestration.task_queue.enqueue import TaskEnvelope


def test_envelope_defaults():
    e = TaskEnvelope(task_id="t-1", source="manual")
    assert e.task_id == "t-1"
    assert e.source == "manual"
    assert e.targets == []
    assert e.modules == ["sys_vuln", "baseline"]
    assert e.engine == "matcher"
    assert e.nuclei_severity == []
    assert e.nuclei_severity is not e.__dataclass_fields__  # just an is-check, ignore
    assert e.nuclei_tags == []
    assert e.nuclei_templates == []
    assert e.nuclei_timeout_sec == 0


def test_envelope_to_from_json_roundtrip():
    e = TaskEnvelope(
        task_id="t-2",
        source="manual",
        targets=["h-a", "h-b"],
        modules=["sys_vuln"],
        engine="nuclei",
        nuclei_severity=["critical", "high"],
        nuclei_tags=["rce"],
        nuclei_templates=["cves/2024/CVE-2024-1234"],
        nuclei_timeout_sec=120,
        actor="admin",
    )
    raw = e.to_json()
    decoded = TaskEnvelope.from_json(raw)
    assert decoded.task_id == e.task_id
    assert decoded.targets == e.targets
    assert decoded.engine == "nuclei"
    assert decoded.nuclei_severity == ["critical", "high"]
    assert decoded.nuclei_tags == ["rce"]
    assert decoded.nuclei_templates == ["cves/2024/CVE-2024-1234"]
    assert decoded.nuclei_timeout_sec == 120
    assert decoded.actor == "admin"


def test_envelope_from_bytes():
    """XREAD returns bytes; the worker must accept either type."""
    payload = {"task_id": "t-3", "source": "manual", "engine": "matcher"}
    raw = json.dumps(payload).encode("utf-8")
    e = TaskEnvelope.from_json(raw)
    assert e.task_id == "t-3"
    assert e.source == "manual"


def test_envelope_from_dict_drops_unknown_keys():
    """A future schema bump must not crash older workers."""
    e = TaskEnvelope.from_dict(
        {"task_id": "t-4", "source": "manual", "future_field": "ignored"}
    )
    assert e.task_id == "t-4"
    assert e.source == "manual"
    # No exception, unknown field silently dropped


def test_envelope_asdict_serialisable_to_json():
    """Sanity check that json.dumps accepts the dataclass asdict output."""
    e = TaskEnvelope(task_id="t-5", source="manual")
    payload = json.loads(e.to_json())
    assert payload["task_id"] == "t-5"
    assert payload["submitted_at"] == ""  # not yet populated by enqueue_task
