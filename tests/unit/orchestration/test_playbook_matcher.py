"""Unit tests for playbook_matcher_node (rule match + LLM fallback)."""

from unittest.mock import MagicMock

import pytest

from src.orchestration.subgraphs.responder.playbook_matcher import playbook_matcher_node


@pytest.mark.asyncio
async def test_rule_match_returns_yaml_playbook(monkeypatch):
    from src.orchestration.subgraphs.responder import playbook_matcher as pm

    monkeypatch.setattr(pm, "_load_playbooks", lambda: [{
        "playbook_id": "test_pb",
        "description": "test playbook",
        "trigger": {"verdict": "true_positive", "confidence_min": 0.8, "event_tags": ["vulnerability"]},
        "operations": [{"type": "notify", "level": "L1", "params": {}}],
    }])
    state = {
        "verdict": "true_positive",
        "confidence": 0.9,
        "event_tags": ["vulnerability"],
        "iocs": {},
    }
    result = await playbook_matcher_node(state)
    pb = result["playbook_draft"]
    assert pb["playbook_id"] == "test_pb"
    assert pb["description"] == "test playbook"
    assert len(pb["operations"]) == 1
    assert result["operation_level"] == "L1"


@pytest.mark.asyncio
async def test_real_playbooks_have_playbook_id():
    """BOM fix: every loaded real playbook exposes a usable playbook_id key."""
    from src.orchestration.subgraphs.responder.playbook_matcher import _load_playbooks

    pbs = _load_playbooks()
    assert len(pbs) >= 1
    for pb in pbs:
        assert "playbook_id" in pb, f"playbook missing playbook_id: {list(pb.keys())}"


@pytest.mark.asyncio
async def test_no_match_falls_back_to_llm(monkeypatch):
    from src.orchestration.subgraphs.responder import playbook_matcher as pm

    # No rules loaded -> must fall back to the LLM.
    monkeypatch.setattr(pm, "_load_playbooks", lambda: [])

    async def fake_chat(messages, schema=None, temperature=0.1):
        return schema(
            playbook_id="llm-pb",
            description="auto-generated",
            operations=[{"type": "notify", "params": {"channel": "soc"}}],
        )

    mock_adapter = MagicMock()
    mock_adapter.chat_completion = fake_chat
    monkeypatch.setattr(pm, "get_model_adapter", lambda: mock_adapter)

    state = {
        "verdict": "true_positive",
        "confidence": 0.9,
        "event_tags": ["anything"],
        "iocs": {},
    }
    result = await playbook_matcher_node(state)
    assert result["playbook_draft"]["description"] == "LLM generated"
    assert result["operation_level"] == "L1"  # notify -> L1
