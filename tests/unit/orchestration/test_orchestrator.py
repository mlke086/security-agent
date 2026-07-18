"""Tests for orchestrator_node with mocked LLM adapter."""
from unittest.mock import AsyncMock, patch

import pytest

from src.orchestration.main_graph.nodes.orchestrator import TriageResult, orchestrator_node
from src.orchestration.main_graph.state import MainGraphState


@pytest.mark.asyncio
async def test_honeypot_rule_match():
    """Honeypot command triggers rule path, not LLM."""
    state = MainGraphState(
        event_id="evt-001",
        raw_event={"sanitized_text": "whoami && id from attacker"},
        priority="high", event_tags=[], stage="triage",
        final_verdict=None, confidence_score=None,
        pending_action=None, subgraph_result=None, error=None, audit_log=[],
    )
    result = await orchestrator_node(state)
    assert result["priority"] == "high"
    assert "honeypot" in result["event_tags"]
    assert result["stage"] == "route"


@pytest.mark.asyncio
async def test_no_honeypot_uses_llm():
    """Non-honeypot text triggers LLM path with mock."""
    mock_result = TriageResult(
        priority="high", event_tags=["exploit"],
        noise_score=0.1, reasoning="Mock",
    )
    mock_adapter = AsyncMock()
    mock_adapter.chat_completion.return_value = mock_result

    state = MainGraphState(
        event_id="evt-002",
        raw_event={"sanitized_text": "CVE-2024-1234 exploit attempt"},
        priority="medium", event_tags=[], stage="triage",
        final_verdict=None, confidence_score=None,
        pending_action=None, subgraph_result=None, error=None, audit_log=[],
    )

    with patch("src.orchestration.main_graph.nodes.orchestrator.get_model_adapter",
               return_value=mock_adapter):
        result = await orchestrator_node(state)

    assert result["priority"] == "high"
    assert "exploit" in result["event_tags"]
    assert result["stage"] == "route"


@pytest.mark.asyncio
async def test_llm_fallback_on_error():
    """When LLM fails, fallback returns medium priority."""
    mock_adapter = AsyncMock()
    mock_adapter.chat_completion.side_effect = RuntimeError("API unavailable")

    state = MainGraphState(
        event_id="evt-003",
        raw_event={"sanitized_text": "Some unclear event"},
        priority="medium", event_tags=[], stage="triage",
        final_verdict=None, confidence_score=None,
        pending_action=None, subgraph_result=None, error=None, audit_log=[],
    )

    with patch("src.orchestration.main_graph.nodes.orchestrator.get_model_adapter",
               return_value=mock_adapter):
        result = await orchestrator_node(state)

    assert result["priority"] == "medium"
    assert "unknown" in result["event_tags"]
    assert result["stage"] == "route"
