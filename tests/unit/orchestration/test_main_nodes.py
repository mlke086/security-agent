"""Unit tests for main_graph nodes: entry, orchestrator, aggregator, ignore."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.orchestration.main_graph.nodes.aggregator import aggregator_node, ignore_node
from src.orchestration.main_graph.nodes.entry import entry_node
from src.orchestration.main_graph.nodes.orchestrator import orchestrator_node


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    mock = MagicMock()
    mock.log = AsyncMock()
    monkeypatch.setattr("src.common.audit.audit_logger.get_audit_logger", lambda: mock)


@pytest.mark.asyncio
async def test_entry_node():
    state = {"raw_event": {"event_id": "e1", "sanitized_text": "x"}}
    result = await entry_node(state)
    assert result["event_id"] == "e1"
    assert result["stage"] == "triage"
    assert result["audit_log"][0]["node"] == "entry"


@pytest.mark.asyncio
async def test_orchestrator_honeypot_rule():
    state = {"raw_event": {"sanitized_text": "Honeypot captured whoami from 1.2.3.4"}, "event_id": "e1"}
    result = await orchestrator_node(state)
    assert result["priority"] == "high"
    assert "honeypot" in result["event_tags"]


@pytest.mark.asyncio
async def test_orchestrator_llm_path(monkeypatch):
    from src.orchestration.main_graph.nodes import orchestrator as orch

    async def fake_chat(messages, schema=None, temperature=0.1):
        return schema(priority="low", event_tags=["scan"], noise_score=0.9, reasoning="port scan")

    mock_adapter = MagicMock()
    mock_adapter.chat_completion = fake_chat
    monkeypatch.setattr(orch, "get_model_adapter", lambda: mock_adapter)

    state = {"raw_event": {"sanitized_text": "a non-honeypot event description"}, "event_id": "e1"}
    result = await orchestrator_node(state)
    assert result["priority"] == "low"
    assert result["event_tags"] == ["scan"]


@pytest.mark.asyncio
async def test_aggregator_node():
    state = {"event_id": "e1", "subgraph_result": {"final_verdict": "true_positive", "confidence_score": 0.9}}
    result = await aggregator_node(state)
    assert result["final_verdict"] == "true_positive"
    assert result["confidence_score"] == 0.9
    assert result["stage"] == "done"


@pytest.mark.asyncio
async def test_ignore_node():
    result = await ignore_node({"event_id": "e1"})
    assert result["final_verdict"] == "ignored"
    assert result["stage"] == "done"
