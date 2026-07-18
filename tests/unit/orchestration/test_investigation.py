"""Unit tests for investigation nodes (investigator + cti_analyst) with mocked LLM."""

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_investigator_node(monkeypatch):
    from src.orchestration.subgraphs.investigation import investigator as inv

    async def fake_chat(messages, schema=None, temperature=0.1):
        return schema(
            verdict="true_positive",
            confidence=0.9,
            evidence_summary="IOC match",
            mitre_ttps=["T1059"],
            recommended_action="block",
        )

    mock = MagicMock()
    mock.chat_completion = fake_chat
    monkeypatch.setattr(inv, "get_model_adapter", lambda: mock)

    state = {
        "raw_event": {"sanitized_text": "whoami from 1.2.3.4"},
        "raw_intel": {"risk": "high"},
        "event_id": "e1",
        "investigation_log": [],
    }
    result = await inv.investigator_node(state)
    assert result["final_verdict"] == "true_positive"
    assert result["confidence_score"] == 0.9
    assert result["mitre_ttps"] == ["T1059"]
    assert len(result["investigation_log"]) == 1


@pytest.mark.asyncio
async def test_cti_analyst_node(monkeypatch):
    from src.orchestration.subgraphs.investigation import cti_analyst as cti

    async def fake_chat(messages, schema=None, temperature=0.1):
        return schema(
            risk_level="high",
            related_apt=["APT29"],
            campaigns=[],
            ttps=["T1059"],
            recommendations=["isolate"],
            raw_evidence=["hit"],
        )

    mock = MagicMock()
    mock.chat_completion = fake_chat
    monkeypatch.setattr(cti, "get_model_adapter", lambda: mock)
    monkeypatch.setattr(cti, "_query_graphrag", AsyncMock(return_value=""))

    mm = MagicMock()
    mm.store_evidence = AsyncMock()
    monkeypatch.setattr(cti, "get_memory_manager", lambda: mm)

    state = {
        "iocs": {"ips": ["1.2.3.4"], "domains": [], "hashes": []},
        "graph_relations": [],
        "event_id": "e1",
        "investigation_log": [],
    }
    result = await cti.cti_analyst_node(state)
    assert result["raw_intel"]["risk_level"] == "high"
    assert result["raw_intel"]["related_apt"] == ["APT29"]
    assert len(result["investigation_log"]) == 1
    mm.store_evidence.assert_awaited_once()
