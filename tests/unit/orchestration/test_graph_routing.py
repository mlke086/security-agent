"""Tests for route_decision, entry_node, aggregator_node."""

import pytest

from src.orchestration.main_graph.graph import route_decision
from src.orchestration.main_graph.nodes.aggregator import aggregator_node, ignore_node
from src.orchestration.main_graph.nodes.entry import entry_node


class TestRouteDecision:
    def test_low_priority_ignores(self):
        state = dict(event_id="1", raw_event={}, priority="low", event_tags=[],
                                stage="route", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        assert route_decision(state) == "ignore"

    def test_high_priority_vuln_goes_to_vuln_check(self):
        state = dict(event_id="1", raw_event={}, priority="high",
                                event_tags=["vulnerability", "exploit"],
                                stage="route", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        assert route_decision(state) == "vuln_check"

    def test_high_priority_no_vuln_goes_to_investigate(self):
        state = dict(event_id="1", raw_event={}, priority="high",
                                event_tags=["honeypot"],
                                stage="route", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        assert route_decision(state) == "investigate"

    def test_medium_priority_with_vuln_tag(self):
        state = dict(event_id="1", raw_event={}, priority="medium",
                                event_tags=["vulnerability"],
                                stage="route", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        assert route_decision(state) == "vuln_check"

    def test_default_low_priority(self):
        state = dict(event_id="1", raw_event={}, priority="medium",
                                event_tags=[],
                                stage="route", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        assert route_decision(state) == "investigate"


class TestEntryNode:
    @pytest.mark.asyncio
    async def test_entry_sets_stage(self):
        state = dict(event_id="", raw_event={"event_id": "evt-001"},
                                priority="high", event_tags=[],
                                stage="", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        result = await entry_node(state)
        assert result["event_id"] == "evt-001"
        assert result["stage"] == "triage"
        assert result["error"] is None
        assert len(result["audit_log"]) == 1
        assert result["audit_log"][0]["node"] == "entry"


class TestAggregatorNode:
    @pytest.mark.asyncio
    async def test_aggregator_with_result(self):
        state = dict(event_id="evt-001", raw_event={},
                                priority="high", event_tags=[],
                                stage="done", final_verdict=None, confidence_score=None,
                                pending_action=None,
                                subgraph_result={"final_verdict": "true_positive", "confidence_score": 0.95},
                                error=None, audit_log=[])
        result = await aggregator_node(state)
        assert result["final_verdict"] == "true_positive"
        assert result["confidence_score"] == 0.95
        assert result["stage"] == "done"

    @pytest.mark.asyncio
    async def test_aggregator_empty_result(self):
        state = dict(event_id="evt-001", raw_event={},
                                priority="high", event_tags=[],
                                stage="done", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        result = await aggregator_node(state)
        assert result["final_verdict"] == "unknown"

    @pytest.mark.asyncio
    async def test_ignore_node(self):
        state = dict(event_id="evt-001", raw_event={},
                                priority="low", event_tags=[],
                                stage="done", final_verdict=None, confidence_score=None,
                                pending_action=None, subgraph_result=None, error=None, audit_log=[])
        result = await ignore_node(state)
        assert result["final_verdict"] == "ignored"
        assert result["stage"] == "done"
