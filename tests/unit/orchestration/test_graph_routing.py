"""Tests for route_decision, entry_node, aggregator_node."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.orchestration.main_graph.graph import route_after_verdict, route_decision
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


class TestRouteAfterVerdict:
    """Covers P2-CORE-NEW-4: route_after_verdict had zero coverage, including
    the verify-stage branch added by the P1-CORE-1 fix."""

    def _state(self, **over):
        base = dict(event_id="1", stage="route", subgraph_result={},
                    pending_action=None, error=None)
        base.update(over)
        return base

    def test_verify_is_vulnerable_routes_to_respond(self):
        state = self._state(stage="verify",
                            subgraph_result={"final_verdict": "true_positive",
                                             "is_vulnerable": True, "confidence_score": 0.95})
        assert route_after_verdict(state) == "respond"

    def test_verify_not_vulnerable_routes_to_done(self):
        state = self._state(stage="verify",
                            subgraph_result={"final_verdict": "false_positive",
                                             "is_vulnerable": False, "confidence_score": 0.2})
        assert route_after_verdict(state) == "done"

    def test_first_pass_true_positive_high_conf_routes_to_respond(self):
        state = self._state(stage="investigate",
                            subgraph_result={"final_verdict": "true_positive", "confidence_score": 0.9})
        assert route_after_verdict(state) == "respond"

    def test_first_pass_medium_conf_routes_to_vuln_check(self):
        state = self._state(stage="investigate",
                            subgraph_result={"final_verdict": "unknown", "confidence_score": 0.6})
        assert route_after_verdict(state) == "vuln_check"

    def test_first_pass_low_conf_routes_to_done(self):
        state = self._state(stage="investigate",
                            subgraph_result={"final_verdict": "unknown", "confidence_score": 0.3})
        assert route_after_verdict(state) == "done"


class TestVulnCheckVerdict:
    """Covers P1-CORE-NEW-2: vuln_check_node must set final_verdict from
    is_vulnerable so aggregator/runner store true_positive, not unknown."""

    @pytest.mark.asyncio
    async def test_vulnerable_event_gets_true_positive_verdict(self):
        from src.orchestration.main_graph import graph as graph_mod

        mock_subgraph = MagicMock()
        mock_subgraph.ainvoke = AsyncMock(return_value={
            "is_vulnerable": True, "final_poc": "import requests", "exploit_chain": "x",
        })
        with patch("src.orchestration.subgraphs.vuln_hunter.graph.build_vuln_hunter_subgraph", return_value=mock_subgraph):
            result = await graph_mod.vuln_check_node({
                "event_id": "e1", "raw_event": {"sanitized_text": "x"},
            })
        sub = result["subgraph_result"]
        assert sub["final_verdict"] == "true_positive"
        assert sub["confidence_score"] == 0.95
        assert sub["is_vulnerable"] is True
        assert result["stage"] == "verify"

    @pytest.mark.asyncio
    async def test_not_vulnerable_event_gets_false_positive_verdict(self):
        from src.orchestration.main_graph import graph as graph_mod

        mock_subgraph = MagicMock()
        mock_subgraph.ainvoke = AsyncMock(return_value={"is_vulnerable": False, "final_poc": ""})
        with patch("src.orchestration.subgraphs.vuln_hunter.graph.build_vuln_hunter_subgraph", return_value=mock_subgraph):
            result = await graph_mod.vuln_check_node({
                "event_id": "e1", "raw_event": {"sanitized_text": "x"},
            })
        assert result["subgraph_result"]["final_verdict"] == "false_positive"
