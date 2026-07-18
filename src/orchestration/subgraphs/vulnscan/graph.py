"""VulnScan subgraph -- compiled graph."""
from langgraph.graph import END, StateGraph

from src.orchestration.subgraphs.vulnscan.nodes import (
    _default_state,
    aggregate,
    collect,
    dispatch,
    generate_report,
    llm_analysis,
    parse_intent,
)
from src.orchestration.subgraphs.vulnscan.state import VulnScanState

_vulnscan_subgraph = StateGraph(VulnScanState)
_vulnscan_subgraph.add_node("parse_intent", parse_intent)
_vulnscan_subgraph.add_node("dispatch", dispatch)
_vulnscan_subgraph.add_node("collect", collect)
_vulnscan_subgraph.add_node("aggregate", aggregate)
_vulnscan_subgraph.add_node("llm_analysis", llm_analysis)
_vulnscan_subgraph.add_node("generate_report", generate_report)
_vulnscan_subgraph.set_entry_point("parse_intent")
_vulnscan_subgraph.add_edge("parse_intent", "dispatch")
_vulnscan_subgraph.add_edge("dispatch", "collect")
_vulnscan_subgraph.add_edge("collect", "aggregate")
_vulnscan_subgraph.add_edge("aggregate", "llm_analysis")
_vulnscan_subgraph.add_edge("llm_analysis", "generate_report")
_vulnscan_subgraph.add_edge("generate_report", END)
compiled_vulnscan_subgraph = _vulnscan_subgraph.compile()

def get_vulnscan_subgraph():
    return compiled_vulnscan_subgraph

async def run_vulnscan(source, intent_text=None, targets=None, modules=None, task_id: str | None = None):
    """Run the vulnscan subgraph. ``task_id`` is honored when provided so that
    the caller (router / orchestrator) can use the SAME id for the ES task, the
    scan_result stream and the API response. Without this, /tasks/{id}, /tasks/{id}/stream
    and /reports/{id} all 404 (P0-VS-2).
    """
    graph = get_vulnscan_subgraph()
    initial = _default_state(source, intent_text, targets, modules, task_id=task_id)
    result = await graph.ainvoke(initial)
    return result
