"""Asset-scan subgraph -- compiled graph (需求②).

线性流水线：parse_intent → discover → fingerprint → match_vulns →
llm_analysis → generate_report。由 asset-scan 服务的 TaskWorker
（run_asset_scan_from_envelope）驱动。
"""

from langgraph.graph import END, StateGraph

from src.orchestration.subgraphs.asset_scan.nodes import (
    _default_state,
    discover,
    fingerprint,
    generate_report,
    llm_analysis,
    match_vulns,
    parse_intent,
)
from src.orchestration.subgraphs.asset_scan.state import AssetScanState

_asset_scan_subgraph = StateGraph(AssetScanState)
_asset_scan_subgraph.add_node("parse_intent", parse_intent)
_asset_scan_subgraph.add_node("discover", discover)
_asset_scan_subgraph.add_node("fingerprint", fingerprint)
_asset_scan_subgraph.add_node("match_vulns", match_vulns)
_asset_scan_subgraph.add_node("llm_analysis", llm_analysis)
_asset_scan_subgraph.add_node("generate_report", generate_report)
_asset_scan_subgraph.set_entry_point("parse_intent")
_asset_scan_subgraph.add_edge("parse_intent", "discover")
_asset_scan_subgraph.add_edge("discover", "fingerprint")
_asset_scan_subgraph.add_edge("fingerprint", "match_vulns")
_asset_scan_subgraph.add_edge("match_vulns", "llm_analysis")
_asset_scan_subgraph.add_edge("llm_analysis", "generate_report")
_asset_scan_subgraph.add_edge("generate_report", END)
compiled_asset_scan_subgraph = _asset_scan_subgraph.compile()


def get_asset_scan_subgraph():
    return compiled_asset_scan_subgraph


async def run_asset_scan(envelope) -> dict:
    """Run the asset-scan subgraph from an AssetScanEnvelope.

    ``envelope`` 是 AssetScanEnvelope（鸭子类型：task_id/targets/ports/
    engine/modules/schedule/actor 字段）。
    """
    graph = get_asset_scan_subgraph()
    initial = _default_state(envelope)
    return await graph.ainvoke(initial)
