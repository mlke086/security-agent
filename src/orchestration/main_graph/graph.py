from langgraph.graph import END, START, StateGraph

from src.common.logging.logger import get_logger
from src.orchestration.main_graph.nodes.aggregator import aggregator_node, ignore_node
from src.orchestration.main_graph.nodes.entry import entry_node
from src.orchestration.main_graph.nodes.orchestrator import orchestrator_node
from src.orchestration.main_graph.state import MainGraphState

logger = get_logger(__name__)


# ---------- Stub subgraphs (Week 1-2) ----------
async def investigation_stub(state: MainGraphState) -> dict:
    return {
        "subgraph_result": {
            "final_verdict": "true_positive",
            "confidence_score": 0.85,
            "evidence_summary": "Stub: investigation completed",
        }
    }


async def vuln_hunter_stub(state: MainGraphState) -> dict:
    return {
        "subgraph_result": {
            "final_poc": "# stub PoC",
            "is_vulnerable": True,
            "exploit_chain": "Stub: vuln verified",
        }
    }


# ---------- Routing logic ----------
def route_decision(state: MainGraphState) -> str:
    priority = state.get("priority", "low")
    tags = state.get("event_tags", [])

    if priority == "low":
        return "ignore"
    if "vulnerability" in tags:
        return "vuln_check"
    return "investigate"


# ---------- Main graph assembly ----------
def build_main_graph() -> StateGraph:
    graph = StateGraph(MainGraphState)

    graph.add_node("entry", entry_node)
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("investigate", investigation_stub)
    graph.add_node("vuln_check", vuln_hunter_stub)
    graph.add_node("aggregator", aggregator_node)
    graph.add_node("ignore", ignore_node)

    graph.add_edge(START, "entry")
    graph.add_edge("entry", "orchestrator")
    graph.add_conditional_edges(
        "orchestrator",
        route_decision,
        {
            "investigate": "investigate",
            "vuln_check": "vuln_check",
            "ignore": "ignore",
        },
    )
    graph.add_edge("investigate", "aggregator")
    graph.add_edge("vuln_check", "aggregator")
    graph.add_edge("aggregator", END)
    graph.add_edge("ignore", END)

    return graph.compile()


def get_compiled_graph():
    return build_main_graph()
