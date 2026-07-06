from langgraph.graph import END, START, StateGraph

from src.orchestration.subgraphs.investigation.cti_analyst import cti_analyst_node
from src.orchestration.subgraphs.investigation.investigator import investigator_node
from src.orchestration.subgraphs.investigation.state import InvestigationSubState


def build_investigation_subgraph():
    graph = StateGraph(InvestigationSubState)

    graph.add_node("cti_analyst", cti_analyst_node)
    graph.add_node("investigator", investigator_node)

    graph.add_edge(START, "cti_analyst")
    graph.add_edge("cti_analyst", "investigator")
    graph.add_edge("investigator", END)

    return graph.compile()
