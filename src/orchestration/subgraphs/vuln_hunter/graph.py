from langgraph.graph import END, START, StateGraph

from src.orchestration.subgraphs.vuln_hunter.poc_generator import (
    check_convergence,
    finalize_node,
    generate_poc_node,
    linter_check_node,
    sandbox_exec_node,
)
from src.orchestration.subgraphs.vuln_hunter.state import VulnHunterSubState


def build_vuln_hunter_subgraph():
    graph = StateGraph(VulnHunterSubState)

    graph.add_node("generate_poc", generate_poc_node)
    graph.add_node("linter_check", linter_check_node)
    graph.add_node("sandbox_exec", sandbox_exec_node)
    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "generate_poc")
    graph.add_edge("generate_poc", "linter_check")
    graph.add_edge("linter_check", "sandbox_exec")
    graph.add_conditional_edges(
        "sandbox_exec",
        check_convergence,
        {
            "generate_poc": "generate_poc",
            "finalize": "finalize",
        },
    )
    graph.add_edge("finalize", END)

    return graph.compile()
