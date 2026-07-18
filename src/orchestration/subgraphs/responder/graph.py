from langgraph.graph import END, START, StateGraph

from src.orchestration.subgraphs.responder.hitl_handler import (
    execute_response_node,
    hitl_approval_node,
    reject_response_node,
)
from src.orchestration.subgraphs.responder.playbook_matcher import playbook_matcher_node
from src.orchestration.subgraphs.responder.state import ResponderSubState


def route_after_hitl(state: ResponderSubState) -> str:
    return "execute_response" if state.get("approval_status") == "approved" else "reject"


def build_responder_subgraph():
    graph = StateGraph(ResponderSubState)

    graph.add_node("playbook_matcher", playbook_matcher_node)
    graph.add_node("hitl_approval", hitl_approval_node)
    graph.add_node("execute_response", execute_response_node)
    graph.add_node("reject_response", reject_response_node)

    graph.add_edge(START, "playbook_matcher")
    graph.add_edge("playbook_matcher", "hitl_approval")
    graph.add_conditional_edges("hitl_approval", route_after_hitl, {
        "execute_response": "execute_response",
        "reject": "reject_response",
    })
    graph.add_edge("execute_response", END)
    graph.add_edge("reject_response", END)

    return graph.compile()
