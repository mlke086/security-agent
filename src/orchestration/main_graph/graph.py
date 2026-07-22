import asyncio

from langgraph.graph import END, START, StateGraph

from src.common.logging.logger import get_logger
from src.orchestration.main_graph.nodes.aggregator import aggregator_node, ignore_node
from src.orchestration.main_graph.nodes.entry import entry_node
from src.orchestration.main_graph.nodes.orchestrator import orchestrator_node
from src.orchestration.main_graph.state import MainGraphState

logger = get_logger(__name__)

# ---------- Subgraph timeouts (seconds) ----------
_TIMEOUT_INVESTIGATE = 120
_TIMEOUT_VULN_HUNTER = 600
_TIMEOUT_RESPOND = 300


async def investigate_node(state: MainGraphState) -> dict:
    """Run the real investigation subgraph with timeout."""
    from src.orchestration.subgraphs.investigation.graph import build_investigation_subgraph

    subgraph = build_investigation_subgraph()
    iocs = state.get("raw_event", {}).get("iocs", {})
    sub_state = {
        "event_id": state["event_id"],
        "raw_event": state.get("raw_event", {}),
        "iocs": iocs,
        "raw_intel": None,
        "graph_relations": [],
        "investigation_log": [],
        "final_verdict": None,
        "confidence_score": None,
        "evidence_summary": None,
        "mitre_ttps": [],
    }
    try:
        result = await asyncio.wait_for(subgraph.ainvoke(sub_state), timeout=_TIMEOUT_INVESTIGATE)
        try:
            from src.common.audit.audit_logger import get_audit_logger

            await get_audit_logger().log(
                event_id=state["event_id"],
                node="investigate",
                action="investigation_complete",
                details={
                    "final_verdict": result.get("final_verdict", "unknown"),
                    "confidence_score": result.get("confidence_score", 0.0),
                },
            )
        except Exception:
            pass
        return {
            "subgraph_result": {
                "final_verdict": result.get("final_verdict", "unknown"),
                "confidence_score": result.get("confidence_score", 0.0),
                "evidence_summary": result.get("evidence_summary", ""),
                "mitre_ttps": result.get("mitre_ttps", []),
            }
        }
    except TimeoutError:
        logger.warning("investigation_timeout", event_id=state["event_id"])
        # P2-CORE-NEW-5 (2026-07-20): keep stage="investigate" so the
        # aggregator can decide between vuln_check and archive (the
        # investigation path is the canonical first-pass branch).
        return {
            "stage": "investigate",
            "subgraph_result": {
                "final_verdict": "timeout",
                "confidence_score": 0.0,
                "evidence_summary": "Investigation timed out",
            },
        }
    except Exception as exc:
        logger.error("investigation_error", event_id=state["event_id"], error=str(exc))
        return {
            "stage": "investigate",
            "subgraph_result": {
                "final_verdict": "error",
                "confidence_score": 0.0,
                "evidence_summary": f"Error: {exc}",
            },
        }


async def vuln_check_node(state: MainGraphState) -> dict:
    """Run the real vuln-hunter subgraph with timeout."""
    from src.orchestration.subgraphs.vuln_hunter.graph import build_vuln_hunter_subgraph
    from src.orchestration.subgraphs.vuln_hunter.memory import VulnHunterMemory

    subgraph = build_vuln_hunter_subgraph()
    sub_state = {
        "event_id": state["event_id"],
        "raw_event": state.get("raw_event", {}),
        "target": state.get("raw_event", {}).get("sanitized_text", "")[:500],
        "memory": VulnHunterMemory(
            target_info=state.get("raw_event", {}).get("sanitized_text", "")[:200]
        ),
        "cve_info": {},
        "exploit_chain": None,
        "current_poc": "",
        "investigation_log": [],
        "iteration_count": 0,
        "last_exec_result": None,
        "final_poc": None,
        "is_vulnerable": False,
    }
    # 漏洞子图最多 10 轮 × 3 节点 = 30 步，超过 LangGraph 默认递归上限 25。
    # 按设计上限放宽 recursion_limit，避免正常跑满迭代时被误判为 error。
    _vuln_config = {"recursion_limit": 35}
    try:
        result = await asyncio.wait_for(
            subgraph.ainvoke(sub_state, config=_vuln_config), timeout=_TIMEOUT_VULN_HUNTER
        )
        try:
            from src.common.audit.audit_logger import get_audit_logger

            await get_audit_logger().log(
                event_id=state["event_id"],
                node="vuln_check",
                action="vuln_check_complete",
                details={"is_vulnerable": result.get("is_vulnerable", False)},
            )
        except Exception:
            pass
        return {
            "stage": "verify",
            "subgraph_result": {
                # P1-CORE-NEW-2: derive final_verdict from is_vulnerable so
                # aggregator/runner store "true_positive" (not "unknown") and
                # the responder's playbook_matcher can match cve_exploit.yaml
                # (whose trigger requires verdict=="true_positive"). Without
                # this, confirmed-vuln events were stored as verdict="unknown"
                # and fell back to the LLM playbook path.
                "final_verdict": "true_positive"
                if result.get("is_vulnerable")
                else "false_positive",
                "confidence_score": 0.95 if result.get("is_vulnerable") else 0.2,
                "final_poc": result.get("final_poc", ""),
                "is_vulnerable": result.get("is_vulnerable", False),
                "exploit_chain": result.get("exploit_chain", ""),
            },
        }
    except TimeoutError:
        logger.warning("vuln_hunter_timeout", event_id=state["event_id"])
        # P2-CORE-NEW-5 (2026-07-20): set stage="verify" so route_after_verdict
        # takes the vuln-check branch. Without this the event silently falls
        # back to the first-pass investigation logic (which then archives it).
        return {
            "stage": "verify",
            "subgraph_result": {"final_verdict": "timeout", "confidence_score": 0.0},
        }
    except Exception as exc:
        logger.error("vuln_hunter_error", event_id=state["event_id"], error=str(exc))
        return {
            "stage": "verify",
            "subgraph_result": {
                "final_verdict": "error",
                "confidence_score": 0.0,
                "evidence_summary": f"Error: {exc}",
            },
        }


async def respond_node(state: MainGraphState) -> dict:
    """Run the responder subgraph with timeout."""
    from src.orchestration.subgraphs.responder.graph import build_responder_subgraph

    subgraph = build_responder_subgraph()
    sub = state.get("subgraph_result") or {}
    sub_state = {
        "event_id": state["event_id"],
        "verdict": sub.get("final_verdict", "unknown"),
        "confidence": sub.get("confidence_score", 0.0),
        "iocs": state.get("raw_event", {}).get("iocs", {}),
        "event_tags": state.get("event_tags", []),
        "playbook_draft": None,
        "operation_level": "L1",
        "approval_id": None,
        "approval_status": None,
        "execution_result": None,
    }
    try:
        result = await asyncio.wait_for(subgraph.ainvoke(sub_state), timeout=_TIMEOUT_RESPOND)
        # P1-CORE-NEW-1: surface approval_status so runner can derive the
        # correct event status. Previously only approval_id was passed back,
        # and runner treated "approval_id present" as "pending_approval" --
        # but by now hitl_approval_node has already waited for a terminal
        # decision, so every L3+ event was mis-stored as pending_approval
        # (even after approved+executed or rejected/timeout).
        return {
            "pending_action": {
                "approval_id": result.get("approval_id"),
                "approval_status": result.get("approval_status"),
                "execution_summary": result.get("execution_result"),
            }
        }
    except TimeoutError:
        logger.warning("responder_timeout", event_id=state["event_id"])
        return {"error": "responder_timeout"}
    except Exception as exc:
        logger.error("responder_error", event_id=state["event_id"], error=str(exc))
        return {"error": f"responder_error: {exc}"}


# ---------- Pre-investigation routing ----------
def route_decision(state: MainGraphState) -> str:
    priority = state.get("priority", "low")
    tags = state.get("event_tags", [])

    if priority == "low":
        return "ignore"
    if "vulnerability" in tags:
        return "vuln_check"
    if priority in ("high", "medium"):
        return "investigate"
    return "ignore"


# ---------- Post-aggregation routing (文档 4.3.2: 置信度阈值路由) ----------
def route_after_verdict(state: MainGraphState) -> str:
    sub = state.get("subgraph_result") or {}
    verdict = sub.get("final_verdict", "unknown")
    conf = sub.get("confidence_score", 0.0) or 0.0

    # P1-CORE-1: vuln-check subgraph path. The verdict-confident signal is the
    # authoritative one here -- if the vuln-hunter produced a working PoC or
    # confirmed a vulnerability (is_vulnerable / final_poc), route to respond
    # so the responder can pick a playbook. Otherwise archive.
    if state.get("stage") == "verify":
        is_vulnerable = bool(sub.get("is_vulnerable")) or bool(sub.get("final_poc"))
        if verdict == "true_positive" or is_vulnerable:
            return "respond"
        return "done"
    # 首次研判分流
    if verdict == "true_positive" and conf >= 0.8:
        return "respond"
    if 0.5 <= conf < 0.8:
        return "vuln_check"
    return "done"  # < 0.5 或 unknown → 归档


# ---------- Main graph assembly ----------
def build_main_graph():
    graph = StateGraph(MainGraphState)

    graph.add_node("entry", entry_node)
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("vuln_check", vuln_check_node)
    graph.add_node("aggregator", aggregator_node)
    graph.add_node("respond", respond_node)
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
    # aggregator 后按置信度分流（≥0.8→响应、0.5–0.8→漏洞验证、<0.5→归档）
    graph.add_conditional_edges(
        "aggregator",
        route_after_verdict,
        {
            "respond": "respond",
            "vuln_check": "vuln_check",
            "done": END,
        },
    )
    graph.add_edge("respond", END)
    graph.add_edge("ignore", END)

    return graph.compile()


def get_compiled_graph():
    return build_main_graph()
