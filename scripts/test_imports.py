import sys


def check(label, ok):
    print(f"  {'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        sys.exit(1)


print("=== Sprint 0 Import Smoke Test ===")

from src.common.config.settings import get_settings
s = get_settings()
check("settings", True)

from src.common.logging.logger import configure_logging, get_logger
configure_logging()
logger = get_logger("test")
check("logging", True)

from src.orchestration.main_graph.state import MainGraphState
check("graph state", True)

from src.orchestration.main_graph.nodes.entry import entry_node
check("entry_node", True)

from src.orchestration.main_graph.nodes.orchestrator import orchestrator_node
check("orchestrator_node", True)

from src.orchestration.main_graph.nodes.aggregator import aggregator_node, ignore_node
check("aggregator_node", True)

from src.orchestration.main_graph.graph import get_compiled_graph
g = get_compiled_graph()
check("compiled graph", True)

from src.knowledge.models.adapter import get_model_adapter
a = get_model_adapter()
check("model adapter", True)

from src.api.main import app
check("fastapi app", True)

from src.common.audit.audit_logger import get_audit_logger
al = get_audit_logger()
check("audit_logger", True)

from src.orchestration.subgraphs.investigation.graph import build_investigation_subgraph
check("investigation subgraph", True)

print(f"\n{'='*30} ALL SPRINT 0 IMPORTS PASSED {'='*30}")
