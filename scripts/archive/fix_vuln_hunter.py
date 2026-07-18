path = r"V:\project\security-agent\src\orchestration\main_graph\graph.py"
content = open(path, "r", encoding="utf-8").read()

old_start = 'from src.orchestration.subgraphs.vuln_hunter.graph import build_vuln_hunter_subgraph'
new_start = 'from src.orchestration.subgraphs.vuln_hunter.graph import build_vuln_hunter_subgraph\n    from src.orchestration.subgraphs.vuln_hunter.memory import VulnHunterMemory'
content = content.replace(old_start, new_start)

old_memory = '"memory": {"target_info": state.get("raw_event", {}).get("sanitized_text", "")[:200]},'
new_memory = '"memory": VulnHunterMemory(target_info=state.get("raw_event", {}).get("sanitized_text", "")[:200]),\n        "cve_info": {},\n        "exploit_chain": None,'
content = content.replace(old_memory, new_memory)

open(path, "w", encoding="utf-8").write(content)
print("graph.py fixed!")
import ast
ast.parse(content)
print("Syntax OK")
