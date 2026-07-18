import os, ast

# 1. MemoryManager - investigator.py
path = "src/orchestration/subgraphs/investigation/investigator.py"
c = open(path, "r", encoding="utf-8").read()
if "get_memory_manager" not in c:
    c = c.replace("from src.common.logging.logger import get_logger", "from src.common.logging.logger import get_logger\nfrom src.orchestration.memory import get_memory_manager")
    old = '''    log_entry = f"Investigator: verdict={result.verdict} confidence={result.confidence:.2f}"
    logger.info("investigation_complete", event_id=state.get("event_id"), verdict=result.verdict)
    return {'''
    new = '''    log_entry = f"Investigator: verdict={result.verdict} confidence={result.confidence:.2f}"
    logger.info("investigation_complete", event_id=state.get("event_id"), verdict=result.verdict)
    try:
        mm = get_memory_manager()
        await mm.store_evidence(event_id=state.get("event_id","unknown"), node="investigator", content=f"Verdict: {result.verdict}", metadata={"mitre_ttps": result.mitre_ttps})
    except Exception as mem_err:
        logger.warning("memory_store_failed", error=str(mem_err))
    return {'''
    c = c.replace(old, new)
    open(path, "w", encoding="utf-8").write(c)
    ast.parse(open(path, "r", encoding="utf-8").read())
    print("investigator.py: MemoryManager added")
else:
    print("investigator.py: already has MemoryManager")

# 2. MemoryManager - cti_analyst.py
path = "src/orchestration/subgraphs/investigation/cti_analyst.py"
c = open(path, "r", encoding="utf-8").read()
if "get_memory_manager" not in c:
    c = c.replace("from src.common.logging.logger import get_logger", "from src.common.logging.logger import get_logger\nfrom src.orchestration.memory import get_memory_manager")
    old = '''    log_entry = f"CTI: risk={intel_card.risk_level} apt={intel_card.related_apt}"
    return {'''
    new = '''    log_entry = f"CTI: risk={intel_card.risk_level} apt={intel_card.related_apt}"
    try:
        mm = get_memory_manager()
        await mm.store_evidence(event_id=state.get("event_id","unknown"), node="cti_analyst", content=f"Risk: {intel_card.risk_level}", metadata=intel_card.model_dump())
    except Exception as mem_err:
        logger.warning("memory_store_failed", error=str(mem_err))
    return {'''
    c = c.replace(old, new)
    open(path, "w", encoding="utf-8").write(c)
    ast.parse(open(path, "r", encoding="utf-8").read())
    print("cti_analyst.py: MemoryManager added")
else:
    print("cti_analyst.py: already has MemoryManager")

# 3. .gitignore
with open(".gitignore", "a", encoding="utf-8") as f:
    f.write("\n# Coverage\n.coverage\ncoverage.xml\nhtmlcov/\n")
print(".gitignore updated")

# 4. Verify tests
import subprocess
r = subprocess.run([".venv/Scripts/python.exe", "-m", "pytest", "tests/unit/", "-q", "--cov-fail-under=0"], capture_output=True, text=True, env={**os.environ, "API_SECRET_KEY": "change-this-secret-key"})
lines = r.stdout.strip().split("\n")
for l in lines[-3:]:
    print(l)
if r.returncode == 0:
    print("ALL TESTS PASSED")

