"""Fix remaining P1/P2 issues from code review."""
import os, ast, yaml, re
 
print("=== P2 Correctness Fixes ===")
 
# 1. Fix password regex (\\S+ -> \\S+(?:\\s+\\S+)* to catch spaces)
path = "src/preprocessing/rules/default_rules.yaml"
content = open(path, "r", encoding="utf-8").read()
# Replace \\S+ with a pattern that includes spaces
content = content.replace(r"\S+", r"\S+(?:\s+\S+)*")
open(path, "w", encoding="utf-8").write(content)
print("P2-11: Password regex \\S+ -> \\S+(?:\\s+\\S+)* (catches multi-word values)")
 
# 2. Remove duplicate PoCOutput class (first one is dead code)
path = "src/orchestration/subgraphs/vuln_hunter/poc_generator.py"
content = open(path, "r", encoding="utf-8").read()
# Remove the first PoCOutput (with confidence/trigger_condition)
old_class = """class PoCOutput(BaseModel):
    poc_code: str
    confidence: float
    trigger_condition: str
    expected_result: str
 
 
"""
new_class = ""
if old_class in content:
     content = content.replace(old_class, new_class)
     open(path, "w", encoding="utf-8").write(content)
     ast.parse(open(path, "r").read())
     print("P2-12: Duplicate PoCOutput removed")
else:
     # Try without the trailing newlines
     for v in ["", "\n", "\n\n"]:
         c = old_class.rstrip() + v
         if c in content:
             content = content.replace(c, "")
             open(path, "w", encoding="utf-8").write(content)
             print("P2-12: Duplicate PoCOutput removed (alt)")
             break
     else:
         print("P2-12: SKIP - PoCOutput not found")
 
print("\n=== Done ===")
