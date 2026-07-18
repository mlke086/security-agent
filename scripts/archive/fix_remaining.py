"""Fix remaining indentation and validation issues."""
import os, ast

# Fix graph.py line 94 (5 spaces -> 4 spaces)
path = "src/orchestration/main_graph/graph.py"
content = open(path, "r", encoding="utf-8").read()
old_line = "     confidence = (state.get(\\\"subgraph_result\\\") or {}).get(\\\"confidence_score\\\", 0.0)"
new_line = "    confidence = (state.get(\\\"subgraph_result\\\") or {}).get(\\\"confidence_score\\\", 0.0)"
if old_line in content:
     content = content.replace(old_line, new_line)
     open(path, "w", encoding="utf-8").write(content)
     ast.parse(open(path, "r").read())
     print("Fixed graph.py line 94")
else:
     print("SKIP graph.py - pattern not found")

# Fix settings.py: add model_validator import + validation function
path = "src/common/config/settings.py"
content = open(path, "r", encoding="utf-8").read()
if "model_validator" not in content:
     content = content.replace("from pydantic import Field", "from pydantic import Field, model_validator")
     # Add validation function before Logging section
     old_section = "    # Sandbox"
     new_section = "    @model_validator(mode=\"after\")\n    def validate_api_secret_key(cls, info):\n        sk = info.data.get(\"api_secret_key\", \"\")\n        if not sk:\n            print(\"FATAL: API_SECRET_KEY must be set\", file=__import__(\"sys\").stderr)\n            __import__(\"sys\").exit(1)\n        return info\n\n    # Sandbox"
     if old_section in content:
         content = content.replace(old_section, new_section)
         open(path, "w", encoding="utf-8").write(content)
         ast.parse(open(path, "r").read())
         print("Added validation to settings.py")
     else:
         print("SKIP settings.py - section not found")
else:
     print("model_validator already present")

print("Done")
