import re as re_mod
import ast

path = "V:/project/security-agent/tests/unit/preprocessing/test_sanitization_extra.py"
content = open(path, "r", encoding="utf-8").read()

old = '_rule = Rule(name="test", pattern=re.compile(""), mask_char="*")'
new = '_rule = Rule(name="test", pattern=re_mod.compile("."), type="pii", priority=1, mask="***")'

if old in content:
    content = content.replace(old, new)
    open(path, "w", encoding="utf-8").write(content)
    ast.parse(content)
    print("Fixed OK")
else:
    print(f"Could not find: {old}")
    # Try the current content
    import re
    m = re.search(r"_rule = Rule\([^)]+\)", content)
    if m:
        print(f"Current: {m.group()}")
