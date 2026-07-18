import ast
path = "src/common/config/settings.py"
c = open(path, "r", encoding="utf-8").read()
c = c.replace("model_validator, model_validator", "model_validator")
lines = c.split("\n")
keep = True
count = 0
new_lines = []
for l in lines:
    if "def validate_api_secret_key" in l:
        count += 1
        if count == 2:
            keep = False
            continue
    if not keep:
        stripped = l.strip()
        if stripped == "" or l[0].isspace():
            continue
        else:
            keep = True
    if keep:
        new_lines.append(l)
c = "\n".join(new_lines)
ast.parse(c)
open(path, "w", encoding="utf-8").write(c)
print("Fixed")
