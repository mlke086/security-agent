import os
path = "src/common/config/settings.py"
c = open(path).read()
c = c.replace("from pydantic import Field", "from pydantic import Field, model_validator")
func = [
     "",
     '    @model_validator(mode="after")',
     "    def validate_api_secret_key(cls, info):",
     '        sk = info.data.get("api_secret_key", "")',
     "        if not sk:",
     "            import sys",
     '            print("FATAL: API_SECRET_KEY must be set", file=sys.stderr)',
     "            sys.exit(1)",
     "        return info",
     "",
]
c = c.replace("\\n# Logging\\n    log_level", "\\n" + "\\n".join(func) + "\\n# Logging\\n    log_level")
open(path, "w").write(c)
import ast; ast.parse(open(path).read())
print("Fixed settings.py")
