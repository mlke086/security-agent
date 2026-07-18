"""Update main.py to register auth and operations routers."""
path = "V:/project/security-agent/src/api/main.py"
content = open(path, "r", encoding="utf-8").read()

# Fix import: remove old import of HTTPBearer if present
# Add auth router import after the audit_logger import
old_imports = 'from src.common.audit.audit_logger import get_audit_logger'
new_imports = old_imports + '\nfrom src.api.auth import auth_router\nfrom src.api.routers.operations import router as operations_router'
if "auth_router" not in content:
    content = content.replace(old_imports, new_imports)

# Add include_router calls before the if __name__ block
old_end = 'if __name__ == "__main__":'
new_end = '# Include routers\napp.include_router(auth_router)\napp.include_router(operations_router)\n\n' + old_end
if "app.include_router(auth_router)" not in content:
    content = content.replace(old_end, new_end)

# Fix: make sure HTTPBearer import isn't duplicated
# The routes.py already has it

open(path, "w", encoding="utf-8").write(content)
import ast
ast.parse(content)
print("main.py updated OK")
