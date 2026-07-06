import ast
from typing import Literal

from pydantic import BaseModel

ALLOWED_IMPORTS = frozenset([
    "requests", "socket", "json", "re", "time", "sys",
    "struct", "hashlib", "base64", "urllib", "http",
    "ssl", "threading", "itertools", "functools", "string",
    "collections", "math", "random", "binascii", "hmac",
])

DANGEROUS_CALLS = frozenset([
    "os.system", "os.popen", "os.execv", "os.execvp",
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "eval", "exec", "compile", "__import__",
    "open", "builtins.open",
])


class LinterResult(BaseModel):
    passed: bool
    error_type: Literal["syntax", "import", "dangerous_call"] | None = None
    error_detail: str | None = None
    suggestion: str | None = None
    line_number: int | None = None


class PoCLinter:
    """Three-channel static checker: syntax → import whitelist → dangerous calls."""

    def check(self, code: str) -> LinterResult:
        result = self._syntax_check(code)
        if not result.passed:
            return result
        result = self._import_check(code)
        if not result.passed:
            return result
        return self._dangerous_call_check(code)

    # ------------------------------------------------------------------

    def _syntax_check(self, code: str) -> LinterResult:
        try:
            ast.parse(code)
            return LinterResult(passed=True)
        except SyntaxError as exc:
            return LinterResult(
                passed=False,
                error_type="syntax",
                error_detail=str(exc.msg),
                suggestion=f"Fix syntax error near line {exc.lineno}: {exc.text}",
                line_number=exc.lineno,
            )

    def _import_check(self, code: str) -> LinterResult:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return LinterResult(passed=True)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in ALLOWED_IMPORTS:
                        return LinterResult(
                            passed=False,
                            error_type="import",
                            error_detail=f"Import '{alias.name}' is not in the allowlist",
                            suggestion=f"Use one of the allowed modules: {', '.join(sorted(ALLOWED_IMPORTS))}",
                            line_number=node.lineno,
                        )
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                if module and module not in ALLOWED_IMPORTS:
                    return LinterResult(
                        passed=False,
                        error_type="import",
                        error_detail=f"Import from '{node.module}' is not in the allowlist",
                        suggestion=f"Use one of the allowed modules: {', '.join(sorted(ALLOWED_IMPORTS))}",
                        line_number=node.lineno,
                    )
        return LinterResult(passed=True)

    def _dangerous_call_check(self, code: str) -> LinterResult:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return LinterResult(passed=True)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func)
            if name in DANGEROUS_CALLS:
                return LinterResult(
                    passed=False,
                    error_type="dangerous_call",
                    error_detail=f"Dangerous call '{name}' is prohibited in sandbox",
                    suggestion=f"Remove the call to '{name}'",
                    line_number=getattr(node, "lineno", None),
                )
        return LinterResult(passed=True)

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{PoCLinter._call_name(node.value)}.{node.attr}"
        return ""
