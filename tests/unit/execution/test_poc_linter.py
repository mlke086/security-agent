"""Tests for PoCLinter — syntax, import whitelist, dangerous call checks."""
from src.execution.linter.poc_linter import PoCLinter

linter = PoCLinter()


class TestSyntaxCheck:
    def test_valid_syntax(self):
        result = linter.check("import requests\nr = requests.get('http://test.com')")
        assert result.passed is True

    def test_syntax_error(self):
        result = linter.check("import requests\ndef broken(")
        assert result.passed is False
        assert result.error_type == "syntax"
        assert result.line_number is not None

    def test_empty_code(self):
        result = linter.check("")
        assert result.passed is True

    def test_just_comment(self):
        result = linter.check("# just a comment")
        assert result.passed is True


class TestImportCheck:
    def test_allowed_import(self):
        result = linter.check("import requests")
        assert result.passed is True

    def test_disallowed_import(self):
        result = linter.check("import os")
        assert result.passed is False
        assert result.error_type == "import"
        assert "os" in result.error_detail

    def test_allowed_from_import(self):
        result = linter.check("from requests import get")
        assert result.passed is True

    def test_disallowed_from_import(self):
        result = linter.check("from subprocess import run")
        assert result.passed is False
        assert result.error_type == "import"

    def test_import_suggestion(self):
        result = linter.check("import os")
        assert result.suggestion is not None
        assert "allowed" in result.suggestion


class TestDangerousCallCheck:
    def test_allowed_call(self):
        result = linter.check("import requests\nrequests.get('http://test.com')")
        assert result.passed is True

    def test_eval_call(self):
        result = linter.check("eval('print(1)')")
        assert result.passed is False
        assert result.error_type == "dangerous_call"

    def test_eval_dangerous_call(self):
        result = linter.check("import requests\neval('print(1)')")
        assert result.passed is False
        assert result.error_type == "dangerous_call"

    def test_open_dangerous_call(self):
        result = linter.check("import json\nopen('/etc/passwd')")
        assert result.passed is False
        assert result.error_type == "dangerous_call"

    def test_exec_call(self):
        result = linter.check("exec('print(1)')")
        assert result.passed is False
        assert result.error_type == "dangerous_call"


class TestMultiChannel:
    def test_syntax_beats_import(self):
        """Syntax errors are reported before import violations."""
        result = linter.check("import os\ndef broken(")
        assert result.error_type == "syntax"

    def test_import_beats_dangerous(self):
        """Import violations are reported before dangerous calls."""
        result = linter.check("import os\nos.system('ls')")
        assert result.error_type == "import"
