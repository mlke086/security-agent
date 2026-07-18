"""Unit tests for SandboxExecutor (no-docker path + mocked container run)."""

from unittest.mock import MagicMock

import pytest

pytest.importorskip("docker")  # executor imports docker; skip if unavailable

from src.execution.sandbox.executor import ExecutionResult, SandboxExecutor  # noqa: E402


@pytest.mark.asyncio
async def test_execute_no_docker():
    ex = SandboxExecutor()
    ex._docker = None
    result = await ex.execute("print('hi')")
    assert result.status == "error"
    assert "Docker not available" in result.stderr


@pytest.mark.asyncio
async def test_execute_success_with_mocked_container(monkeypatch):
    ex = SandboxExecutor()
    ex._docker = MagicMock()  # truthy so execute proceeds past the None check

    def fake_run(name, code):
        return ExecutionResult(
            status="success", stdout="VULNERABLE\n", stderr="", exit_code=0, is_vulnerable=True
        )

    monkeypatch.setattr(ex, "_run_container", fake_run)
    result = await ex.execute("exploit code")
    assert result.status == "success"
    assert result.is_vulnerable is True
