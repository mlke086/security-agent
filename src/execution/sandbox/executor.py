import asyncio
import time
import uuid
from typing import Literal

import docker
from docker.errors import DockerException
from pydantic import BaseModel

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

SANDBOX_IMAGE = "security-agent-sandbox:latest"


class ExecutionResult(BaseModel):
    status: Literal["success", "crash", "timeout", "error"]
    stdout: str
    stderr: str
    exit_code: int = 0
    crash_log: str | None = None
    execution_time_ms: int = 0
    is_vulnerable: bool = False


class SandboxExecutor:
    """Execute PoC code in an isolated Docker container."""

    def __init__(self) -> None:
        settings = get_settings()
        self._timeout = settings.sandbox_exec_timeout_sec
        self._network = settings.sandbox_network
        try:
            self._docker = docker.from_env()
        except DockerException as exc:
            logger.warning("docker_unavailable", error=str(exc))
            self._docker = None  # type: ignore[assignment]

    async def execute(self, code: str) -> ExecutionResult:
        if self._docker is None:
            return ExecutionResult(status="error", stdout="", stderr="Docker not available", exit_code=-1)

        start = time.monotonic()
        container_name = f"poc-{uuid.uuid4().hex[:8]}"

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._run_container, container_name, code),
                timeout=self._timeout,
            )
            result.execution_time_ms = int((time.monotonic() - start) * 1000)
            return result
        except asyncio.TimeoutError:
            await asyncio.to_thread(self._kill_container, container_name)
            return ExecutionResult(
                status="timeout",
                stdout="",
                stderr=f"Execution exceeded {self._timeout}s timeout",
                execution_time_ms=self._timeout * 1000,
            )
        except Exception as exc:
            logger.error("sandbox_exec_error", error=str(exc))
            return ExecutionResult(status="error", stdout="", stderr=str(exc), exit_code=-1)

    # ------------------------------------------------------------------

    def _run_container(self, name: str, code: str) -> ExecutionResult:
        try:
            container = self._docker.containers.run(
                SANDBOX_IMAGE,
                command=["python3", "-c", code],
                name=name,
                detach=False,
                remove=True,
                network=self._network,
                mem_limit="1g",
                cpu_period=100000,
                cpu_quota=200000,   # 2 CPUs
                read_only=True,
                tmpfs={"/tmp": "size=64m"},
                security_opt=["no-new-privileges:true", "seccomp=runtime/default"],
                stdout=True,
                stderr=True,
            )
            # container.run with detach=False returns bytes output
            output = container if isinstance(container, bytes) else b""
            stdout_text = output.decode("utf-8", errors="replace")
            is_vuln = "VULNERABLE" in stdout_text or "exploit_success" in stdout_text.lower()
            return ExecutionResult(
                status="success" if is_vuln else "crash",
                stdout=stdout_text,
                stderr="",
                exit_code=0,
                is_vulnerable=is_vuln,
            )
        except docker.errors.ContainerError as exc:
            return ExecutionResult(
                status="crash",
                stdout="",
                stderr=exc.stderr.decode("utf-8", errors="replace") if exc.stderr else str(exc),
                exit_code=exc.exit_status,
                is_vulnerable=False,
            )

    def _kill_container(self, name: str) -> None:
        try:
            c = self._docker.containers.get(name)
            c.kill()
            c.remove(force=True)
        except Exception:
            pass
