"""子进程编排（需求②: asset-scan scanner 基础设施）。

统一封装 nmap / masscan / nuclei 子进程的执行：超时 kill、Redis
取消墓碑检查、并发限流（信号量）、stdout/stderr 捕获。所有扫描
模块（discovery/fingerprint/vuln_match）只依赖本 runner，不直接
碰 asyncio subprocess。
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

CancelCheck = Callable[[], Awaitable[bool]] | None


class ScannerRunner:
    """子进程执行器：超时 + 取消 + 限流。

    - ``timeout_sec``: 单个子进程的硬超时（超时 SIGKILL 并抛 TimeoutError）。
    - ``cancel_check``: 每个扫描阶段入口调用的取消探测（Redis 墓碑）,
      返回 True 表示应中止, 抛 ``asyncio.CancelledError``。
    - ``semaphore``: 进程级并发限流（masscan 是网络密集工具, 多个
      并发大网段扫描会打爆目标网络）。
    """

    def __init__(
        self,
        *,
        timeout_sec: int = 3600,
        concurrency: int = 2,
        cancel_check: CancelCheck = None,
        redis_url: str | None = None,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.cancel_check = cancel_check
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._redis: aioredis.Redis | None = None
        self._redis_url = redis_url

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self._redis_url or get_settings().redis_url, decode_responses=True
            )
        return self._redis

    async def check_cancelled(self, task_id: str | None = None) -> None:
        """Redis 墓碑取消探测: 存在 cancel key 则抛 CancelledError。"""
        if task_id is None:
            return
        try:
            from src.orchestration.task_queue.keys import asset_cancel_key

            redis = await self._get_redis()
            if await redis.exists(asset_cancel_key(task_id)):
                logger.warning("asset_scan_cancelled", task_id=task_id)
                raise asyncio.CancelledError(f"task {task_id} cancelled")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            # 取消探测失败不阻断扫描（Redis 抖动时扫描继续, 由超时兜底）。
            logger.debug("asset_cancel_check_failed", error=str(exc))

    async def run(
        self,
        args: list[str],
        *,
        timeout_sec: int | None = None,
        task_id: str | None = None,
    ) -> tuple[int, str, str]:
        """Run a subprocess; return ``(returncode, stdout, stderr)``.

        - 超时: SIGKILL + 抛 ``asyncio.TimeoutError``（调用方决定重试/放弃）。
        - 取消: 执行前 + 执行中每 2s 探测一次 Redis 墓碑。
        - 并发: 受信号量限制。
        """
        async with self._semaphore:
            await self.check_cancelled(task_id)
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            timeout = timeout_sec or self.timeout_sec

            async def _watch_cancel() -> None:
                while True:
                    await asyncio.sleep(2)
                    try:
                        await self.check_cancelled(task_id)
                    except asyncio.CancelledError:
                        if proc.returncode is None:
                            proc.kill()
                        raise

            watcher = asyncio.create_task(_watch_cancel()) if task_id else None
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning(
                    "scanner_subprocess_timeout",
                    argv0=args[0] if args else "?",
                    timeout=timeout,
                )
                raise
            finally:
                if watcher is not None:
                    watcher.cancel()
                    try:
                        await watcher
                    except (asyncio.CancelledError, Exception):  # noqa: BLE001
                        pass
            return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:  # noqa: BLE001
                pass
            self._redis = None


_runner: ScannerRunner | None = None


def get_runner(**kwargs: Any) -> ScannerRunner:
    """进程级单例 runner（并发信号量跨模块共享）。"""
    global _runner
    if _runner is None:
        settings = get_settings()
        _runner = ScannerRunner(
            timeout_sec=settings.asset_scan_task_timeout_sec,
            concurrency=settings.asset_scan_concurrency,
            **kwargs,
        )
    return _runner
