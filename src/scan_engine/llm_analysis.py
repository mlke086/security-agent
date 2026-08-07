"""2026-08-06 LLM 分析监控:漏洞分析/报告生成的超时·失败·重试。

背景:扫描任务执行完会调 LLM 逐批分析漏洞(analyze_findings)与生成报告摘要
(generate_report)。此前失败只记 structlog 日志、无重试、无指标,运维看不到
AI 调用的健康度。本模块集中实现:

1. 指标埋点(进程内 prometheus_counter/histogram,跨服务由 gateway 读 Redis 聚合):
   - llm_analysis_total            Counter{kind,status}  调用总数(成功/超时/失败/重试)
   - llm_analysis_duration_seconds Histogram             调用耗时
2. Redis 持久化(gateway 聚合 + 跨进程可见):
   - llm:usage                     Hash  当日各状态计数 + 累计耗时
   - llm:failures                  List  最近失败明细(JSON,上限 200)
   - llm:retry:{task_id}           Hash  待补扫批次(finding_id -> attempt 计数)
   - llm:active                    Gauge 活跃 LLM 调用数(空闲判定用)
3. 两级重试:
   - 第一层(即时):单批失败立刻重试 ``llm_analysis_retry_attempts`` 次,指数退避
     ``llm_analysis_retry_backoff_sec``;仍失败则批次进 ``llm:retry:*`` 待补扫,
     该批 findings 写 fallback("等待补扫")。
   - 第二层(空闲补扫):scan-engine lifespan 起的 ``rescan_loop`` 周期检查
     ``llm_analysis_rescan_check_interval_sec``;当活跃 LLM 调用数 ≤
     ``llm_analysis_busy_threshold`` 时,取一个待补扫批次重新分析,累计尝试
     ≤ ``llm_analysis_max_total_attempts``;达到上限仍未成功:
       - 该任务所有批次都失败   -> 标记 "AI全部分析失败"
       - 部分成功部分失败        -> 标记 "AI部分分析失败"
   任务队列本身继续保留(不删除),标记后不再自动补扫,由管理员决定。

所有参数均来自 Settings(Nacos 可热更新):llm_analysis_*。
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, TypeVar

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# Redis keys
KEY_USAGE = "llm:usage"
KEY_FAILURES = "llm:failures"
KEY_ACTIVE = "llm:active"
RETRY_PREFIX = "llm:retry:"
# 失败明细上限
FAILURES_CAP = 200
# 单任务最大待补扫批次(防恶意超大任务撑爆)
MAX_RETRY_BATCHES_PER_TASK = 200

# ---- prometheus 指标(进程内) ----
try:
    from prometheus_client import Counter, Gauge, Histogram

    _llm_total = Counter(
        "llm_analysis_total",
        "LLM analysis calls by kind and status",
        ["kind", "status"],
    )
    _llm_duration = Histogram(
        "llm_analysis_duration_seconds",
        "LLM analysis call duration",
        ["kind"],
        buckets=(0.5, 1, 2, 5, 10, 20, 30, 60, 120, 240, 480),
    )
    _llm_active = Gauge("llm_analysis_active", "Active LLM analysis calls")
except Exception:  # pragma: no cover - prometheus_client 缺失时降级
    _llm_total = None
    _llm_duration = None
    _llm_active = None

# 进程内活跃调用数(与 Redis gauge 同步,快速判定)
_active_calls = 0
_active_lock = asyncio.Lock()


async def _incr_active() -> None:
    global _active_calls
    async with _active_lock:
        _active_calls += 1
    try:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            await r.incr(KEY_ACTIVE)
            await r.expire(KEY_ACTIVE, get_settings().llm_analysis_metrics_ttl_sec)
        finally:
            await r.aclose()
    except Exception:
        pass
    if _llm_active is not None:
        _llm_active.inc()


async def _decr_active() -> None:
    global _active_calls
    async with _active_lock:
        _active_calls = max(0, _active_calls - 1)
    try:
        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            await r.decr(KEY_ACTIVE)
            await r.expire(KEY_ACTIVE, get_settings().llm_analysis_metrics_ttl_sec)
        finally:
            await r.aclose()
    except Exception:
        pass
    if _llm_active is not None:
        _llm_active.dec()


def active_call_count() -> int:
    """进程内活跃 LLM 分析调用数(空闲判定第一来源)。"""
    return _active_calls


async def _redis() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


async def _record(kind: str, status: str, duration_ms: int, extra: dict[str, Any] | None = None) -> None:
    """记录一次调用到 prometheus + Redis(llm:usage / llm:failures)。"""
    if _llm_total is not None:
        _llm_total.labels(kind=kind, status=status).inc()
    if _llm_duration is not None and duration_ms >= 0:
        _llm_duration.labels(kind=kind).observe(duration_ms / 1000.0)
    try:
        r = await _redis()
        try:
            day = datetime.now(UTC).strftime("%Y-%m-%d")
            pipe = r.pipeline()
            pipe.hincrby(KEY_USAGE, f"{day}:{kind}:{status}", 1)
            pipe.hincrby(KEY_USAGE, f"{day}:{kind}:duration_ms", duration_ms)
            pipe.expire(KEY_USAGE, get_settings().llm_analysis_metrics_ttl_sec)
            if status in ("timeout", "failed") and extra:
                pipe.lpush(
                    KEY_FAILURES,
                    json.dumps(
                        {
                            "ts": datetime.now(UTC).isoformat(),
                            "kind": kind,
                            "status": status,
                            "duration_ms": duration_ms,
                            **extra,
                        },
                        default=str,
                    ),
                )
                pipe.ltrim(KEY_FAILURES, 0, FAILURES_CAP - 1)
                pipe.expire(KEY_FAILURES, get_settings().llm_analysis_metrics_ttl_sec)
            await pipe.execute()
        finally:
            await r.aclose()
    except Exception as exc:
        logger.warning("llm_metric_record_failed", error=str(exc))


async def enqueue_retry_batch(task_id: str, finding_ids: list[str]) -> None:
    """失败批次进 Redis 待补扫队列。finding_ids 为该批次内未成功的 finding_id 列表。"""
    if not finding_ids:
        return
    try:
        r = await _redis()
        try:
            key = RETRY_PREFIX + task_id
            pipe = r.pipeline()
            for fid in finding_ids:
                pipe.hincrby(key, fid, 1)  # value = 已尝试次数
            pipe.expire(key, get_settings().llm_analysis_metrics_ttl_sec)
            await pipe.execute()
            logger.info(
                "llm_retry_batch_enqueued",
                task_id=task_id,
                findings=len(finding_ids),
            )
        finally:
            await r.aclose()
    except Exception as exc:
        logger.warning("llm_retry_enqueue_failed", error=str(exc))


async def list_retry_tasks(limit: int = 50) -> list[dict[str, Any]]:
    """列出所有待补扫批次(供 gateway 聚合端点与补扫循环)。"""
    out: list[dict[str, Any]] = []
    try:
        r = await _redis()
        try:
            keys = await r.keys(RETRY_PREFIX + "*")
            keys = sorted(keys)[:limit]
            for key in keys:
                task_id = key[len(RETRY_PREFIX):]
                entries = await r.hgetall(key)
                out.append(
                    {
                        "task_id": task_id,
                        "pending_batches": len(entries),
                        "entries": [
                            {"finding_id": fid, "attempts": int(cnt)}
                            for fid, cnt in sorted(entries.items(), key=lambda x: int(x[1]), reverse=True)
                        ],
                    }
                )
        finally:
            await r.aclose()
    except Exception as exc:
        logger.warning("llm_retry_list_failed", error=str(exc))
    return out


async def remove_retry_batch(task_id: str, finding_ids: list[str]) -> None:
    """补扫成功后从待补扫队列移除对应 finding。"""
    if not finding_ids:
        return
    try:
        r = await _redis()
        try:
            key = RETRY_PREFIX + task_id
            pipe = r.pipeline()
            for fid in finding_ids:
                pipe.hdel(key, fid)
            await pipe.execute()
            remaining = await r.hlen(key)
            if remaining == 0:
                await r.delete(key)
        finally:
            await r.aclose()
    except Exception as exc:
        logger.warning("llm_retry_remove_failed", error=str(exc))


async def _is_idle() -> bool:
    """队列空闲判定:活跃 LLM 调用 ≤ busy_threshold。"""
    s = get_settings()
    # 进程内计数优先(瞬时准确);Redis gauge 兜底(跨进程,如多个 worker)
    if _active_calls <= s.llm_analysis_busy_threshold:
        return True
    try:
        r = await _redis()
        try:
            raw = await r.get(KEY_ACTIVE)
            return int(raw or 0) <= s.llm_analysis_busy_threshold
        finally:
            await r.aclose()
    except Exception:
        return False


async def rescan_loop(stop_event: asyncio.Event | None = None) -> None:
    """空闲补扫主循环(scan-engine lifespan 启动)。

    周期检查:若启用 && 空闲 && 有待补扫批次,则取 attempt 最小的任务重新分析。
    由 ``rescan_one_batch`` 回调执行真实 LLM 调用(在 nodes.py 注入,避免本模块
    依赖 vulnscan 子图造成循环 import)。
    """
    from src.orchestration.subgraphs.vulnscan.rescan import rescan_one_batch

    s = get_settings()
    logger.info(
        "llm_rescan_loop_started",
        interval_sec=s.llm_analysis_rescan_check_interval_sec,
        enabled=s.llm_analysis_rescan_enabled,
    )
    while stop_event is None or not stop_event.is_set():
        try:
            if s.llm_analysis_rescan_enabled and await _is_idle():
                pending = await list_retry_tasks(limit=10)
                for item in pending:
                    if not (s.llm_analysis_rescan_enabled and await _is_idle()):
                        break
                    try:
                        await rescan_one_batch(item["task_id"])
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("llm_rescan_batch_failed", task_id=item["task_id"], error=str(exc))
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm_rescan_loop_error", error=str(exc))
        try:
            await asyncio.sleep(s.llm_analysis_rescan_check_interval_sec)
        except asyncio.CancelledError:
            break


# ---- 即时重试包装(供 nodes.py 使用) ----

T = TypeVar("T")


async def chat_with_retry(
    kind: str,
    call: Callable[[], Awaitable[T]],
    *,
    task_id: str | None = None,
    batch_idx: int | None = None,
    finding_ids: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> T:
    """带两级重试的 LLM 调用包装。

    第一层:失败后即时重试 ``llm_analysis_retry_attempts`` 次(指数退避)。
    仍失败:记录 timeout/failed 指标 + 失败明细,批次进待补扫队列(若给了
    finding_ids),并抛出最后一次异常让调用方写 fallback。

    ``call`` 必须是每次新建的 coroutine factory(不能复用已 await 的协程)。
    """
    s = get_settings()
    attempts = max(1, s.llm_analysis_retry_attempts + 1)  # 首次 + 重试次数
    backoff = s.llm_analysis_retry_backoff_sec
    last_exc: Exception | None = None
    await _incr_active()
    try:
        for attempt in range(attempts):
            t0 = time.monotonic()
            try:
                result = await call()
                duration_ms = int((time.monotonic() - t0) * 1000)
                await _record(kind, "success", duration_ms, extra)
                if attempt > 0:
                    await _record(kind, "retry", duration_ms, extra)
                    logger.info("llm_call_recovered", kind=kind, task_id=task_id, attempt=attempt)
                return result
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                duration_ms = int((time.monotonic() - t0) * 1000)
                status = "timeout" if _is_timeout(exc) else "failed"
                # 失败明细自动带 error/task/batch(前端失败列表可读)
                fail_extra = dict(extra or {})
                fail_extra.setdefault("error", str(exc)[:300])
                if task_id:
                    fail_extra.setdefault("task_id", task_id)
                if batch_idx is not None:
                    fail_extra.setdefault("batch", batch_idx)
                await _record(kind, status, duration_ms, fail_extra)
                logger.warning(
                    "llm_call_attempt_failed",
                    kind=kind,
                    task_id=task_id,
                    batch_idx=batch_idx,
                    attempt=attempt + 1,
                    status=status,
                    error=str(exc)[:300],
                )
                if attempt < attempts - 1:
                    await asyncio.sleep(backoff * (2**attempt))
        # 全部即时重试失败
        if finding_ids and task_id:
            await enqueue_retry_batch(task_id, finding_ids)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("llm call failed without exception")  # pragma: no cover
    finally:
        await _decr_active()


def _is_timeout(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    return "timeout" in name or "timeout" in msg or "deadline" in msg


# ---- 失败标记(补扫达到上限后写入任务状态) ----

async def mark_analysis_outcome(task_id: str, total_findings: int, succeeded: int) -> None:
    """补扫达上限后,给任务打终态标记(不进 ES 状态机,写 Redis 供监控/前端展示)。"""
    try:
        r = await _redis()
        try:
            if succeeded <= 0:
                reason = "AI全部分析失败"
            elif succeeded < total_findings:
                reason = "AI部分分析失败"
            else:
                return  # 全部成功无需标记
            await r.hset(f"llm:outcome:{task_id}", mapping={"reason": reason, "succeeded": succeeded, "total": total_findings, "ts": datetime.now(UTC).isoformat()})
            await r.expire(f"llm:outcome:{task_id}", get_settings().llm_analysis_metrics_ttl_sec)
            logger.warning("llm_analysis_final_outcome", task_id=task_id, reason=reason, succeeded=succeeded, total=total_findings)
        finally:
            await r.aclose()
    except Exception as exc:
        logger.warning("llm_outcome_mark_failed", error=str(exc))


def new_batch_id() -> str:
    """补扫批次唯一 ID(用于失败明细关联)。"""
    return uuid.uuid4().hex[:12]
