"""2026-08-06 LLM 分析监控:使用量聚合端点。

scan-engine 的 vulnscan 子图调 LLM 分析漏洞/生成报告时,把指标写入
Redis(llm:usage / llm:failures / llm:retry:* / llm:outcome:*)。本 router
在 gateway 侧读 Redis 聚合,供前端 LLM 分析监控页展示。

端点:
  - GET /api/v1/ai-analytics/llm-usage
        汇总:按 kind/status 计数 + 平均耗时 + 失败明细 + 待补扫批次 + 终态标记
  - GET /api/v1/ai-analytics/llm-usage/rescan
        待补扫批次列表(任务级)
"""
from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.api.auth.routes import require_role
from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/ai-analytics", tags=["llm-analytics"])

KEY_USAGE = "llm:usage"
KEY_FAILURES = "llm:failures"
KEY_ACTIVE = "llm:active"
RETRY_PREFIX = "llm:retry:"
OUTCOME_PREFIX = "llm:outcome:"


class LlmUsageSummary(BaseModel):
    total_calls: int = 0
    by_kind: dict[str, dict[str, int]] = {}
    success: int = 0
    timeout: int = 0
    failed: int = 0
    retried: int = 0
    active_calls: int = 0
    avg_duration_ms: int = 0
    total_duration_ms: int = 0
    failures_recent: list[dict[str, Any]] = []
    retry_pending: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    window_days: list[str] = []


async def _redis() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


@router.get("/llm-usage", response_model=LlmUsageSummary)
async def llm_usage(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> LlmUsageSummary:
    """聚合 LLM 分析调用使用量(scan-engine 写入 Redis 的指标)。"""
    out = LlmUsageSummary()
    try:
        r = await _redis()
        try:
            usage = await r.hgetall(KEY_USAGE)
            for key, val in usage.items():
                parts = key.split(":")
                if len(parts) != 3:
                    continue
                day, kind, metric = parts
                v = int(val)
                if day not in out.window_days:
                    out.window_days.append(day)
                if kind not in out.by_kind:
                    out.by_kind[kind] = {}
                out.by_kind[kind][metric] = out.by_kind[kind].get(metric, 0) + v
                if metric == "success":
                    out.success += v
                elif metric == "timeout":
                    out.timeout += v
                elif metric == "failed":
                    out.failed += v
                elif metric == "retry":
                    out.retried += v
                elif metric == "duration_ms":
                    out.total_duration_ms += v

            # 活跃调用
            raw_active = await r.get(KEY_ACTIVE)
            out.active_calls = int(raw_active or 0)

            # 最近失败明细(新->旧)
            raw_failures = await r.lrange(KEY_FAILURES, 0, 49)
            for item in raw_failures:
                try:
                    out.failures_recent.append(json.loads(item))
                except Exception:
                    pass

            # 待补扫批次(任务级)
            retry_keys = await r.keys(RETRY_PREFIX + "*")
            for key in sorted(retry_keys)[:50]:
                task_id = key[len(RETRY_PREFIX):]
                entries = await r.hgetall(key)
                out.retry_pending.append(
                    {
                        "task_id": task_id,
                        "pending_batches": len(entries),
                        "entries": [
                            {"finding_id": fid, "attempts": int(cnt)}
                            for fid, cnt in sorted(entries.items(), key=lambda x: int(x[1]), reverse=True)
                        ],
                    }
                )

            # 终态标记(AI 全/部分分析失败)
            outcome_keys = await r.keys(OUTCOME_PREFIX + "*")
            for key in sorted(outcome_keys)[:50]:
                task_id = key[len(OUTCOME_PREFIX):]
                data = await r.hgetall(key)
                data["task_id"] = task_id
                out.outcomes.append(data)

            # 计算总调用数与平均耗时
            out.total_calls = out.success + out.timeout + out.failed
            if out.total_calls:
                out.avg_duration_ms = out.total_duration_ms // out.total_calls
        finally:
            await r.aclose()
    except Exception as exc:
        logger.warning("llm_usage_aggregate_failed", error=str(exc))
    return out


@router.get("/llm-usage/rescan", response_model=list[dict[str, Any]])
async def llm_rescan_pending(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    """待补扫批次明细(供前端展开)。"""
    out: list[dict[str, Any]] = []
    try:
        r = await _redis()
        try:
            keys = await r.keys(RETRY_PREFIX + "*")
            for key in sorted(keys)[:100]:
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
        logger.warning("llm_rescan_list_failed", error=str(exc))
    return out


__all__ = ["router"]
