"""Redis key/stream naming for the vulnscan task queue.

Centralising the strings here lets ops grep one file for "vulnscan:" when
diagnosing keys with ``redis-cli --scan`` and avoids drift between writer
(API) and reader (worker).
"""

from __future__ import annotations

# Stream holding pending vulnscan tasks. Producer = API router,
# Consumer = TaskWorker(s). Bounded only by Redis maxmemory.
STREAM_TASKS: str = "vulnscan:queue:tasks"

# Dead-letter stream. After ``MAX_DELIVERY`` redeliveries (via XAUTOCLAIM
# loop) the message is moved here so operators can inspect / replay.
STREAM_DLQ: str = "vulnscan:queue:dlq"

# Single consumer group shared by every worker in the fleet. This is what
# spreads load: redis hands each new entry to exactly one member of the
# group that has ``id == current`` (the consumer name).
CONSUMER_GROUP: str = "vulnscan-workers"

# Status keys live in normal Redis (hash / string) so the API can read
# them from GET /tasks/{id} without XREAD'ing the stream. They are short
# TTL -- the canonical record lives in ES (vulnscan-tasks index).
STATUS_KEY_PREFIX: str = "vulnscan:queue:status:"
STATUS_TTL_SEC: int = 24 * 3600

# Cancellation tombstones prevent queued work from starting and let the
# running graph converge on a cancelled terminal state across API workers.
CANCEL_KEY_PREFIX: str = "vulnscan:queue:cancel:"
CANCEL_TTL_SEC: int = 24 * 3600

# Convenience: how deep the stream currently is (LLEN-style metric). The
# value is refreshed by ``stream_depth()`` on demand, not maintained as a
# separate counter (no atomicity guarantee with XADD).
DEPTH_KEY: str = "vulnscan:queue:depth"

# -- P3-A (需求②): 内网资产扫描队列 (agentless asset-scan 服务) -------------
# 与 vulnscan 完全独立的 Redis Stream / group / DLQ / 状态 / 取消键。
# 生产者 = gateway routers/asset_scan.py，消费者 = asset-scan 服务的
# TaskWorker(stream=...)。

STREAM_ASSET_TASKS: str = "assetscan:queue:tasks"
STREAM_ASSET_DLQ: str = "assetscan:queue:dlq"
ASSET_CONSUMER_GROUP: str = "asset-scan-workers"
ASSET_STATUS_KEY_PREFIX: str = "assetscan:queue:status:"
ASSET_CANCEL_KEY_PREFIX: str = "assetscan:queue:cancel:"
ASSET_DEPTH_KEY: str = "assetscan:queue:depth"


def asset_status_key(task_id: str) -> str:
    """Redis key for the short-lived status side-channel of an asset task."""
    return ASSET_STATUS_KEY_PREFIX + task_id


def asset_cancel_key(task_id: str) -> str:
    """Redis tombstone checked by asset-scan worker and graph nodes."""
    return ASSET_CANCEL_KEY_PREFIX + task_id


def status_key(task_id: str) -> str:
    """Redis key for the short-lived status side-channel of a task.

    Workers write ``{"status": "running", "worker": "..."}`` so the API can
    surface "running" / "queued" / "failed" without round-tripping to ES.
    """
    return STATUS_KEY_PREFIX + task_id


def cancel_key(task_id: str) -> str:
    """Redis tombstone checked by queue workers and graph nodes."""
    return CANCEL_KEY_PREFIX + task_id


def depth_key() -> str:
    """Alias kept for backwards-compat naming; matches DEPTH_KEY above."""
    return DEPTH_KEY
