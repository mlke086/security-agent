"""Async task queue built on Redis Streams (P2 of docs/架构改造设计.md).

The queue lets API workers ``POST /api/v1/vulnscan/tasks`` and immediately
return ``{task_id}`` while one or more background ``TaskWorker`` instances
consume the stream and run the vulnscan subgraph. Multiple uvicorn workers
join the same consumer group so the load spreads naturally and a crashed
worker hands its pending entries back via ``XAUTOCLAIM``.

Why not Celery / RabbitMQ / Kafka?  We already speak Redis for pub/sub
(``agent:cmd:*`` cross-worker routing) and as the LLM cache. Adding a
second broker for vulnscan alone would double the ops surface for no
benefit -- a stream consumer with a single in-process worker is enough for
the current scan throughput.
"""

from src.orchestration.task_queue.dequeue import (
    ack_message,
    claim_stale,
    pending_count,
    read_message_blocking,
    stream_depth,
)
from src.orchestration.task_queue.enqueue import (
    AssetScanEnvelope,
    TaskEnvelope,
    enqueue_asset_task,
    enqueue_task,
)
from src.orchestration.task_queue.keys import (
    CONSUMER_GROUP,
    STATUS_KEY_PREFIX,
    STREAM_ASSET_TASKS,
    STREAM_DLQ,
    STREAM_TASKS,
    asset_status_key,
    depth_key,
    status_key,
)

# 阶段 0-3:防御性 lazy 化——runner 和 worker 顶层 import 会拖入
# orchestration.subgraphs.vulnscan.graph(经 run_pipeline),间接拖 langgraph。
# gateway 镜像不该含 langgraph(方案改动点 7)。采用 PEP 562 模块级 __getattr__
# 按需加载:调用方显式 `from src.orchestration.task_queue import run_vulnscan_from_envelope`
# 时才触发 import。其他场景(仅 enqueue/dequeue/keys)零代价。
_LAZY_NAMES = {
    "run_vulnscan_from_envelope": "src.orchestration.task_queue.runner",
    "TaskWorker": "src.orchestration.task_queue.worker",
    "WorkerHandle": "src.orchestration.task_queue.worker",
}


def __getattr__(name: str):
    """PEP 562 lazy attribute loader for runner/worker symbols."""
    module_path = _LAZY_NAMES.get(name)
    if module_path is None:
        raise AttributeError(f"module 'src.orchestration.task_queue' has no attribute {name!r}")
    import importlib

    module = importlib.import_module(module_path)
    value = getattr(module, name)
    globals()[name] = value  # cache for subsequent access
    return value


def __dir__():
    """让 dir(task_queue) 能看到 lazy 属性,便于 IDE 自动补全。"""
    return sorted(set(__all__) | set(globals().keys()))


__all__ = [
    "STREAM_TASKS",
    "STREAM_DLQ",
    "CONSUMER_GROUP",
    "STATUS_KEY_PREFIX",
    "STREAM_ASSET_TASKS",
    "depth_key",
    "status_key",
    "asset_status_key",
    "TaskEnvelope",
    "AssetScanEnvelope",
    "enqueue_task",
    "enqueue_asset_task",
    "ack_message",
    "claim_stale",
    "pending_count",
    "stream_depth",
    "read_message_blocking",
    "TaskWorker",
    "WorkerHandle",
    "run_vulnscan_from_envelope",
]
