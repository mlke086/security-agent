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
from src.orchestration.task_queue.enqueue import TaskEnvelope, enqueue_task
from src.orchestration.task_queue.keys import (
    CONSUMER_GROUP,
    STATUS_KEY_PREFIX,
    STREAM_DLQ,
    STREAM_TASKS,
    depth_key,
    status_key,
)
from src.orchestration.task_queue.runner import run_vulnscan_from_envelope
from src.orchestration.task_queue.worker import TaskWorker, WorkerHandle

__all__ = [
    "STREAM_TASKS",
    "STREAM_DLQ",
    "CONSUMER_GROUP",
    "STATUS_KEY_PREFIX",
    "depth_key",
    "status_key",
    "TaskEnvelope",
    "enqueue_task",
    "ack_message",
    "claim_stale",
    "pending_count",
    "stream_depth",
    "read_message_blocking",
    "TaskWorker",
    "WorkerHandle",
    "run_vulnscan_from_envelope",
]
