"""Unit tests for the Redis key/stream naming helpers."""
from __future__ import annotations

from src.orchestration.task_queue import keys
from src.orchestration.task_queue.keys import (
    CONSUMER_GROUP,
    DEPTH_KEY,
    STREAM_DLQ,
    STREAM_TASKS,
    depth_key,
    status_key,
)


def test_stream_names_are_stable():
    """Renaming a stream breaks every deployed worker. Lock these strings."""
    assert STREAM_TASKS == "vulnscan:queue:tasks"
    assert STREAM_DLQ == "vulnscan:queue:dlq"
    assert CONSUMER_GROUP == "vulnscan-workers"


def test_status_key_prefixes_correctly():
    assert status_key("abc-123") == "vulnscan:queue:status:abc-123"
    assert status_key("") == "vulnscan:queue:status:"


def test_depth_key_alias_matches_constant():
    """depth_key() is the public helper; DEPTH_KEY is the raw constant.
    Keep them in sync so operators only need to grep one string."""
    assert depth_key() == DEPTH_KEY
    assert DEPTH_KEY == keys.DEPTH_KEY
