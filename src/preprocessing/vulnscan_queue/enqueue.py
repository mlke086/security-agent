"""阶段 4-2:EDR 事件入队实现。

preprocessing 镜像消费 Kafka 原始告警,完成 sanitize + IOC 抽取后,
通过本模块调 ``enqueue_event`` 推入 Redis Stream ``events:tasks``。
scan-engine 镜像启动 consumer loop 监听同一 stream 触发 LangGraph 流水线。

依赖:仅 redis + common.config + common.logging(无 langgraph / orchestration / execution)。
体积:preprocessing 镜像只增加 aiokafka + redis(共 ~80MB),不拖 langgraph。
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.preprocessing.vulnscan_queue.keys import (
    EVENT_CONSUMER_NAME_PREFIX,
    EVENT_STREAM,
)

logger = get_logger(__name__)


async def enqueue_event(*, event_id: str, payload: dict[str, Any]) -> str:
    """阶段 4-2:推 EDR 事件到 Redis Stream ``events:tasks``。

    返回 XADD 分配的 stream entry id(形如 ``1234-0``),用于排查。
    失败抛异常由 caller 决定不 commit Kafka offset,触发重投递。
    """
    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        # payload 完整序列化进 stream,scan-engine 反序列化即可。
        # 时间戳由入队方补齐(不依赖 caller 必须带)。
        body = dict(payload)
        body.setdefault("event_id", event_id)
        body.setdefault("enqueued_at", datetime.now(UTC).isoformat())
        # XADD payload 字段值必须是 str/bytes。
        # cast: redis-py 的 XADD 类型签名对 dict value 要求 str/bytes,实际接受更多类型,
        # 这里 widen 仅为了让 mypy 不报。
        xadd_payload: dict[str, str] = {
            "event_id": event_id,
            "body": json.dumps(body, ensure_ascii=False),
        }
        entry_id = await redis.xadd(
            EVENT_STREAM,
            cast(dict, xadd_payload),
            maxlen=10_000,
            approximate=True,
        )
        logger.info(
            "event_enqueued",
            event_id=event_id,
            stream=EVENT_STREAM,
            entry_id=entry_id,
        )
        return entry_id
    finally:
        await redis.aclose()


async def ensure_event_consumer_group() -> None:
    """scan-engine 启动时调用,确保消费者组存在(幂等)。

    使用 XGROUP CREATE MKSTREAM,stream 不存在时自动创建。
    """
    import socket

    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        # 函数内 lazy import 让 enqueue_event 单调用方(enqueue_task 不依赖此常量)
        from src.preprocessing.vulnscan_queue.keys import EVENT_CONSUMER_GROUP

        try:
            await redis.xgroup_create(
                name=EVENT_STREAM,
                groupname=EVENT_CONSUMER_GROUP,
                id="$",  # 只消费启动后新事件
                mkstream=True,
            )
        except aioredis.ResponseError as exc:
            # BUSYGROUP Consumer Group name already exists -> 幂等
            if "BUSYGROUP" not in str(exc):
                raise
        consumer_name = f"{EVENT_CONSUMER_NAME_PREFIX}{socket.gethostname()}-{id(redis)}"
        logger.info(
            "event_consumer_group_ready",
            stream=EVENT_STREAM,
            group=EVENT_CONSUMER_GROUP,
            consumer=consumer_name,
        )
        return consumer_name
    finally:
        await redis.aclose()
