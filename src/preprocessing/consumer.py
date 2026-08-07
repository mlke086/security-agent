import asyncio
import json
import uuid
from datetime import UTC, datetime

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaError

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.preprocessing.ioc_extractor.extractor import IOCExtractor
from src.preprocessing.sanitization.engine import SanitizationEngine

logger = get_logger(__name__)


class AlertConsumer:
    """Async Kafka consumer: sanitize → extract IOCs → emit structured JSON."""

    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._sanitizer = SanitizationEngine()
        self._extractor = IOCExtractor()
        self._consumer: AIOKafkaConsumer | None = None
        self._dlq_producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        s = self._settings
        self._consumer = AIOKafkaConsumer(
            s.kafka_topic_raw_alerts,
            bootstrap_servers=s.kafka_bootstrap_servers,
            group_id=s.kafka_consumer_group,
            value_deserializer=lambda b: b.decode("utf-8"),
            max_poll_records=500,
            enable_auto_commit=False,
        )
        self._dlq_producer = AIOKafkaProducer(
            bootstrap_servers=s.kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        await self._consumer.start()
        await self._dlq_producer.start()
        logger.info("consumer_started", topic=s.kafka_topic_raw_alerts)

    async def stop(self) -> None:
        if self._consumer:
            await self._consumer.stop()
        if self._dlq_producer:
            await self._dlq_producer.stop()

    async def run(self) -> None:
        """Consume raw alerts, sanitize, emit into the pipeline, commit offsets.

        P1-PRE-1: derive a stable event_id from the Kafka payload so redeliveries
        do not change the downstream action idempotency key (op_id).
        """
        assert self._consumer is not None
        async for msg in self._consumer:
            stable_event_id: str | None = None
            try:
                stable_event_id = self._stable_event_id(
                    msg.value, source=self._settings.kafka_topic_raw_alerts
                )
            except Exception:
                stable_event_id = None
            try:
                structured = self._process(msg.value, event_id=stable_event_id)
            except Exception as exc:
                logger.error("parse_failed", error=str(exc), offset=msg.offset)
                if await self._send_dlq(msg.value, str(exc)):
                    # DLQ durable -- safe to commit so we don't re-deliver.
                    await self._consumer.commit()
                else:
                    # DLQ write failed -- DO NOT commit. Kafka will redeliver
                    # after the next session timeout so we get another shot.
                    logger.warning(
                        "parse_dlq_skipped_commit",
                        offset=msg.offset,
                        note="Kafka will redeliver this offset",
                    )
                continue

            try:
                await self._emit(structured)
                await self._consumer.commit()
            except Exception as exc:
                logger.error(
                    "pipeline_failed",
                    event_id=structured.get("event_id"),
                    error=str(exc),
                )
                # Do not commit -- Kafka re-delivers for retry.

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _stable_event_id(raw: str, source: str = "kafka") -> str:
        """Deterministic event_id from the raw Kafka payload.

        If the payload is JSON with an ``id`` / ``event_id`` / ``alert_id`` field we
        use it prefixed with the source -- otherwise two sources that happen to
        share the same id (e.g. auto-increment ids) would collide on the events
        table primary key and wedge the consumer (V13 P0-1). Otherwise we sha256
        the sanitized payload so re-deliveries hash to the same id.
        """
        try:
            obj = json.loads(raw)
            for key in ("id", "event_id", "alert_id", "uuid"):
                val = obj.get(key)
                if isinstance(val, str) and val:
                    return f"{source}:{val}"
        except Exception:
            pass
        import hashlib

        return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def _process(self, raw: str, event_id: str | None = None) -> dict:
        sanitized = self._sanitizer.sanitize(raw)
        iocs = self._extractor.extract(sanitized)
        return {
            "event_id": event_id or str(uuid.uuid4()),
            "sanitized_text": sanitized,
            "iocs": {
                "ips": iocs.ips,
                "domains": iocs.domains,
                "hashes": iocs.hashes,
                "urls": iocs.urls,
            },
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "kafka",
        }

    async def _emit(self, event: dict) -> None:
        """阶段 4-2 拆分:将事件推入 Redis Stream ``events:tasks``,由 scan-engine 消费。

        原实现直接调 ``src.orchestration.runner.run_pipeline``(包含 LangGraph 子图),
        会让 preprocessing 镜像必须 COPY orchestration/ 全包(包括 langgraph + execution/)。
        改为 Redis Stream 入队后:

        - preprocessing 镜像只依赖 aiokafka + redis(无 langgraph),体积 ~80MB
        - scan-engine 镜像负责 LangGraph 流水线执行(单服务单职责)
        - 并发控制由 scan-engine TaskWorker 的 concurrency 配置决定

        入队失败抛异常,由 caller (run) 决定不 commit offset,触发 Kafka 重投递。
        """
        # 阶段 4-2:独立裁剪版 task_queue 包,只依赖 redis(PEP 562 lazy 化后
        # gateway 携带同包时不拖 langgraph)。preprocessing 镜像 COPY 此包即可。
        from src.preprocessing.vulnscan_queue.enqueue import (
            EVENT_STREAM,
            enqueue_event,
        )

        # 事件 ID 由调用方在 _process 时生成(sha256/raw id)
        event_id = event["event_id"]
        # enqueue_event 内部用 Redis Stream XADD + 简洁 payload
        await enqueue_event(
            event_id=event_id,
            payload={
                "event_id": event_id,
                "sanitized_text": event.get("sanitized_text", ""),
                "iocs": event.get("iocs", {}),
                "source": event.get("source", "kafka"),
                "ts": event.get("timestamp", datetime.now(UTC).isoformat()),
            },
        )
        logger.info(
            "preprocessing_event_emitted",
            event_id=event_id,
            stream=EVENT_STREAM,
        )

    async def _send_dlq(self, raw: str, error: str) -> bool:
        """Push the poison-pill alert onto the DLQ topic. Returns True if the
        broker acknowledged the write (so the caller can safely commit the
        original offset); False on transport failure -- the caller MUST NOT
        commit so Kafka redelivers later.

        P1-PRE-01 (2026-07-19): aiokafka producer.send() returns a Future;
        awaiting it once resolves to RecordMetadata (broker ack). The
        previous version used no return value and committed unconditionally,
        so a broker hiccup between in-memory buffer and flush silently
        dropped alerts.
        """
        assert self._dlq_producer is not None
        try:
            await self._dlq_producer.send(
                self._settings.kafka_topic_dlq,
                value={"raw": raw, "error": error, "ts": datetime.now(UTC).isoformat()},
            )
            return True
        except KafkaError as exc:
            logger.error("dlq_send_failed", error=str(exc))
            return False


async def run_consumer() -> None:
    consumer = AlertConsumer()
    await consumer.start()
    try:
        await consumer.run()
    finally:
        await consumer.stop()


if __name__ == "__main__":
    asyncio.run(run_consumer())
