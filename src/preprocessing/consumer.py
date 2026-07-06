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
        assert self._consumer is not None
        async for msg in self._consumer:
            try:
                structured = self._process(msg.value)
                await self._emit(structured)
                await self._consumer.commit()
            except Exception as exc:
                logger.error("message_processing_failed", error=str(exc), offset=msg.offset)
                await self._send_dlq(msg.value, str(exc))
                await self._consumer.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process(self, raw: str) -> dict:
        sanitized = self._sanitizer.sanitize(raw)
        iocs = self._extractor.extract(sanitized)
        return {
            "event_id": str(uuid.uuid4()),
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
        # Hook point: downstream graph ingestion
        logger.info("event_processed", event_id=event["event_id"])

    async def _send_dlq(self, raw: str, error: str) -> None:
        assert self._dlq_producer is not None
        try:
            await self._dlq_producer.send(
                self._settings.kafka_topic_dlq,
                value={"raw": raw, "error": error, "ts": datetime.now(UTC).isoformat()},
            )
        except KafkaError as exc:
            logger.error("dlq_send_failed", error=str(exc))


async def run_consumer() -> None:
    consumer = AlertConsumer()
    await consumer.start()
    try:
        await consumer.run()
    finally:
        await consumer.stop()


if __name__ == "__main__":
    asyncio.run(run_consumer())
