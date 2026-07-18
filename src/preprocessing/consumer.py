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

# Pipeline concurrency semaphore (module-level, shared across consumer runs)
_pipeline_sem: asyncio.Semaphore | None = None


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
                stable_event_id = self._stable_event_id(msg.value)
            except Exception:
                stable_event_id = None
            try:
                structured = self._process(msg.value, event_id=stable_event_id)
            except Exception as exc:
                logger.error("parse_failed", error=str(exc), offset=msg.offset)
                await self._send_dlq(msg.value, str(exc))
                await self._consumer.commit()
                continue

            try:
                await self._emit(structured)
                await self._consumer.commit()
            except Exception as exc:
                logger.error(
                    "pipeline_failed",
                    event_id=structured.get("event_id"), error=str(exc),
                )
                # Do not commit -- Kafka re-delivers for retry.


    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _stable_event_id(raw: str) -> str:
        """Deterministic event_id from the raw Kafka payload.

        If the payload is JSON with an ``id`` / ``event_id`` / ``alert_id`` field we
        use it directly (most alert sources include a unique id). Otherwise we
        sha256 the sanitized payload so re-deliveries hash to the same id.
        """
        try:
            obj = json.loads(raw)
            for key in ("id", "event_id", "alert_id", "uuid"):
                val = obj.get(key)
                if isinstance(val, str) and val:
                    return val
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
        """Submit event to the LangGraph pipeline with concurrency control."""
        global _pipeline_sem
        if _pipeline_sem is None:
            _pipeline_sem = asyncio.Semaphore(get_settings().pipeline_concurrency)

        from src.orchestration.runner import run_pipeline
        async with _pipeline_sem:
            await run_pipeline(
                event["event_id"],
                event["sanitized_text"],
                event["iocs"],
                event.get("source", "kafka"),
            )

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
