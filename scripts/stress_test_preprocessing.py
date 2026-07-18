"""S2-2: Preprocessing stress test — Kafka injection + throughput benchmark.

Usage:
    python scripts/stress_test_preprocessing.py              # Quick test (100 events)
    python scripts/stress_test_preprocessing.py --count 2000 # Full benchmark

Requires:
    - Kafka broker at 192.168.80.101:9092 (from .env)
    - Redis at 192.168.80.101:6379
"""

import asyncio
import json
import time
import sys
import uuid
from datetime import UTC, datetime

from aiokafka import AIOKafkaProducer

from src.common.config.settings import get_settings
from src.common.logging.logger import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

_SAMPLE_EVENTS = [
    {
        "sanitized_text": "Honeypot captured whoami from 45.33.32.156 on external interface",
        "iocs": {"ip": ["45.33.32.156"], "command": ["whoami"]},
        "source": "honeypot",
    },
    {
        "sanitized_text": "CVE-2024-1234 exploit attempt on prod-api-01 from 10.0.0.5",
        "iocs": {"ip": ["10.0.0.5"], "cve": ["CVE-2024-1234"]},
        "source": "waf",
    },
    {
        "sanitized_text": "Port scan from 203.0.113.5: ports 22,80,443,3306,8080",
        "iocs": {"ip": ["203.0.113.5"]},
        "source": "ids",
        "noise_score": 0.9,
    },
    {
        "sanitized_text": "Failed SSH login root@admin from 198.51.100.20 at 2026-07-10T10:00:00Z",
        "iocs": {"ip": ["198.51.100.20"]},
        "source": "ssh_server",
    },
    {
        "sanitized_text": "Malware sample detected: SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "iocs": {"hash": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},
        "source": "av",
    },
]


async def produce_events(count: int, batch_size: int = 100) -> float:
    """Produce events to Kafka and measure throughput."""
    settings = get_settings()
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        compression_type="snappy",
        linger_ms=10,
        batch_size=65536,
    )
    await producer.start()

    start = time.monotonic()
    sent = 0
    try:
        for i in range(0, count, batch_size):
            batch_start = time.monotonic()
            batch = []
            for j in range(batch_size):
                idx = (i + j) % len(_SAMPLE_EVENTS)
                event = dict(_SAMPLE_EVENTS[idx])
                event["event_id"] = str(uuid.uuid4())
                event["ts"] = datetime.now(UTC).isoformat()
                batch.append(event)

            for event in batch:
                await producer.send(
                    settings.kafka_topic_raw_alerts,
                    json.dumps(event).encode("utf-8"),
                )

            await producer.flush()
            sent += len(batch)
            elapsed = time.monotonic() - batch_start
            rate = len(batch) / elapsed if elapsed > 0 else 0
            logger.info("batch_sent", batch=i // batch_size, count=len(batch), rate=f"{rate:.0f} events/s")

    finally:
        await producer.stop()

    total_elapsed = time.monotonic() - start
    throughput = sent / total_elapsed if total_elapsed > 0 else 0
    return throughput


async def main() -> None:
    count = 100
    if "--count" in sys.argv:
        idx = sys.argv.index("--count")
        count = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 100

    print(f"=== Preprocessing Stress Test ===")
    print(f"Target: {count} events @ 192.168.80.101:9092")
    print(f"Rate target: >=2000 events/s, P99<50ms")
    print()

    throughput = await produce_events(count)

    print(f"\nResults:")
    print(f"  Throughput: {throughput:.0f} events/s")
    print(f"  Target:    >=2000 events/s")
    if throughput >= 2000:
        print(f"  ✅ PASSED")
    else:
        print(f"  ❌ FAILED (increase batch_size or check Kafka latency)")


if __name__ == "__main__":
    asyncio.run(main())
    print("Done.")
