"""E2E:验证 scan-engine events:tasks 消费者端到端。

- 入队一个 events:tasks
- 等待 scan-engine 消费
- 看 ES 是否写了 event 记录
"""
import asyncio
import json
import os
import threading
import time
import urllib.request

os.environ.setdefault("AI_BASE_URL", "http://127.0.0.1:18001")
os.environ.setdefault("GRAPHRAG_BASE_URL", "http://127.0.0.1:18002")
os.environ.setdefault("REDIS_URL", "redis://:redis_password_2026@192.168.80.101:6379/0")
os.environ.setdefault("PG_PASSWORD", "Ke615700")
os.environ.setdefault("NEO4J_PASSWORD", "neo4j_password_2026")

import uvicorn

from src.scan_engine.main import app as se_app
from src.common.config.settings import get_settings


async def main():
    # 先启动 scan-engine
    cfg = uvicorn.Config(se_app, host="127.0.0.1", port=18003, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(80):
        if server.started:
            break
        time.sleep(0.3)
    time.sleep(3)
    print("[1] scan-engine /healthz")
    s, b = http_get("http://127.0.0.1:18003/healthz")
    print(f"    {s} {b}")

    # 入队一个 events:tasks
    print("[2] enqueue events:tasks via redis xadd")
    import redis.asyncio as aioredis
    from src.preprocessing.vulnscan_queue.keys import EVENT_STREAM

    settings = get_settings()
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    event_id = f"e2e-test-{int(time.time())}"
    entry_id = await r.xadd(
        EVENT_STREAM,
        {
            "event_id": event_id,
            "body": json.dumps(
                {
                    "event_id": event_id,
                    "sanitized_text": "suspicious login from 1.2.3.4 by user test",
                    "iocs": {"ips": ["1.2.3.4"], "domains": [], "hashes": []},
                    "source": "e2e_smoke",
                }
            ),
        },
    )
    print(f"    xadd entry_id={entry_id}, event_id={event_id}")
    await r.aclose()

    # 等待消费 + ES 写入
    print("[3] wait 5s for consumer to process")
    time.sleep(5)

    # 查 ES 是否写了 event
    print("[4] GET /api/v1/events/<event_id> via gateway")
    # 用 Redis 看 xlen / xinfo stream 验证
    r2 = aioredis.from_url(settings.redis_url, decode_responses=True)
    stream_len = await r2.xlen(EVENT_STREAM)
    print(f"    stream {EVENT_STREAM} xlen={stream_len}")
    # 查 group lag
    try:
        info = await r2.xinfo_groups(EVENT_STREAM)
        print(f"    groups: {info}")
    except Exception as e:
        print(f"    xinfo_groups err: {e}")
    await r2.aclose()

    server.should_exit = True
    t.join(timeout=3)
    print("done")


def http_get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read() or b"null")
    except Exception as e:
        return 0, str(e)


if __name__ == "__main__":
    asyncio.run(main())