"""完整 vulnscan e2e:gateway POST 入队 → scan-engine 消费 → events 推。

- gateway + scan-engine + graphrag + ai 4 服务实启动
- 走完 POST /api/v1/vulnscan/tasks (admin JWT)
- 查 Redis stream 是否有新 entry
- 查 ES(若可达) 是否有 task 记录
"""
import asyncio
import json
import os
import threading
import time
import urllib.error
import urllib.request

os.environ["PG_PASSWORD"] = "Ke615700"
os.environ["REDIS_URL"] = "redis://:redis_password_2026@192.168.80.101:6379/0"
os.environ["NEO4J_PASSWORD"] = "neo4j_password_2026"
os.environ["AI_BASE_URL"] = "http://127.0.0.1:18001"
os.environ["GRAPHRAG_BASE_URL"] = "http://127.0.0.1:18002"

import uvicorn
from src.api.auth.jwt import create_access_token
from src.api.main import app as gw_app
from src.scan_engine.main import app as se_app


def boot(app, port, label):
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True, name=label)
    t.start()
    for _ in range(80):
        if server.started:
            break
        time.sleep(0.3)
    return server, t


def http_post(url, body, headers=None, timeout=15):
    h = {"Content-Type": "application/json", **(headers or {})}
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:
        return 0, str(e)


def http_get(url, headers=None, timeout=10):
    h = headers or {}
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:
        return 0, str(e)


async def main():
    print("=" * 60)
    gw, gt = boot(gw_app, 18000, "gw")
    se, st = boot(se_app, 18003, "se")
    time.sleep(4)

    token = create_access_token(data={"sub": "admin", "role": "admin"}, token_version=0)
    h = {"Authorization": f"Bearer {token}"}

    # 1. POST /vulnscan/tasks
    print("[1] POST /api/v1/vulnscan/tasks")
    s, b = http_post(
        "http://127.0.0.1:18000/api/v1/vulnscan/tasks",
        {"source": "manual", "targets": ["127.0.0.1"], "intent_text": "smoke test", "engine": "matcher"},
        headers=h,
    )
    print(f"    {s} {b}")
    task_id = b.get("task_id") if isinstance(b, dict) else None
    if not task_id:
        print("FAIL: no task_id returned")
        return

    # 2. 查 Redis stream
    print(f"[2] check Redis stream for task_id={task_id[:8]}...")
    import redis.asyncio as aioredis
    r = aioredis.from_url("redis://:redis_password_2026@192.168.80.101:6379/0", decode_responses=True)
    pre_xlen = await r.xlen("vulnscan:queue:tasks")
    print(f"    vulnscan:queue:tasks xlen={pre_xlen}")
    # 查 group lag
    info = await r.xinfo_groups("vulnscan:queue:tasks")
    print(f"    groups[0] lag={info[0].get('lag', 'n/a')}")
    await r.aclose()

    # 3. 查 ES task 记录
    print("[3] GET /api/v1/vulnscan/tasks/<id>")
    s, b = http_get(f"http://127.0.0.1:18000/api/v1/vulnscan/tasks/{task_id}", headers=h)
    print(f"    {s} body_keys={list(b.keys()) if isinstance(b, dict) else type(b).__name__}")
    if isinstance(b, dict):
        print(f"    status={b.get('status')} engine={b.get('engine')}")

    # 4. 查 events:tasks 流(用 events 消费者路径)
    print("[4] enqueue events:tasks e2e test event")
    r2 = aioredis.from_url("redis://:redis_password_2026@192.168.80.101:6379/0", decode_responses=True)
    eid = f"e2e-events-{int(time.time())}"
    entry = await r2.xadd(
        "events:tasks",
        {
            "event_id": eid,
            "body": json.dumps(
                {
                    "event_id": eid,
                    "sanitized_text": f"smoke event for {task_id[:8]}",
                    "iocs": {"ips": ["1.2.3.4"]},
                    "source": "e2e_smoke",
                }
            ),
        },
    )
    print(f"    xadd entry={entry}")
    time.sleep(4)
    # 等消费者处理
    pending = await r2.xpending("events:tasks", "scan-engine-events")
    print(f"    xpending: {pending}")
    xlen2 = await r2.xlen("events:tasks")
    print(f"    xlen after wait: {xlen2}")
    await r2.aclose()

    gw.should_exit = True
    se.should_exit = True
    gt.join(timeout=3)
    st.join(timeout=3)
    print("done")


if __name__ == "__main__":
    asyncio.run(main())