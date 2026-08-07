"""P6 release 端点实测(用 es 直接 index 文档做 seeding)。"""
import asyncio
import json
import os
import threading
import time
import urllib.error
import urllib.request

os.environ.setdefault("PG_PASSWORD", "Ke615700")
os.environ.setdefault("REDIS_URL", "redis://:redis_password_2026@192.168.80.101:6379/0")
os.environ.setdefault("NEO4J_PASSWORD", "neo4j_password_2026")

import redis.asyncio as aioredis
import uvicorn

from src.api.main import app


def seed_es_tasks_sync(tids_with_status):
    """直接用 ES client 写文档(create)。在已有 event loop 的脚本里直接 await。"""
    from elasticsearch import AsyncElasticsearch
    from src.common.config.settings import get_settings

    async def _do():
        s = get_settings()
        es = AsyncElasticsearch(hosts=[s.es_hosts])
        for tid, status in tids_with_status:
            doc = {
                "task_id": tid,
                "status": status,
                "source": "manual",
                "engine": "matcher",
                "targets": ["127.0.0.1"],
                "created_at": "2026-08-06T00:00:00",
            }
            await es.index(
                index="vulnscan-tasks",
                id=tid,
                document=doc,
                refresh=True,
            )
        await es.close()

    return _do()  # 返回 coroutine,调用方 await


async def main():
    suffix = int(time.time())
    tids_with_status = [
        (f"smoke-q-1-{suffix}", "queued"),
        (f"smoke-q-2-{suffix}", "queued"),
        (f"smoke-s-1-{suffix}", "scanning"),
        (f"smoke-c-1-{suffix}", "completed"),
    ]
    seed_coro = seed_es_tasks_sync(tids_with_status)
    await seed_coro
    tids = [tid for tid, _ in tids_with_status]
    print(f"[seed] ES tasks: {tids}")

    r = aioredis.from_url(
        "redis://:redis_password_2026@192.168.80.101:6379/0", decode_responses=True
    )
    for tid in tids[:2]:  # 2 queued 入 stream
        await r.xadd(
            "vulnscan:queue:tasks",
            {"task_id": tid, "envelope": json.dumps({"task_id": tid})},
        )
    await r.aclose()

    cfg = uvicorn.Config(app, host="127.0.0.1", port=18000, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(80):
        if server.started:
            break
        time.sleep(0.3)
    time.sleep(4)

    from src.api.auth.jwt import create_access_token

    token = create_access_token(
        data={"sub": "admin", "role": "admin"}, token_version=0
    )
    h = {"Authorization": f"Bearer {token}"}

    # batch release 包含 2 queued(应 released)+ 1 scanning(busy)+ 1 completed + 1 not_exist
    payload = {"task_ids": tids + ["nonexistent-id-xyz"]}
    print(f"[test] release-batch payload")
    req = urllib.request.Request(
        "http://127.0.0.1:18000/api/v1/vulnscan/tasks/release-batch",
        data=json.dumps(payload).encode(),
        headers={**h, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read())
            print(
                f"  summary: released={body['released']} failed={body['failed']} "
                f"busy={body['busy']} not_found={body['not_found']}"
            )
            for it in body["items"]:
                print(f"  - {it['task_id'][:25]}...: {it['status']}")
    except urllib.error.HTTPError as e:
        print(f"  err: {e.code} {e.read()[:200]}")

    # 单个 release scanning — 应 busy_scanning
    print(f"[test] release single scanning (expected busy_scanning)")
    req = urllib.request.Request(
        f"http://127.0.0.1:18000/api/v1/vulnscan/tasks/release?task_id={tids[2]}",
        headers=h,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"  status: {r.status} body: {r.read()[:200]}")
    except urllib.error.HTTPError as e:
        print(f"  err: {e.code} {e.read()[:200]}")

    # verify
    from src.agents.store import get_vulnscan_store

    store = get_vulnscan_store()
    for tid in tids:
        t = await store.get_task(tid)
        print(f"[verify] {tid[:25]}... ES status: {t.status if t else 'NOT FOUND'}")

    r2 = aioredis.from_url(
        "redis://:redis_password_2026@192.168.80.101:6379/0", decode_responses=True
    )
    for tid in tids[:2]:
        entries = await r2.xrange("vulnscan:queue:tasks", count=500)
        found = [eid for eid, f in entries if f.get("task_id") == tid]
        print(f"[verify] {tid[:25]}... in stream: {bool(found)} (expected False)")
    await r2.aclose()

    server.should_exit = True
    t.join(timeout=3)
    print("done")


asyncio.run(main())