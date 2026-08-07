"""P2 验证:release stream 清理翻页逻辑(真实 Redis)。"""
import asyncio

import redis.asyncio as aioredis

from src.orchestration.task_queue.keys import STREAM_TASKS

REDIS_URL = "redis://:redis_password_2026@192.168.80.101:6379/0"


async def main() -> None:
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await r.delete(STREAM_TASKS)
        await r.xadd(STREAM_TASKS, {"task_id": "p2-target-task"})
        for i in range(600):
            await r.xadd(STREAM_TASKS, {"task_id": f"other-{i}"})
        print("xlen:", await r.xlen(STREAM_TASKS))

        # 与 task_monitor release 相同的翻页查找逻辑
        target_entries: list[str] = []
        cursor: str | None = None
        pages = 0
        while pages < 20:
            if cursor is None:
                entries = await r.xrevrange(STREAM_TASKS, count=500)
            else:
                entries = await r.xrevrange(STREAM_TASKS, max=f"({cursor}", count=500)
            if not entries:
                break
            for eid, fields in entries:
                if fields.get("task_id") == "p2-target-task":
                    target_entries.append(eid)
            cursor = entries[-1][0]
            pages += 1
            if len(entries) < 500:
                break
        print("pages:", pages, "found:", target_entries)
        assert len(target_entries) == 1, "target entry should be found (old impl would miss it)"

        for eid in target_entries:
            await r.xdel(STREAM_TASKS, eid)
        print("after xlen:", await r.xlen(STREAM_TASKS))
        remaining = [f for _, f in await r.xrevrange(STREAM_TASKS, count=601)]
        print("target gone:", not any(f.get("task_id") == "p2-target-task" for f in remaining))
        assert not any(f.get("task_id") == "p2-target-task" for f in remaining)
        print("P2 VERIFY OK")
    finally:
        await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())
