"""诊断:事件数据在 PG 还是 ES,gateway 与 scan-engine 的 store_backend 一致性。"""
import asyncio
import json

import asyncpg


async def main() -> None:
    conn = await asyncpg.connect(
        host="192.168.80.101", port=5432, user="secagent", password="Ke615700", database="SecAgent"
    )
    try:
        tables = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE '%event%'"
        )
        print("event tables:", [t["tablename"] for t in tables])
        try:
            row = await conn.fetchrow(
                "SELECT event_id, data FROM events WHERE event_id='7679e9e7-545f-4933-a509-ca0fbed1c93d'"
            )
            if row:
                d = row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
                print("PG event FOUND | status:", d.get("status"), "| trace:", len(d.get("trace", [])))
            else:
                print("PG event NOT found")
        except Exception as e:
            print("PG event query err:", e)
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
