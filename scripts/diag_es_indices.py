"""诊断:事件索引里到底有什么,gateway 写入的 store 是哪个。"""
import asyncio
import os
import sys

sys.path.insert(0, "V:/project/security-agent")
os.environ["ES_URL"] = "http://192.168.80.101:9200"

from src.api.store_es import get_es_event_store


async def main() -> None:
    store = get_es_event_store()
    try:
        resp = await store._es.search(index=store._events_index, query={"match_all": {}}, size=5)
        print(f"events index '{store._events_index}' total:", resp["hits"]["total"]["value"])
        for h in resp["hits"]["hits"][:5]:
            s = h["_source"]
            print(" -", s.get("event_id"), "|", s.get("status"))
    except Exception as e:
        print("events index search err:", e)

    # 也看所有索引
    try:
        indices = await store._es.cat.indices(format="json")
        names = [i["index"] for i in indices if "security" in i["index"] or "event" in i["index"] or "alert" in i["index"]]
        print("related indices:", names)
    except Exception as e:
        print("indices err:", e)
    await store._es.close()


if __name__ == "__main__":
    asyncio.run(main())
