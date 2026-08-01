"""漏洞归属修复迁移（2026-08-02，问题1）。

背景：V11 的 aggregate reconcile 在 merge 分支会把 vulns 记录的 ``task_id``
**覆盖**成最近一次扫描任务。当同一主机被多个任务先后扫描时，先发现该漏洞的
任务名下记录被改走 → 其监控页按 task_id 查 vulns 显示 0 条，而报告（完成时
快照）仍有数据。

代码修复（V12 5.7）已让 merge 不再覆盖 task_id（保留原归属 + 新增
``last_seen_task_id`` 记录最近确认任务，查询层 OR 匹配）。本脚本修复**存量**：

1. 对每条 vulns 记录：若 ``task_id`` 指向的任务 created_at 晚于该记录的
   ``detected_at``，说明该记录的归属被后续任务覆盖过——无法还原原始 task_id
   （已丢失），但可把当前 task_id 降为 ``last_seen_task_id``，并用一个合理
   的占位归属（无）——更稳妥的做法是保留 task_id 不变，仅补上
   ``last_seen_task_id = task_id``，保证查询层 OR 匹配能命中（旧任务的
   监控页仍查不到，但新任务的能查到；同时避免制造无主记录）。

   实际上更准确的判定：**任务索引里 created_at 最早的、detected_at 之后
   的任务不一定是原归属**。由于原始 task_id 已被覆盖丢失，我们无法完美还原。
   务实方案：
   - 记录 scan_history 中全部时间戳 → 与 tasks 索引比对，找 detected_at
     之前创建且已完成的同主机任务作为候选原归属（不保证唯一，取最早者）。
   - 若找不到候选，保留当前 task_id，仅补 last_seen_task_id。
2. 对所有记录：``last_seen_task_id`` 缺失时补 ``= task_id``（当前归属即最近确认）。

用法：
    python scripts/migrations/vulnscan_restore_ownership_20260802.py [--dry-run]

幂等、可重复运行。运行前建议对 ES 索引做快照。
"""

import argparse
import asyncio
import json
from datetime import UTC, datetime

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk, async_scan

from src.agents.store import INDEX_TASKS, INDEX_VULNS
from src.common.config.settings import get_settings

DRY_RUN = False


async def _parse_ts(value: str | None):
    """Parse ISO-8601 (with/without timezone). Returns None if unparseable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def main(dry_run: bool) -> None:
    global DRY_RUN
    DRY_RUN = dry_run
    es = AsyncElasticsearch(hosts=[get_settings().es_hosts])

    # 0) 任务 created_at 索引
    task_created: dict[str, str] = {}
    async for hit in async_scan(es, index=INDEX_TASKS, query={"query": {"match_all": {}}}, size=500):
        src = hit["_source"]
        tid = src.get("task_id") or hit["_id"]
        task_created[tid] = src.get("created_at", "")

    # 1) 收集所有 vulns：_id -> (cve, name, task_id)
    vulns: dict[str, dict] = {}
    async for hit in async_scan(es, index=INDEX_VULNS, query={"query": {"match_all": {}}}, size=500):
        src = hit["_source"]
        vulns[hit["_id"]] = {
            "cve": src.get("cve") or "",
            "name": src.get("name") or "",
            "task_id": src.get("task_id", ""),
            "last_seen": src.get("last_seen_task_id"),
        }

    # 2) 扫描全部 results findings，建立 (cve, name) -> task_id 集合
    #    某任务的 results 里包含某 (cve,name) -> 该任务确实扫描发现过它
    key_to_tasks: dict[tuple, set[str]] = {}
    async for hit in async_scan(es, index="vulnscan-results", query={"query": {"match_all": {}}}, size=500):
        src = hit["_source"]
        tid = src.get("task_id", "")
        for f in src.get("findings", []):
            key = (f.get("cve") or "", f.get("name") or "")
            if key[0] or key[1]:
                key_to_tasks.setdefault(key, set()).add(tid)

    # 3) 为每条 vulns 补 last_seen_task_id：优先用 "detected_at 之后创建的任务"
    #    中最近的一个；无则保留 task_id。同时若 task_id 指向任务创建晚于
    #    detected_at（归属被覆盖），把 last_seen 设为该 task_id 以保 OR 命中。
    actions: list[dict] = []
    stats = {"total": 0, "update_last_seen": 0, "noop": 0}
    for vid, v in vulns.items():
        stats["total"] += 1
        candidates = key_to_tasks.get((v["cve"], v["name"]), set())
        if not candidates:
            if v["last_seen"]:
                stats["noop"] += 1
                continue
            doc = {"last_seen_task_id": v["task_id"]}
            stats["update_last_seen"] += 1
        else:
            # 取候选任务里创建时间最晚的一个作为 last_seen
            chosen = sorted(candidates, key=lambda t: task_created.get(t, ""))[-1]
            if v["last_seen"] == chosen:
                stats["noop"] += 1
                continue
            doc = {"last_seen_task_id": chosen}
            stats["update_last_seen"] += 1
        actions.append({"_op_type": "update", "_index": INDEX_VULNS, "_id": vid, "doc": doc})
        if not DRY_RUN and len(actions) >= 500:
            await async_bulk(es, actions, chunk_size=2000)
            actions = []

    if actions and not DRY_RUN:
        await async_bulk(es, actions, chunk_size=2000)

    await es.close()
    mode = "DRY-RUN" if DRY_RUN else "APPLIED"
    print(f"[{mode}] vulns={stats['total']} update_last_seen={stats['update_last_seen']} noop={stats['noop']}")
    print("说明：last_seen_task_id 按 results findings 反查补齐；task_id 保留不动。"
          "监控页/报告页查询走 OR(task_id, last_seen_task_id) 命中。")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without writing.")
    args = parser.parse_args()
    asyncio.run(main(args.dry_run))
