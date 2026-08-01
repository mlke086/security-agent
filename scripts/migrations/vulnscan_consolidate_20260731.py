"""漏洞清单整理 — 存量数据归并迁移脚本（2026-07-31 UX upgrade 一次性迁移）。

对 ES `vulnscan-vulns` 里的历史重复记录做"去重 + 补历史扫描时间"：

* 按身份键 (agent_id, cve or "", name) 分组（与 aggregate 节点的归并键一致）；
* 每组保留 detected_at 最新的一条为 canonical，其余各条的 detected_at 并入
  canonical 的 `scan_history`（升序、去重）；
* 删除其余各条。

它**故意不做**追溯性"已修复"标记：旧扫描结果（vulnscan-results）没有
`scanned_categories`，无法证明某次完整扫描覆盖了某类别且未发现该漏洞，追溯
判定会误判。修正时点放在下次真实扫描（升级后的 agent 上报类别覆盖后自动修复
自然补齐）。

幂等、可重复运行。用 `--dry-run` 预览而不改动数据。运行前建议对 ES 索引做快照。

用法：
    python _migrate_consolidate_vulns.py [--dry-run]
"""

import argparse
import asyncio
import json
from collections import defaultdict
from datetime import datetime

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk, async_scan

from src.agents.store import INDEX_VULNS, detected_sort_key
from src.common.config.settings import get_settings


def _ts_key(value: str):
    """Sort key for detection timestamps (shared with aggregate node)."""
    return detected_sort_key(value)


async def main(dry_run: bool) -> None:
    settings = get_settings()
    es = AsyncElasticsearch(hosts=[settings.es_hosts])
    try:
        if not dry_run:
            # Ensure the scan_history field is mapped (idempotent; dynamic
            # mapping would also cover it on first write, this just makes it
            # explicit). Skipped in dry-run so preview stays read-only.
            try:
                await es.indices.put_mapping(
                    index=INDEX_VULNS,
                    properties={"scan_history": {"type": "date"}},
                )
                print(f"put_mapping: scan_history ensured on {INDEX_VULNS}")
            except Exception as exc:  # noqa: BLE001 - best-effort
                print(f"put_mapping skipped (dynamic mapping will cover): {exc}")

        # Stream every vuln doc (full source, so the backup below can restore
        # them verbatim), grouped by identity key.
        groups: dict[tuple, list[dict]] = defaultdict(list)
        total = 0
        async for hit in async_scan(
            es,
            index=INDEX_VULNS,
            # async_scan's ``query`` is the FULL search body (it forwards to
            # client.search(body=query)), so it must wrap the match_all clause.
            query={"query": {"match_all": {}}},
        ):
            total += 1
            src = hit["_source"]
            key = (src.get("agent_id", ""), src.get("cve") or "", src.get("name", ""))
            groups[key].append(src)

        updates: list[tuple[str, list[str]]] = []  # (finding_id, merged scan_history)
        deletes: list[str] = []
        deleted_docs: list[dict] = []  # full source of docs being removed (backup)
        dup_groups = 0
        for docs in groups.values():
            if len(docs) <= 1:
                continue
            dup_groups += 1
            docs_sorted = sorted(
                docs,
                key=lambda d: (_ts_key(d.get("detected_at") or ""), d.get("finding_id", "")),
                reverse=True,
            )
            canonical, others = docs_sorted[0], docs_sorted[1:]
            hist = list(canonical.get("scan_history") or [])
            for d in others:
                t = d.get("detected_at")
                if t:
                    hist.append(t)
            hist = list(dict.fromkeys(hist))
            hist.sort(key=_ts_key)  # ascending
            updates.append((canonical["finding_id"], hist))
            deletes.extend(d["finding_id"] for d in others)
            deleted_docs.extend(others)

        print(
            f"docs={total} groups_with_dups={dup_groups} "
            f"canonical_updates={len(updates)} deletes={len(deletes)}"
        )
        if dry_run:
            for fid, hist in updates[:20]:
                print(f"  UPDATE {fid} scan_history={hist}")
            for fid in deletes[:20]:
                print(f"  DELETE {fid}")
            print(f"(dry-run: NOT applied -- {len(updates)} updates, {len(deletes)} deletes)")
            return

        # Safety net: write every doc we are about to touch to a JSON backup so
        # the migration is reversible without an ES snapshot.
        backup_path = f"vulnscan_consolidate_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "created_at": datetime.now().isoformat(),
                    "index": INDEX_VULNS,
                    "canonical_updates": [
                        {"finding_id": fid, "scan_history": hist} for fid, hist in updates
                    ],
                    "deleted_docs": deleted_docs,
                },
                fh,
                ensure_ascii=False,
                indent=2,
            )
        print(f"backup written: {backup_path} ({len(deleted_docs)} deleted docs, {len(updates)} updates)")

        actions: list[dict] = []
        for fid, hist in updates:
            actions.append(
                {
                    "_op_type": "update",
                    "_index": INDEX_VULNS,
                    "_id": fid,
                    "doc": {"scan_history": hist},
                }
            )
        for fid in deletes:
            actions.append({"_op_type": "delete", "_index": INDEX_VULNS, "_id": fid})
        if actions:
            await async_bulk(es, actions)
        print(f"Done: {len(updates)} canonical docs updated, {len(deletes)} duplicates deleted")
    finally:
        await es.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Consolidate duplicate vuln records in ES (dedup + scan_history)."
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without writing.")
    args = parser.parse_args()
    asyncio.run(main(dry_run=args.dry_run))
