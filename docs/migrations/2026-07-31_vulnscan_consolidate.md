# 迁移：漏洞清单整合（vulnscan_consolidate）— 2026-07-31

## 背景

V11 批次引入漏洞清单"自动修复 + 扫描历史合并 + 去重"功能（`aggregate` 节点 reconcile）。
在功能上线**之前**，历史存量漏洞（V11 之前多轮扫描生成的重复记录 / 无 scan_history 的旧记录）
需要一次性整合到新数据结构，否则：

- 同一 (agent, cve, name) 的旧重复记录不会自动消失（reconcile 只处理新扫描命中的 key）
- 已修复但从未被记录 `first_fixed_at` 的旧漏洞无法追溯

## 脚本

- 位置：`scripts/migrations/vulnscan_consolidate_20260731.py`（原仓库根 `_migrate_consolidate_vulns.py`）
- 行为：
  1. 读取 ES `vulnscan-vulns` 全量
  2. 按 (agent_id, cve, name) 分组，保留 detected_at 最新的一条为 canonical
  3. 其余同 key 记录：detected_at 并入 canonical 的 `scan_history`，然后删除
  4. 输出备份到 `vulnscan_consolidate_backup_<ts>.json`（**已 gitignore**）

## 运行

```bash
# 需 ES 可连接（settings 里 ES_HOSTS 指向 192.168.80.101:9200）
python scripts/migrations/vulnscan_consolidate_20260731.py
```

预期输出：
- 扫描多少条、合并多少组、删除多少条重复记录
- 备份文件路径（含完整原始数据，可回滚）

## 回滚

```bash
# 用备份文件恢复：
# 1. 删除当前 vulnscan-vulns 中被合并/删除的文档（备份里有原始 _id）
# 2. 重新写入备份中每个文档的原始 _source
```
> 回滚脚本未提供（一次性迁移，备份在手即可人工恢复）。迁移前建议对 ES 做一次快照。

## 幂等性

已运行过一次后再次运行：无重复记录可合并，输出 0 条删除（空跑安全）。
可用 `--dry-run` 参数先行验证影响范围。

## 相关脚本

- `scripts/archive/migrate_s2_auth_headers.py`（原 `_migrate.py`）：V10 stage 2 的测试 fixture 迁移工具，
  使命已完成，归档保留。
