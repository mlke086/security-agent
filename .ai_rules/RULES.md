# RULES —— AI 协作规则（Harness Engineering）

> 适用对象：所有在本仓库工作的 AI 工具（Claude Code / OpenAI Codex / DeepSeek-Reasonix / 其他）与人工。
> 本文件是**强制约束**：违反规则的提交会被拒绝或要求补正。

---

## 规则 1：项目现状文档必须同步

- 每次修改代码 / 配置 / 文档后，**更新 `.ai_rules/项目现状.md`**：
  - 在文件头部"最近更新"追加一行：`YYYY-MM-DD | 工具名 | 改动摘要`
  - 同步修改对应章节（架构/功能/数据/已知问题等）
- 新增功能 → 更新"功能清单"；新增中间件/配置 → 更新"测试机信息"；发现新问题 → 更新"已知问题"

## 规则 2：更改记录文档必须登记

- 每次 **git commit** 后，在 `.ai_rules/项目更改记录文档.md` 追加一行（简表）+ 按需补"变更明细"：
  ```
  | 时间 | AI 工具 | 改动内容 | 提交 hash | 单元测试 | 备注 |
  ```
- "AI 工具"列填写实际执行工具名（如 `Claude Code` / `OpenAI Codex` / `DeepSeek-Reasonix` / `人工`）
- 未提交的改动（如临时验证）也应补记，备注标注"未提交"

## 规则 3：提交代码必须同步单元测试（强制）

- **任何代码改动（功能/修复/重构）在提交时必须包含对应的单元测试用例**，否则视为未完成：
  - Python：pytest 用例，放 `tests/unit/<模块>/`，覆盖新行为（正常路径 + 边界 + 异常）
  - Go：`*_test.go` 与被测代码同目录
  - 前端：纯逻辑（client.ts 等）可加 vitest 用例；组件至少保证 tsc/vite build 通过
- 测试运行命令（在仓库根目录）：
  ```bash
  # Python 单测（需 101 中间件可达，见 .env）
  .venv312/Scripts/python.exe -m pytest tests/unit/<目标> -o addopts=""
  # Go
  cd agent && go test ./...
  # 前端
  cd frontend && npx tsc --noEmit && npx vite build
  ```
- 提交信息中写明测试结果（如 `测试: pytest 7 passed`）

## 规则 4：docs 定期归档

- **频率**：每 2 周，或当某文档明显过期/被新文档取代时
- **执行**：`bash scripts/archive_docs.sh`（默认预览模式，`--apply` 执行）
  - 归档标准：`docs/` 下超过 60 天未更新的非 README/非方案性文档 → 移入 `docs/archive/`
  - 命名冲突自动加时间戳后缀；不删除任何文件（仅移动）
- 归档后更新 `.ai_rules/项目现状.md` 的 docs 说明（如有）

## 规则 5：临时文件定时清理

- **频率**：每次 AI 会话结束时，或工作区临时文件 > 20 个时
- **执行**：`bash scripts/cleanup_tmp.sh`（默认预览模式，`--apply` 执行）
- **清理范围（只删这些）**：
  - 项目根/子目录下 `.tmp*`、`*.tmp`、`*_tmp*`、`.tmp_*.sh/.py/.txt`
  - `__pycache__/`、`.pytest_cache/`、`.mypy_cache/`、`.ruff_cache/`、`.coverage`
  - `agent/dist/` 下的临时构建产物（`*.test`、`*-v*` 等，保留正式产物）
  - 项目根下的 `e2e_*.sh`、`check_*.sh`、`dbg_*.sh` 等一次性验证脚本（保留 `start_all.sh`、`restart_*.sh`）
- **绝不删除**：`src/`、`agent/internal|cmd`、`frontend/src`、`tests/`、`deployments/` 下的任何代码文件；`.env`；`docs/`
- 清理后更新 `.ai_rules/项目更改记录文档.md`（备注"临时文件清理"）

---

## 附：各 AI 工具接入说明

| 工具 | 如何读到本规则 |
|---|---|
| Claude Code | 项目根放 `CLAUDE.md`（软链或复制本文件核心条目） |
| OpenAI Codex | 项目根放 `AGENTS.md`（同上） |
| DeepSeek-Reasonix | 项目根放 `REASONIX.md`（同上） |
| 所有工具 | `.ai_rules/` 目录本身作为约定俗成的规则区 |

> 软链已建立（2026-08-09，commit e9c6e1e）：项目根 `CLAUDE.md` / `AGENTS.md` / `REASONIX.md` → `.ai_rules/RULES.md`，工具启动时自动读取本规则。
