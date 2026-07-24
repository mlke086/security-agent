# P0 改造：Nuclei 扫描引擎集成

> 日期：2026-07-18
> 阶段：架构改造 P0
> 依据：`docs/架构改造设计.md` 阶段三「集成漏洞扫描引擎核心」

## 设计选择

参考文档同时给出两个路径：
- **方案 A**：os/exec 调用 CLI（轻量）
- **方案 B**：嵌入 Nuclei SDK（专业）

我们采用**方案 A**：
- agent 仍是单二进制，不引入 Go SDK 依赖（避免 go.mod 大量膨胀）
- nuclei CLI + templates bundle 通过 install.sh 单独下载
- nuclei 缺失时，agent 自动回退到 matcher（向后兼容）
- templates 通过控制台 `/api/v1/rules/sync` 下发，保证一致性

| 比较 | 方案 A（已选） | 方案 B |
|---|---|---|
| agent 二进制大小 | 11 MB（不变） | +35 MB（SDK） |
| go.mod 依赖 | 不增 | nuclei/v3 + 大量传递依赖 |
| 启动速度 | 不变 | 慢（初始化 SDK） |
| CVE 模板更新 | 拉 tarball 替换 | 重新编译 agent |
| 多进程隔离 | 走 agent 进程 + cgroups | go-plugin 跨进程 |
| 隔离故障域 | OS process boundary | 单进程崩溃全挂 |

文档方案 A 更适合我们当前架构（单二进制 + 系统级 systemd 隔离），所以选了它。

## 改动清单

### 新增
- `agent/internal/scan/nuclei/` 包
  - `client.go` — Runner 接口 + Request/Result/Summary 类型
  - `runner.go` — os/exec 包装（CLIRunner）+ NDJSON 流式解析
  - `templates.go` — Manifest 校验 + tar 解压
  - `runner_test.go` — JSON 解析 / 工具函数 / Manifest 往返

### 修改
- `agent/internal/scan/engine.go`
  - `ScanEngine.nuclei` 字段
  - `ScanCommand.Engine` (matcher|nuclei) + `Nuclei*` 字段
  - `Engine` 类型 + `EngineNuclei` 常量
  - `Execute()` 分支：EngineNuclei 走 `runNuclei()`，否则原 matcher 路径
  - `runNuclei()` 函数 + `toFinding()` 翻译

- `src/agents/models.py` — `ScanTask` 加 `engine` / `nuclei_*` 字段

- `src/api/routers/vulnscan.py` — `POST /tasks` 接受并校验 `engine` 字段

- `src/orchestration/subgraphs/vulnscan/{graph,nodes}.py`
  - `_default_state()` + `run_vulnscan()` 新增 engine/nuclei 入参
  - `dispatch()` 把 engine/nuclei 塞到 WS scan_command payload

- `frontend/src/pages/ScanTaskPage.tsx` — 手动表单加 engine 选择器 + nuclei 子表单（仅 engine=nuclei 时显示）

- `agent/packaging/install.sh` — `install_nuclei()` 函数，从 projectdiscovery/nuclei release 拉 nuclei CLI 到 `/opt/secagent/bin/`，失败时降级到 matcher-only

## 测试覆盖

- `agent/internal/scan/nuclei/runner_test.go` (5 个测试)
  - NDJSON 行解析
  - `firstNonEmpty` / `firstNonEmpty3`
  - `equalFold` (大小写不敏感 hex 比较)
  - `Manifest` 磁盘往返

- `tests/unit/api/test_agents_api.py::test_engine_field_roundtrip_through_scantask` — ScanTask 字段 + payload 结构
- `tests/unit/api/test_agents_api.py::test_install_script_downloads_nuclei` — install.sh 内容包含 `install_nuclei()` + nuclei tarball URL + `|| true` 容错

## 数据流

```
UI (ScanTaskPage)
  -> POST /api/v1/vulnscan/tasks {engine: "nuclei", nuclei_*: [...]}
  -> run_vulnscan(engine="nuclei", ...)
  -> dispatch() 构造 scan_cmd["engine"]="nuclei", scan_cmd["nuclei_*"]
  -> WS: {"type": "scan_command", "payload": {..., "engine": "nuclei", ...}}
  -> Agent engine.Execute()
     -> runNuclei() 调 nuclei CLI
        -> nuclei -silent -json -t /opt/secagent/templates ...
        -> NDJSON 一行行变 nuclei.Result
        -> toFinding() 转 Finding
        -> OnResult(ws.send) 流回控制台
```

## 验收清单（手动）

- [x] agent 编译 + 所有 Go test 通过
- [x] 前端 ScanTaskPage TSX parse 通过
- [x] 控制台 Python AST 通过
- [x] ruff 检查我改的文件只余下 pre-existing UP042

## 已知限制 / 留给下次的项

1. **`nuclei -version` 在新版本里没这个 flag**，调用可能 stderr 输错但不影响 —— install.sh 用 `2>/dev/null | head -1` 容忍。
2. **`nuclei -tags` 是 `-t` 的子集**，我们的 frontend 暴露 "tags" 写法但 CLI 用 `-tags`。
3. **没有引入 templates pre-fill**——首次启动需要手动 `cd agent && ./nuclei -update-templates`（或 console `/api/v1/rules/sync` 推送 Manifest）。
4. **scan_result 上报 protocol 兼容**：现有 matcher 走 `Finding{Category: "sys_vuln"/"baseline"}`，新加的 `Category: "nuclei"`，前端 VulnListPage 应该按 category 着色（实测请确认）。
5. **templates 同步**未做——`src/agents/rules_sync.py` 还在跑 NVD sync（P0 还没集成 nuclei-templates 下载）。等明确需求再加。
