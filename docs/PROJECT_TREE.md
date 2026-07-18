# 项目结构 - 2026-07-18 整理

> 当前项目已清理：移除了 30+ 临时过程文件（`_fix_*.py`、`_*.log`、`_start_*.cmd`、`debug/` 等），
> 旧版本文档已归档到 `docs/archive/`，构建产物已删除（`dist/`、`__pycache__/`、`test-results/`），
> `.gitignore` 已扩展，覆盖未来所有过程性文件。

---

## 顶级目录树

```
security-agent/
├── .agents/                       # OpenAI agents 元数据
├── .claude/                       # Claude 配置
├── .github/
│   └── workflows/                # CI 工作流
│       ├── ci.yml                # 主 CI（ruff + mypy + pytest）
│       └── security.yml          # 安全扫描（bandit 等）
├── .goworks/                     # Go 模块缓存（gitignore 应排除，未列）
├── .idea/                         # IntelliJ 项目配置（gitignore）
├── .pytest_cache/                # pytest 缓存（gitignore）
├── .ruff_cache/                   # ruff 缓存（gitignore）
│
├── agent/                         # ★★★ Go Agent 源码 ★★★
├── deployments/                  # ★ 部署产物
├── docs/                         # ★★★ 文档（含 archive）
├── frontend/                     # ★★★ React 前端
├── scripts/                       # ★ 工具/运维脚本
├── src/                           # ★★★ Python 后端源码
├── tests/                         # ★★★ 测试
│
├── .env                           # 当前环境配置（gitignore）
├── .env.example                   # 环境配置模板（提交）
├── .gitignore                    # Git 忽略规则
├── pyproject.toml                # Python 项目配置
├── README.md                     # 项目说明（17 字节，建议补充）
```

---

## `agent/` —— Go Agent（主机端漏洞扫描代理）

> 独立 Go 二进制，部署在被纳管主机上，与控制台 WebSocket 通信。

```
agent/
├── Makefile                      # Unix 构建（`make build-all` 出 3 平台）
├── build.ps1                     # ★ Windows PowerShell 构建（`make` 等价物）
├── go.mod / go.sum               # Go 模块依赖
│
├── cmd/
│   └── agent/                    # main 包
│       └── main.go               # 入口、enroll 引导、回调接线、信号处理
│
├── internal/                     # 业务包（不对外）
│   ├── comm/                     # WebSocket 客户端
│   │   ├── client.go             # 连接、重连、消息分发
│   │   └── client_test.go
│   ├── config/                   # 配置加载
│   │   └── config.go             # AgentConfig 结构 + Load/Save
│   ├── crypto/                   # Ed25519 验签
│   │   ├── verify.go             # PublicKey 全局变量 + Verify() 入口
│   │   └── verify_test.go
│   ├── enroll/                   # 注册流程
│   │   ├── enroll.go             # POST /enroll 客户端
│   │   └── enroll_test.go
│   ├── queue/                    # 离线消息队列（SQLite）
│   │   ├── queue.go
│   │   └── queue_test.go
│   ├── resource/                 # CPU/内存监控
│   │   ├── monitor.go
│   │   └── monitor_test.go
│   ├── scan/                     # 扫描引擎
│   │   ├── engine.go             # ScanEngine.Execute + 内联/缓存规则
│   │   ├── matcher.go            # 规则匹配
│   │   ├── collector.go          # 包/内核采集
│   │   ├── rules.go              # 规则存储
│   │   └── rules_test.go / matcher_test.go / collector_test.go
│   ├── updater/                  # 自升级 + 规则热更新
│   │   ├── upgrade.go            # HandleUpgrade / HandleRuleUpdate（带签名校验）
│   │   └── upgrade_test.go
│   └── version/
│       └── version.go            # 编译期注入的版本号
│
├── packaging/                    # 打包文件
│   ├── agent.service             # systemd unit（生成时由 install.sh 渲染）
│   ├── install.sh                # ★ Linux 安装脚本
│   └── install.ps1               # Windows 安装脚本（未启用）
│
└── rules/                        # ★ 编译产物暂存目录（实际放 deployments/agent/dist/）
```

**产物位置**：`deployments/agent/dist/<os>/<arch>/agent[.exe]`（由 `Makefile` / `build.ps1` 产出，被控制台 `/api/v1/agents/binary/{os}/{arch}` 读取）。

---

## `src/` —— Python 后端（控制台）

```
src/
├── agents/                       # ★★ 漏洞扫描子系统
│   ├── enroll.py                 # 安装脚本渲染、token 生成/校验、注册
│   ├── manager.py                # 主机心跳/在线/CRUD；含 decommission_host_by_ip
│   ├── models.py                 # Pydantic：Host / ScanTask / ScanResult / VulnFinding / ScanReport
│   ├── rules_sync.py             # NVD 抓取 + 规则转换 + ES/PG 持久化
│   ├── scheduler.py              # 后台循环：规则同步 + 离线检查
│   ├── signing.py                # Ed25519 服务端 sign / get_public_key_hex
│   ├── store.py                  # VulnscanStore（ES+PG 双写，timestamptz 规整）
│   └── ws_gateway.py             # WebSocket 网关 + pubsub 跨 worker 路由
│
├── api/                          # ★★ FastAPI 应用
│   ├── main.py                   # FastAPI app + lifespan + 路由挂载
│   ├── store.py                  # 内存版 EventStore（in-memory backend）
│   ├── store_es.py               # ES 版 EventStore
│   ├── events_bus.py             # Redis pub/sub 事件广播
│   ├── auth/
│   │   └── routes.py             # /api/v1/auth：登录 / 注销 / me + JWT 签发
│   └── routers/
│       ├── agents.py             # ★ 主机纳管：enroll-token / install / binary / ca / install-helper / console-url
│       ├── operations.py         # 事件 / 审批 / 指标
│       ├── rules.py              # 规则版本 / 同步 / 包下载
│       ├── stream.py             # SSE（token query 鉴权）
│       ├── demo.py               # 演示数据种子
│       └── vulnscan.py           # 漏扫任务 CRUD
│
├── common/                       # 公共基础设施
│   ├── audit/
│   │   └── audit_logger.py       # ES 审计写入
│   ├── config/
│   │   └── settings.py           # pydantic-settings 全配置（含 agent_console_external_url）
│   ├── db/
│   │   └── pg.py                 # asyncpg 池 + schema 初始化 + 默认用户种子
│   ├── logging/
│   │   └── logger.py             # structlog + PII 脱敏
│   └── celery_app.py             # Celery 审批超时兜底（未启动）
│
├── execution/                    # ★★ 响应执行子系统
│   ├── actions/                  # 动作连接器
│   │   ├── dispatcher.py         # 幂等派发 + dry-run + rollback
│   │   └── connectors/
│   │       ├── dns_block.py      # DNS 拦截
│   │       ├── notify.py         # 通知（飞书/钉钉/Slack）
│   │       ├── siem_tag.py        # SIEM 打标
│   │       └── simulator.py       # 占位（firewall/isolate 等）
│   ├── harness/                  # 复盘/取证
│   ├── linter/
│   │   └── poc_linter.py         # PoC AST 安全审查（防 sys.modules 逃逸）
│   ├── sandbox/
│   │   └── executor.py           # Docker 沙箱执行器（network internal + gVisor）
│   └── harness/
│
├── knowledge/                    # ★★ 知识子系统
│   ├── graphrag/                 # GraphRAG 混合检索
│   │   ├── engine.py             # RRF 融合 + Redis 缓存
│   │   ├── graph/neo4j_client.py # Neo4j 邻居查询
│   │   └── vector/
│   │       ├── embedding.py      # BGE-large-zh-v1.5（1024 维）
│   │       └── milvus_client.py  # Milvus IVF_FLAT 索引
│   ├── models/
│   │   └── adapter.py            # LLM 适配器（DeepSeek/Claude/vLLM）
│   └── tools/                    # 情报 + 通知
│       ├── virustotal.py
│       ├── otx.py                # AlienVault OTX
│       ├── notifier.py           # 企微/钉钉
│       └── registry.py
│
├── orchestration/                # ★★ LangGraph 编排（核心）
│   ├── runner.py                 # 入口 run_pipeline(event_id, text, iocs, source)
│   ├── main_graph/               # 主图
│   │   ├── graph.py              # 入口/路由/置信度阈值
│   │   ├── state.py              # MainGraphState（TypedDict）
│   │   ├── entry.py              # 事件入站 + 审计
│   │   ├── orchestrator.py       # 优先级/标签分发
│   │   └── aggregator.py         # 阶段汇总（保留 stage 给 P1-CORE-1）
│   ├── subgraphs/                # 4 个子图
│   │   ├── investigation/        # CTI 分析 + GraphRAG
│   │   ├── vuln_hunter/          # PoC 生成 + 沙箱验证（迭代循环）
│   │   ├── vulnscan/             # 主机漏洞扫描（subgraph + 子节点 graph/nodes/state）
│   │   └── responder/            # Playbook 匹配 + HITL + 执行
│   ├── memory/                   # MemoryManager（跨事件证据库）
│   └── playbooks/                # 10 个 YAML playbook
│       ├── brute_force.yaml
│       ├── cve_exploit.yaml
│       ├── data_exfiltration.yaml
│       ├── ddos.yaml
│       ├── dns_tunneling.yaml
│       ├── lateral_movement.yaml
│       ├── malware_detection.yaml
│       ├── phishing.yaml
│       ├── ransomware.yaml
│       └── unauthorized_access.yaml
│
├── preprocessing/                # ★★ 告警预处理
│   ├── consumer.py               # Kafka 消费 + 稳定 event_id（哈希去重）
│   ├── ioc_extractor/extractor.py
│   ├── rules/default_rules.yaml  # 7 条脱敏规则
│   └── sanitization/
│       ├── engine.py             # 热加载 + 监控
│       └── mask.py
```

---

## `tests/` —— 测试

```
tests/
├── conftest.py                   # pytest 全局 fixture
│
├── unit/                         # ★ 单元测试（按子系统组织，257 通过）
│   ├── agents/                   # enroll/manager/rules_sync/scheduler/signing/store/ws_gateway
│   ├── api/                      # 各路由的鉴权/边界用例
│   ├── execution/                # dispatcher/poc_linter/sandbox_executor
│   ├── knowledge/                # tools
│   ├── orchestration/             # main_nodes/orchestrator/playbook_matcher/hitl/approval_store/vulnscan_nodes/investigation
│   └── preprocessing/            # consumer/ioc_extractor/sanitization
│
├── integration/                  # 集成测试
│   └── test_investigation.py
│
└── e2e/                          # 端到端
    └── test_scenarios.py
```

> 测试套件状态：unit 通过 ~250 条 / 1 失败（原本的 install mock，后已修）。
> 运行：`.\.venv312\Scripts\python.exe -m pytest -o addopts=""`

---

## `frontend/` —— React 前端

```
frontend/
├── package.json / package-lock.json
├── tsconfig.json / vite.config.ts / playwright.config.ts
├── index.html
│
├── src/
│   ├── main.tsx                  # React 入口
│   ├── App.tsx                   # 路由
│   ├── App.css
│   ├── types.ts                  # 前端 TS 类型
│   ├── api/
│   │   └── client.ts             # ★ FastAPI 客户端（login/createEnrollToken/getInstallScript/getConsoleUrl...）
│   ├── components/               # 通用组件
│   ├── context/                  # React Context（认证等）
│   └── pages/                    # ★ 页面
│       ├── LoginPage.tsx
│       ├── DashboardPage.tsx
│       ├── EventQueuePage.tsx
│       ├── EventDetailPage.tsx
│       ├── ApprovalsPage.tsx
│       └── HostOnboardPage.tsx  # ★ 主机纳管（含 GroupSelector/TwoStep Install）
│
└── e2e/
    └── app.spec.ts               # Playwright e2e
```

**构建产物已删除**（`dist/`、`test-results/`、`node_modules/` 不进 git）。

---

## `deployments/` —— 部署产物

```
deployments/
├── agent/
│   └── dist/                     # ★ Go Agent 编译产物（make build-all 输出到这里）
│       ├── linux/amd64/agent    # x86_64 Linux
│       ├── linux/arm64/agent    # ARM64 Linux（用 make build-all 一次性出齐）
│       └── windows/amd64/agent.exe
│
├── docker/                       # Docker Compose + sandbox 配置
│   ├── docker-compose.dev.yml    # 开发环境（PG/Redis/ES/Milvus/Neo4j）
│   ├── Dockerfile.sandbox        # 沙箱执行器镜像
│   ├── create-sandbox-net.sh/.bat # 创建 docker network
│
└── k8s/                          # Kubernetes 部署清单
    ├── namespace.yaml
    ├── configmap.yaml
    ├── secret.yaml
    ├── deployment.yaml           # 控制台 deployment
    ├── service.yaml              # ClusterIP / NodePort
    └── hpa.yaml                  # HPA 自动扩缩
```

---

## `docs/` —— 文档（按版本组织）

```
docs/
├── README-style docs（当前有效）
│   ├── 代码知识图谱.md                # 架构图 + 模块依赖（review 用）
│   ├── 项目审查V3.md                # ★ 当前审查报告（P0/P1/P2 + CONFIRMED/SUSPECTED）
│   ├── 后续计划V3.md                # ★ 后续计划 + V3 修复轮所有 addendum（推荐 1st read）
│   ├── 服务快速调用表.md              # API + 命令速查
│   ├── 漏洞扫描子系统开发文档.md
│   ├── 漏洞扫描子系统开发方案.md
│   ├── 漏洞扫描子系统检查报告.md
│   ├── 前/后端开发文档.md
│   ├── 功能测试文档.md
│   ├── 项目测试方案.md
│   ├── 项目测试报告.md
│   ├── 企业级AI增强主机漏洞扫描系统设计方案.md
│   ├── 安全AI_Agent开发计划_v1.1.md
│   ├── 安全AI_Agent项目开发文档.md    # 原项目设计（保留）
│   ├── 工程化路线图.md
│   ├── 进度说明.md
│   ├── 项目架构与流程说明.md
│   ├── 项目情况分析.md
│   └── deployment-guide.md
│
├── archive/                       # ★ 历史归档
│   ├── 后续计划.md                 # 2026-07-13（被 V3 替代）
│   ├── 后续计划V2.md                # 2026-07-13（被 V3 替代）
│   ├── 计划v1.md / 计划v2.md       # 早期版本
│   ├── 项目审查V1.md / V2.md       # 历史审查
│   ├── 安全AI_Agent项目开发文档.docx # 原 Word 版本
│   └── sessions/                   # 会话记录留位（空目录，未来放每日 dev log）
```

---

## `scripts/` —— 工具/运维脚本

```
scripts/                          # 留下来的：项目基础设施（数据导入/启动/调试）
├── archive/                      # ★★ 临时过程脚本归档（不再用）
│   ├── fix_*.py × 7              # 一次性修复脚本
│   ├── remote_*.py × 5           # 远程调试脚本
│   └── build_sandbox_v2.py
│
├── build_sandbox.py              # 沙箱镜像构建（one-shot，使用 make 替代也可）
├── check_connectivity.py          # 联通性测试
├── decision_record.py             # 决策记录管理器
├── dedup_validator.py            # 去重校验
├── gen_*.py × 6                  # 项目脚手架生成（首次搭建用，可删；保留供未来复用）
├── healthcheck.sh                # 健康检查（运维用）
├── import_attack_stix.py         # STIX 攻击数据导入
├── ingest_knowledge.py           # 知识摄入入口
├── ingest_neo4j_to_milvus.py      # 图谱数据迁移 Neo4j → Milvus
├── integrate_memory.py            # 记忆整合
├── proxy_test.py                  # 代理测试
├── smoke_test.py                  # 烟雾测试
├── sprint1_test.py                # Sprint 1 验证
├── stress_test_preprocessing.py   # 预处理压力测试
├── test_deepseek.py / test_imports.py  # LLM/imports 烟测
└── update_*.py × 4                # 项目结构更新工具
```

---

## 清理动作（本次）

| 操作 | 数量 | 备注 |
|---|---|---|
| 删除顶层过程文件 | 25 | `_fix_*.py` ×15, `_*.log` ×6, `_start_*.cmd/.py` ×2, `_store_part1.b64`, `diag_err.txt`, `session_record.md` |
| 删除 `debug/` 目录 | 1 | 含网络 HAR 抓包（敏感 IP） |
| 删除 `security_agent.egg-info/` | 1 | pip install 残留 |
| 删除 `frontend/dist/` | 1 | 构建产物 |
| 删除 `frontend/test-results/` | 1 | Playwright 产物 |
| 删除 `__pycache__/` | 41 | 自动生成 |
| 归档文档到 `docs/archive/` | 7 | 后续计划 v1/V2、计划 v1/v2、项目审查 v1/v2、设计 docx |
| 归档过程脚本到 `scripts/archive/` | 16 | `fix_*.py`、`remote_*.py`、`build_sandbox_v2.py` |
| 扩展 `.gitignore` | + | 新增过程文件 pattern、debug/、build artifacts |

---

## 未来 commit 建议

按提交拆分（如果上游要分 PR）：

```bash
git add .gitignore .                  # 1. 扩展 .gitignore
git add docs/archive/                 # 2. 归档旧文档
git add scripts/archive/              # 3. 归档过程脚本
git add -u  # 删除 _fix*, debug/, egg-info, dist, test-results, session_record.md 等
git commit -m "chore: clean up process artifacts from V3 dev cycle"
```

清理完后项目根目录干净、docs 有归档、scripts 有 archive，迭代历史清晰可追溯。
