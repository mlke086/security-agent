# 安全 AI Agent 多智能体系统 — 详细开发计划

> 基于《安全AI_Agent项目开发文档 v1.1》制定
> 计划版本：v1.0 | 日期：2026年7月6日

---

# 第一章 项目概述

## 1.1 项目定位与愿景

本项目构建一套**企业级安全运营自动化平台**，以 LangGraph 为编排引擎，将多个专业化 AI Agent 组织为分层协作体系，覆盖威胁研判、漏洞验证、响应执行三大安全运营核心环节。

**愿景**：让 AI Agent 承担 SOC 中 80% 的重复性分析工作，将安全分析师从"告警消化机器"解放为"高价值决策者"，将企业平均响应时间（MTTR）降低 30% 以上。

## 1.2 核心价值主张

| 痛点 | 现状 | 本项目解法 |
|------|------|----------|
| 告警过载 | 分析师每天处理数千条告警，真正高危事件被淹没 | 调度中枢 Agent 自动噪音过滤 + 优先级分类，低危事件自动归档 |
| 研判浅层 | 单一向量检索无法揭示 APT 组织、C2 基础设施间的深层关联 | GraphRAG 融合 Milvus 向量检索 + Neo4j 图谱关联，溯源深度提升 15-20% |
| 漏洞验证慢 | 人工写 PoC 验证漏洞平均需要数天，时效性差 | Vuln-Hunter 子图在隔离沙箱中自动迭代生成并验证 PoC，最多 10 轮内收敛 |
| 响应延迟高 | 响应策略需人工拟定，流程审批耗时长 | 响应执行子图自动匹配剧本 + HITL 审批流，高危操作 15 分钟内完成审批 |
| 数据合规风险 | 原始告警含明文密码、PII，直接接入 LLM 存在泄露风险 | 脱敏引擎在数据入口处完成 PII 掩码 + IOC 标准化，敏感信息不进入 Agent 推理链路 |

## 1.3 系统全貌：四层架构

```
数据源（SIEM/NTA/IDS/蜜罐/漏洞扫描器/威胁情报源）
    ↓
[第一层] 数据源与预处理层：脱敏引擎（PII掩码 + IOC标准化） → 结构化JSON
    ↓
[第二层] 编排与智能体层：LangGraph主图 + 嵌套子图（研判 / 漏洞挖掘 / 响应执行）
    ↓
[第三层] 知识与工具层：GraphRAG混合检索引擎 + 统一API工具箱 + 模型基座
    ↓
[第四层] 执行与隔离层：PoC Linter预检 + MicroVM沙箱集群 + HITL熔断审批
```

## 1.4 非功能性目标

| 类别 | 指标 |
|------|------|
| 吞吐量 | 预处理层单实例 ≥ 2000 events/s，扩展后 ≥ 20000 events/s |
| 延迟 | 单条告警端到端研判结论 P99 < 30 秒 |
| 可用性 | 核心服务 SLA ≥ 99.5%（月均） |
| 脱敏准确率 | PII 召回率 ≥ 99%，IOC 提取准确率 ≥ 98% |
| 安全 | 沙箱 0 逃逸；Prompt 注入 100% 拦截 |
| 合规 | 数据不出域（私有化部署模式下） |

---

# 第二章 需求拆解与功能模块

## 2.1 模块总览

系统共分为 **6 个功能域、21 个子模块**，按四层架构组织：

```
功能域 F0：基础设施与工程规范
功能域 F1：数据接入与预处理
功能域 F2：编排层核心（主图 + 调度中枢）
功能域 F3：智能体子图（研判 / 漏洞挖掘 / 响应执行）
功能域 F4：知识与工具层（GraphRAG + 工具箱 + 模型适配）
功能域 F5：执行与隔离层（Linter + 沙箱 + HITL）
功能域 F6：API层与前端界面
```

---

## 2.2 F0：基础设施与工程规范

### F0-1 项目骨架与工程规范
- 初始化 `security-agent/` 目录结构（按文档第9.1节）
- 配置 `pyproject.toml`：Python 3.11+，声明全量依赖与开发依赖
- 集成代码质量工具链：Ruff（lint + format）、mypy（strict 模式）、pre-commit 钩子
- 提交规范：Conventional Commits（`feat/fix/refactor/test/docs/chore`）

### F0-2 本地开发环境
- `docker-compose.dev.yml`：一键启动本地依赖（Kafka、Milvus standalone、Neo4j Community、Redis、Elasticsearch）
- 健康检查脚本 `scripts/healthcheck.sh`，验证所有服务就绪
- `.env.example`：列出全量环境变量，含 API Keys、数据库连接串、模型端点

### F0-3 CI/CD 流水线
- GitHub Actions / GitLab CI 流水线：Lint → Unit Test → Integration Test → Security Scan → Docker Build → Deploy
- 分支策略：main（生产）/ develop（开发主线）/ feature/*（功能分支）/ hotfix/*（紧急修复）
- 安全扫描：Bandit（SAST）+ Safety（依赖漏洞）

---

## 2.3 F1：数据接入与预处理

### F1-1 多源数据接入适配器
- 对接 7 类数据源：SIEM（Syslog/REST API）、NTA（Kafka/sFlow）、IDS/IPS（SNMP Trap/API）、蜜罐（Syslog/Webhook）、IAM（REST API/Syslog）、漏洞扫描器（REST API/CSV）、威胁情报源（STIX/TAXII/API）
- 统一通过 Kafka 汇聚，各适配器将原始日志推送至对应 Kafka Topic
- 外部依赖：Kafka（已由运维单独部署）

### F1-2 正则规则引擎
- YAML 规则配置文件（`src/preprocessing/rules/`），覆盖5类规则：PII（手机/邮箱）、密码字段、IP 地址、域名、文件哈希（MD5/SHA-256）
- 支持热更新：通过文件监听（watchdog）无需重启服务
- 规则覆盖率评估脚本，批量验证规则正例/反例

### F1-3 脱敏处理模块
- 三类掩码策略：密码字段全替换为 `***`、手机号保留前3后4位、邮箱用户名保留首字符
- 重叠 span 处理：高优先级规则（credential > pii > hash）优先覆盖
- 脱敏后文本通过校验确保无明文密码残留

### F1-4 IOC 标准化提取器
- 从脱敏文本中提取 IP、域名、文件哈希、URL 四类 IOC
- 私有地址过滤（10.x / 172.16-31.x / 192.168.x）降低误报
- 输出标准化 JSON Schema（event_id、sanitized_text、iocs、timestamp、source）

### F1-5 Kafka 消费引擎
- 使用 `aiokafka` 实现异步消费，Consumer Group 支持水平扩展
- Dead Letter Queue：单条消息解析失败时投递 DLQ，不阻断整体消费
- 背压控制：Consumer Lag 超阈值时触发告警

---

## 2.4 F2：编排层核心

### F2-1 主图（LangGraph Main Graph）
- `MainGraphState`（TypedDict）极简状态定义：event_id、priority、stage、final_verdict、confidence_score、pending_action、subgraph_result、error
- 5 个核心节点：entry（入口校验）、orchestrator（优先级分类）、router（路由决策）、aggregator（结论聚合）、ignore（低危归档）
- 子图超时控制：研判子图 120s、漏洞挖掘子图 600s、响应子图 300s
- 全节点审计日志：每个节点执行追加一条结构化审计记录

### F2-2 调度中枢 Agent（Orchestrator）
- 规则兜底层：蜜罐捕获命令、特定 CVE 标签等高确信规则直接打分，无需 LLM 调用
- LLM 分类层：基于 Pydantic Schema 约束的 Structured Output，输出 priority + event_tags + noise_score + reasoning
- 10 条 Few-shot 示例：覆盖高危漏洞利用、横向移动、正常登录误报等典型场景
- 条件边路由：`low` → ignore、含 `vulnerability` 标签 → vuln_check、其他 → investigate

### F2-3 记忆管理器（Memory Manager）
- 跨子图共享记忆基础设施，负责证据去重、结构化归档、跨事件关联
- 存储后端：Milvus（语义相似查询） + Neo4j（实体关联查询）双写
- TTL 管理：临时记忆默认 24 小时过期，防止无限膨胀

---

## 2.5 F3：智能体子图

### F3-1 子图 A：研判与情报（Investigation Subgraph）

**情报专家 Agent（CTI Analyst）**
- 接收 IOC 列表，并发调用 GraphRAG 混合检索 + VirusTotal + AlienVault OTX
- 解析图谱关联（APT 家族归属、C2 基础设施、僵尸网络溯源）
- Pydantic 约束输出情报卡片：risk_level、related_apt、campaigns、ttps、recommendations

**研判专家 Agent（Investigator）**
- Chain-of-Thought Prompt：分5步推理（IOC特征分析→情报对比→攻击链识别→交叉验证→输出定性）
- Pydantic 约束输出研判结果：verdict（true_positive/false_positive/benign）、confidence（0-1）、evidence_summary、mitre_ttps
- 置信度阈值：≥0.8 确认真阳性 → 响应子图；0.5-0.8 可疑 → 漏洞子图；<0.5 误报 → 归档

**子图状态隔离**
- 独立本地状态：raw_intel、graph_relations、investigation_log、final_verdict、confidence_score
- 向主图仅返回三项：final_verdict、confidence_score、evidence_summary

### F3-2 子图 B：漏洞挖掘（Vuln-Hunter Subgraph）

**7 维记忆 Schema（Pydantic BaseModel）**
- 7个字段：target（目标）、code_paths（代码路径）、input_formats（输入格式）、poc_candidates（候选列表）、negative_evidence（负面证据）、verification_state（验证状态）、constraints（约束条件）
- 每轮迭代强制以 JSON Mode 输出，拒绝自由格式文本

**防遗忘机制**
- XML 标签硬隔离：`<memory_history>` 包裹历史快照、`<constraints>` 集中罗列约束、`<current_reasoning>` 隔离本轮推理
- 负面证据显式回注：失败路径以结构化数据追加到 negative_evidence，不依赖模型自主记忆

**迭代闭环节点**
- generate_poc → linter_check → sandbox_exec → extract_constraints → update_memory → check_convergence（循环/终止）
- 收敛条件：成功触发漏洞 OR 达到最大迭代次数（默认10轮）OR 所有路径耗尽

**向主图仅返回三项**：final_poc、is_vulnerable、exploit_chain

### F3-3 子图 C：响应执行（Responder Subgraph）

**剧本匹配与生成**
- YAML 剧本库（`src/orchestration/playbooks/`），覆盖10类常见事件类型（恶意 IP、横向移动、勒索软件、凭证泄露等）
- 优先规则匹配（无 LLM 调用）；无匹配时调用 LLM 生成定制剧本（Structured Output 约束格式）

**操作分级（L1-L5）**
- L1/L2：自动执行，仅写审计日志
- L3（防火墙规则变更/EDR策略）：单人审批，5分钟内响应
- L4（主机隔离/网络封禁/批量操作）：双人审批，15分钟内响应
- L5（全局阻断/关键系统变更）：安全主管 + 运维主管双人审批

**HITL 审批流**
- LangGraph `interrupt()` 机制在等待审批期间挂起子图，不占用线程
- 审批卡片通过企业微信/钉钉 Webhook 推送，Webhook 回调恢复子图执行
- 审批超时默认拒绝并升级告警

**向主图仅返回两项**：approval_id、execution_summary

---

## 2.6 F4：知识与工具层

### F4-1 GraphRAG 混合检索引擎

**Milvus 向量检索模块**
- 嵌入模型：BGE-large-zh-v1.5（768维稠密向量）
- 索引：IVF_FLAT（召回率优先）
- 知识库初始入库：MITRE ATT&CK、NVD CVE（近3年CVSS≥7.0）、AlienVault OTX 历史情报、内部历史应急响应报告
- 检索策略：Top-K=10，相似度阈值 ≥ 0.7
- 外部依赖：Milvus 2.4+（已由运维单独部署）

**Neo4j 图谱检索模块**
- 核心节点类型：APTGroup、Tool、Infrastructure、CVE、Campaign、IOC
- 核心关系类型：USES、OPERATES、HOSTS、EXPLOITS、ASSOCIATED_WITH
- 初始数据导入：MITRE ATT&CK STIX 数据（`scripts/import_attack_stix.py`）
- Cypher 查询：N跳邻居（最大3跳）、最短路径分析
- 外部依赖：Neo4j 5.x（已由运维单独部署）

**RRF 查询路由与结果融合**
- 两路检索通过 `asyncio.gather` 并发执行
- RRF 算法融合（k=60），无需训练参数
- 相似度 < 0.65 的结果过滤，追加外部威胁情报 API 兜底

### F4-2 统一 API 工具箱（Tool Registry）
- 装饰器注册模式：新增工具实现 Tool 接口后自动注册，无需修改 Agent 核心逻辑
- 覆盖6类工具：VirusTotal/微步在线（IOC查询）、AlienVault OTX（开源情报）、防火墙/SIEM/EDR（策略下发）、漏洞扫描器（漏洞查询）、Kafka/ES（消息队列/日志检索）、企业微信/钉钉（审批通知）
- 每个工具通过 JSON Schema 描述参数，供 LangChain Function Calling 使用

### F4-3 模型适配层（Model Adapter）
- 统一接口屏蔽云端 API（Claude Sonnet 5 / GPT-4o）与私有化部署（Qwen2.5-72B / Llama-3.1-70B vLLM）的差异
- 原型阶段：云端 API；架构稳定后切换至私有化部署，上层代码零修改
- 外部依赖：vLLM 0.6+（私有化推理服务，已由运维单独部署）

---

## 2.7 F5：执行与隔离层

### F5-1 静态语法预检器（PoC Linter）
- 三通道串行检查：语法验证（Python AST 解析）→ 导入白名单验证（requests/socket/json/re/time/sys 等）→ 危险调用拦截（os.system/subprocess.run/eval/exec 等）
- 结构化返回 `LinterResult`（Pydantic）：passed、error_type、error_detail、suggestion、line_number
- suggestion 字段由规则模板生成（"请添加 import requests"等），直接可读，降低 LLM 理解成本
- P99 延迟目标 < 5ms（纯 CPU 操作，无异步）

### F5-2 MicroVM 沙箱集群
- 原型阶段：Docker + SecComp Profile（`runtime/default`）+ AppArmor 加固
- 生产阶段：gVisor（`runtime: runsc`）用户态内核，每个 PoC 获得独立内核地址空间，阻断内核级逃逸
- 四个核心组件：代码编译环境（gcc/clang）、靶机运行环境、PoC 执行器、崩溃日志采集器（ASAN/Core Dump）
- 安全加固：网络隔离（仅 PoC 容器与靶机互通）、资源限制（CPU≤2核/内存≤1GB）、根文件系统只读、硬超时60秒、执行后立即销毁
- 沙箱容器池：预热5个空闲容器，冷启动延迟 < 125ms

### F5-3 HITL 熔断机制
- 5级操作分级（L1-L5），详见 F3-3
- 审批记录写入不可篡改的 Elasticsearch 审计日志
- 超时升级：规定时间内无响应，默认拒绝并通知上级安全负责人

---

## 2.8 F6：API 层与前端界面

### F6-1 FastAPI 后端服务
- 6 个核心 REST 端点：提交事件（POST /events）、查询事件状态（GET /events/{id}）、获取推理轨迹（GET /events/{id}/trace）、提交审批结果（POST /approvals/{id}）、运营指标（GET /dashboard/metrics）、知识库检索（GET /kb/search）
- OAuth 2.0 + JWT 认证（Token 有效期2小时 + Refresh Token）
- RBAC 权限模型：管理员 / 安全专家 / 分析师 / 审计员 四角色最小权限

### F6-2 前端界面（告警态势面板）
- 技术栈：React + Ant Design
- 4个核心页面：事件处理队列实时视图、Agent 推理轨迹可视化、审批待办列表、运营指标大屏（MTTR/告警量趋势/研判准确率）
- 仅消费 FastAPI 接口，不直接访问数据库

---

# 第三章 技术方案设计

## 3.1 核心技术选型汇总

| 类别 | 选型 | 版本要求 | 部署方 |
|------|------|---------|--------|
| 编排框架 | LangGraph | 1.0+ | 项目内置 |
| LLM 框架 | LangChain | 0.3+ | 项目内置 |
| 向量数据库 | Milvus | 2.4+ | 运维单独部署 |
| 图数据库 | Neo4j | 5.x | 运维单独部署 |
| 消息队列 | Apache Kafka | 3.x | 运维单独部署 |
| 日志检索 | Elasticsearch | 8.x | 运维单独部署 |
| 容器运行时 | Docker + Kubernetes | 24+ / 1.28+ | 运维单独部署 |
| 模型推理 | vLLM | 0.6+ | 运维单独部署 |
| 缓存/任务队列 | Redis | 7.x | 运维单独部署 |
| API 网关 | FastAPI | 0.100+ | 项目内置 |
| 任务调度 | Celery | 5.x | 项目内置 |
| 前端框架 | React + Ant Design | 18 / 5.x | 项目内置 |

**开发环境要求**：Python 3.11+、Node.js 18+、Docker 24+、8GB+ RAM（开发机）、NVIDIA GPU 24GB+ VRAM（本地模型推理可选）

---

## 3.2 关键技术方案要点

### 3.2.1 LangGraph 嵌套子图与状态隔离

**核心设计决策**：主图维护极简全局状态（8个控制字段），子图拥有独立本地状态，子图仅向主图回传精简结论，防止 Vuln-Hunter 7维记忆的数百条中间数据撑爆主图上下文窗口。

实现要点：
- 子图以 `compiled_subgraph` 形式注册为主图节点，LangGraph 原生隔离状态
- 入口映射函数（Entry Mapping）明确定义从主图状态提取哪些字段传入子图
- 子图内部错误通过 `error` 字段传回主图，不抛出异常至主图
- 超时控制在编译时配置（`recursion_limit` + 外层 `asyncio.wait_for`）

### 3.2.2 脱敏引擎性能优化

- 正则表达式全部预编译（模块加载时完成，运行时零开销）
- Kafka 消费采用批量模式（`max_poll_records=500`），减少 I/O 次数
- CPU 密集型规则匹配使用 `multiprocessing.Pool`，IO 等待使用 `asyncio`
- 热更新通过 `watchdog` 监听规则文件变更，重载规则不中断消费流程

### 3.2.3 GraphRAG 检索性能

- 两路检索（Milvus + Neo4j）通过 `asyncio.gather` 并发执行，消除串行等待
- 高频 IOC 查询结果写入 Redis 缓存（TTL 1小时），降低数据库压力
- Neo4j Cypher 查询使用参数化语句（防 Cypher 注入），N跳查询限制最大深度3跳
- RRF 融合为纯 Python 运算，< 1ms，不引入额外延迟

### 3.2.4 Vuln-Hunter 防遗忘三重保障

| 保障层 | 机制 | 防止的问题 |
|--------|------|-----------|
| Schema 约束 | Pydantic BaseModel + JSON Mode 强制结构化输出 | 模型输出自由文本，记忆字段缺失 |
| XML 标签隔离 | `<memory_history>/<constraints>/<current_reasoning>` 明确分区 | 注意力稀释，模型忽略早期约束 |
| 显式负面证据回注 | 失败路径以结构化数据追加 negative_evidence | 模型遗忘已排除路径，重复犯同类错误 |

### 3.2.5 沙箱安全分层

```
PoC 代码
  ↓ 层1：PoC Linter（语法/导入/危险调用静态拦截，P99 < 5ms）
  ↓ 层2：SecComp Profile（拦截危险系统调用，原型阶段）
  ↓ 层3：gVisor 用户态内核（独立内核地址空间，生产阶段）
  ↓ 层4：网络隔离（仅与靶机互通，无法访问外网/宿主机）
  ↓ 层5：资源限制（CPU≤2核，内存≤1GB，超时60s强制终止）
  ↓ 层6：生命周期销毁（执行后立即删除容器，无持久状态）
```

### 3.2.6 HITL 审批流与 LangGraph 中断

LangGraph `interrupt()` 机制：
- 响应子图执行到审批节点时调用 `interrupt()`，子图状态持久化，线程释放
- 审批卡片通过 Webhook 推送企业微信/钉钉
- 审批回调触发 `graph.resume(thread_id, update={approval_status: ...})`，子图从断点恢复
- 超时未响应：Celery 定时任务检测超时，写入 `approval_status=timeout`，触发升级流程

### 3.2.7 模型适配层切换策略

```python
# 原型阶段（云端 API）
adapter = ModelAdapter(provider="claude", model="claude-sonnet-5")

# 生产阶段（私有化部署，一行切换，上层代码零修改）
adapter = ModelAdapter(provider="vllm", model="qwen2.5-72b",
                       base_url="http://internal-vllm:8000")
```

适配层统一接口：`chat_completion(messages, schema=None, temperature=0.1)`，支持 Structured Output / JSON Mode 双模式。

---

## 3.3 项目目录结构（详细）

```
security-agent/
├── src/
│   ├── preprocessing/              # F1：预处理层
│   │   ├── consumer.py               #   Kafka 消费引擎
│   │   ├── sanitization/
│   │   │   ├── engine.py             #   SanitizationEngine（脱敏主类）
│   │   │   └── mask.py               #   掩码策略实现
│   │   ├── ioc_extractor/
│   │   │   └── extractor.py          #   IOCExtractor
│   │   └── rules/
│   │       └── default_rules.yaml    #   预置规则配置
│   ├── orchestration/              # F2/F3：编排与智能体层
│   │   ├── main_graph/
│   │   │   ├── state.py              #   MainGraphState TypedDict
│   │   │   ├── graph.py              #   主图装配与编译
│   │   │   └── nodes/
│   │   │       ├── entry.py
│   │   │       ├── orchestrator.py
│   │   │       └── aggregator.py
│   │   ├── subgraphs/
│   │   │   ├── investigation/
│   │   │   │   ├── state.py          #   InvestigationSubState
│   │   │   │   ├── graph.py          #   研判子图装配
│   │   │   │   ├── cti_analyst.py    #   情报专家 Agent
│   │   │   │   └── investigator.py   #   研判专家 Agent
│   │   │   ├── vuln_hunter/
│   │   │   │   ├── state.py          #   VulnHunterSubState
│   │   │   │   ├── memory.py         #   VulnHunterMemory Pydantic Schema
│   │   │   │   ├── graph.py          #   漏洞挖掘子图装配
│   │   │   │   └── poc_generator.py  #   PoC 约束驱动生成
│   │   │   └── responder/
│   │   │       ├── state.py          #   ResponderSubState
│   │   │       ├── graph.py          #   响应执行子图装配
│   │   │       ├── playbook_matcher.py
│   │   │       └── hitl_handler.py   #   LangGraph interrupt() 封装
│   │   ├── memory/
│   │   │   └── manager.py            #   MemoryManager（跨子图共享）
│   │   └── playbooks/
│   │       └── *.yaml                #   应急响应剧本库
│   ├── knowledge/                  # F4：知识与工具层
│   │   ├── graphrag/
│   │   │   ├── engine.py             #   GraphRAGEngine（查询路由 + RRF 融合）
│   │   │   ├── vector/
│   │   │   │   └── milvus_client.py  #   Milvus 封装
│   │   │   └── graph/
│   │   │       └── neo4j_client.py   #   Neo4j Cypher 封装
│   │   ├── tools/
│   │   │   ├── registry.py           #   Tool Registry（装饰器注册）
│   │   │   ├── threat_intel.py       #   VirusTotal/OTX 工具
│   │   │   ├── security_device.py    #   防火墙/SIEM/EDR 工具
│   │   │   └── notification.py       #   企业微信/钉钉审批推送
│   │   └── models/
│   │       └── adapter.py            #   ModelAdapter（云端/私有化切换）
│   ├── execution/                  # F5：执行与隔离层
│   │   ├── linter/
│   │   │   └── poc_linter.py         #   PoCLinter（三通道预检）
│   │   ├── sandbox/
│   │   │   ├── executor.py           #   SandboxExecutor（容器生命周期管理）
│   │   │   └── Dockerfile.sandbox    #   最小化沙箱镜像
│   │   └── harness/
│   │       └── crash_collector.py    #   崩溃日志采集（ASAN/Core Dump）
│   ├── api/                        # F6：API 层
│   │   ├── main.py                   #   FastAPI 应用入口
│   │   ├── routers/
│   │   │   ├── events.py
│   │   │   ├── approvals.py
│   │   │   └── dashboard.py
│   │   └── auth/
│   │       └── jwt_handler.py        #   OAuth 2.0 + JWT
│   └── common/
│       ├── config/
│       │   └── settings.py           #   Pydantic Settings（环境变量管理）
│       ├── logging/
│       │   └── logger.py             #   统一日志（含脱敏处理）
│       └── audit/
│           └── audit_logger.py       #   不可篡改审计日志（写入 ES）
├── tests/
│   ├── unit/                         #   单元测试（覆盖率目标 ≥ 90%）
│   ├── integration/                  #   集成测试（testcontainers）
│   └── e2e/                          #   端到端测试（Playwright + API）
├── scripts/
│   ├── healthcheck.sh
│   ├── ingest_knowledge.py           #   知识库入库脚本
│   └── import_attack_stix.py         #   MITRE ATT&CK STIX 导入
├── deployments/
│   ├── k8s/                          #   Kubernetes 编排文件
│   └── docker/
│       └── docker-compose.dev.yml    #   本地开发环境
├── frontend/                         #   React 前端
├── pyproject.toml
└── .github/workflows/ci.yml          #   CI/CD 流水线
```

---

# 第四章 项目排期与里程碑

## 4.1 总体时间规划

**总周期**：12 周（约 3 个月）| **开始时间**：2026 年 7 月 8 日（周一）| **结束时间**：2026 年 9 月 28 日（周五）

**开发策略**：先通后优（优先打通端到端数据链路，再逐模块优化）+ 依赖驱动排序（按模块依赖关系安排开发顺序）

---

## 4.2 阶段划分与关键路径

```
关键路径（Critical Path）：F0 → F1 → F2 → F3-1（研判子图） → F3-2（漏洞子图） → F3-3（响应子图） → 联调 → 生产加固

可并行开发：
- F4-1（GraphRAG）可与 F2（主图）并行（Week 1-3）
- F5-1（Linter）和 F5-2（沙箱）可与 F3-1（研判子图）并行（Week 3-5）
- F6（API + 前端）可在 Week 7 开始并行开发，与 F3-3（响应子图）同步
```

| 阶段 | 周期 | 核心交付物 | 依赖 | 里程碑 |
|------|------|----------|------|--------|
| 阶段零：基建与预处理 | Week 0-1 | F0 + F1 完成 | 无 | M0 |
| 阶段一：主图与编排 | Week 1-3 | F2 完成 + F4-1 完成 | 依赖 F1 | M1 |
| 阶段二：研判子图 | Week 3-5 | F3-1 完成 + F5-1/F5-2 并行完成 | 依赖 F2 + F4-1 | M2 |
| 阶段三：漏洞挖掘子图 | Week 5-8 | F3-2 完成 | 依赖 F2 + F5-1 + F5-2 | M3 |
| 阶段四：响应执行与联调 | Week 8-11 | F3-3 + F6 + 系统联调 | 依赖 F3-1 + F3-2 | M4 |
| 阶段五：生产加固 | Week 11-12 | 压测 + 安全审计 + 部署 | 依赖全部模块 | M5 |

---

## 4.3 详细周计划（Week-by-Week）

### Week 0-1：阶段零（基建与预处理）

**Week 0（7/8-7/14）：工程基建**
- Day 1-2：项目骨架初始化（F0-1）
  - 创建 `security-agent/` 目录结构
  - 配置 `pyproject.toml`、`pre-commit`、`.env.example`
  - 编写 Git 工作流文档（分支策略、Commit 规范）
- Day 3-4：本地开发环境（F0-2）
  - 编写 `docker-compose.dev.yml`（Kafka、Milvus standalone、Neo4j、Redis、ES）
  - 健康检查脚本 `scripts/healthcheck.sh`
  - 验证所有服务能正常启动
- Day 5：CI/CD 流水线（F0-3）
  - 配置 GitHub Actions：Lint → Test → Security Scan → Build
  - 集成 Ruff + mypy + pytest + Bandit + Safety

**Week 1（7/15-7/21）：预处理层核心**
- Day 1-2：Kafka 消费引擎（F1-5）
  - 实现 `aiokafka` 异步消费，Consumer Group 配置
  - Dead Letter Queue 实现，背压控制
- Day 3-4：脱敏引擎（F1-2 + F1-3）
  - 正则规则引擎（YAML 配置 + watchdog 热更新）
  - 掩码处理模块（3类掩码策略）
  - 单元测试覆盖率 ≥ 90%
- Day 5：IOC 提取器（F1-4）
  - 实现 IP/域名/哈希/URL 提取
  - 私有地址过滤，输出标准 JSON Schema
- Day 6-7：压测与优化
  - 压测脚本（Kafka 注入模拟消息）
  - 验证单实例 ≥ 2000 events/s，P99 < 50ms
  - 性能调优（正则预编译、批量消费、multiprocessing）

**Week 1 末交付**：M0 验收（预处理引擎就绪）
- [ ] 单元测试覆盖率报告 ≥ 90%
- [ ] P99 延迟压测数据 < 50ms
- [ ] PII 识别召回率评估 ≥ 99%
- [ ] IOC 提取准确率 ≥ 98%
- [ ] Kafka 消费集成验证 ≥ 2000 events/s

---

### Week 2-3：阶段一（主图与编排 + GraphRAG）

**Week 2（7/22-7/28）：LangGraph 主图**
- Day 1-2：主图状态与骨架（F2-1）
  - `MainGraphState` TypedDict 定义
  - 5个核心节点实现（entry、orchestrator、router、aggregator、ignore）
  - 子图桩函数（mock 返回固定测试数据）
  - 主图装配与编译
- Day 3-4：调度中枢 Agent（F2-2）
  - 规则兜底层实现（蜜罐命令、CVE 标签直接打分）
  - LLM 分类层（Pydantic Schema 约束 + 10 条 Few-shot）
  - 条件边路由函数
- Day 5-7：记忆管理器（F2-3）
  - MemoryManager 基础架构
  - Milvus + Neo4j 双写逻辑
  - 证据去重与 TTL 管理

**Week 3（7/29-8/4）：GraphRAG 引擎（并行）**
- Day 1-2：Milvus 向量检索（F4-1）
  - Milvus 客户端封装
  - 知识库初始入库脚本（MITRE ATT&CK、NVD CVE）
  - BGE-large-zh-v1.5 嵌入模型集成
- Day 3-4：Neo4j 图谱检索（F4-1）
  - Neo4j Cypher 封装
  - STIX 数据导入脚本 `import_attack_stix.py`
  - 核心关系类型建模验证
- Day 5-6：RRF 查询路由与融合（F4-1）
  - 两路检索并发执行（asyncio.gather）
  - RRF 算法实现（k=60）
  - Redis 缓存层（高频 IOC，TTL 1h）
- Day 7：端到端集成测试
  - 主图 + GraphRAG 联调
  - 用测试事件跑通全流程（含桩子图）

**Week 3 末交付**：M1 验收（编排基线通）
- [ ] 端到端跑通单条告警（含子图桩）
- [ ] 路由决策覆盖所有分支
- [ ] 审计日志全路径写入验证
- [ ] GraphRAG 检索召回率初步评估 ≥ 80%

---

### Week 4-5：阶段二（研判子图 + Linter/沙箱并行）

**Week 4（8/5-8/11）：研判子图核心**
- Day 1-2：情报专家 Agent（F3-1）
  - GraphRAG 调用封装
  - VirusTotal + AlienVault OTX 并发查询
  - Pydantic 情报卡片输出
- Day 3-4：研判专家 Agent（F3-1）
  - Chain-of-Thought Prompt 设计（5步推理）
  - Pydantic 研判结果输出
  - 置信度阈值逻辑（≥0.8 / 0.5-0.8 / <0.5）
- Day 5-6：子图状态隔离实现
  - `InvestigationSubState` 定义
  - 子图装配与编译
  - 向主图仅返回三项验证
- Day 7：集成测试
  - 构造 50 条带标注测试事件
  - 研判准确率评估

**Week 5（8/12-8/18）：Linter + 沙箱（并行）**
- Day 1-2：PoC Linter（F5-1）
  - 三通道预检实现（语法、导入白名单、危险调用）
  - `LinterResult` Pydantic Schema
  - P99 延迟压测 < 5ms
- Day 3-5：Docker 沙箱基础（F5-2）
  - `Dockerfile.sandbox` 最小化镜像
  - SandboxExecutor 生命周期管理
  - SecComp Profile + AppArmor 加固
  - 网络隔离 + 资源限制配置
- Day 6-7：崩溃日志采集（F5-2）
  - ASAN 报告采集
  - Core Dump 处理
  - 沙箱容器池预热机制

**Week 5 末交付**：M2 验收（研判能力上线）
- [ ] GraphRAG 检索召回率 ≥ 85%
- [ ] 研判准确率 ≥ 80%（专家盲评 50 条）
- [ ] 子图状态隔离验证（无泄漏至主图）
- [ ] Linter P99 延迟 < 5ms
- [ ] 沙箱基础功能验证（编译 + 执行 + 日志采集）

---

### Week 6-8：阶段三（漏洞挖掘子图）

**Week 6（8/19-8/25）：7 维记忆架构**
- Day 1-2：VulnHunterMemory Schema（F3-2）
  - Pydantic BaseModel 定义（7个字段）
  - XML 标签 Prompt 模板设计
  - JSON Mode 强制结构化输出测试
- Day 3-4：约束驱动生成（F3-2）
  - `generate_poc` 节点实现
  - 约束条件拼接 Prompt 逻辑
  - Few-shot PoC 示例库构建（按漏洞类型分类）
- Day 5-7：迭代闭环节点
  - `linter_check` → `sandbox_exec` → `extract_constraints` → `update_memory`
  - 收敛判断逻辑（成功/最大轮次/路径耗尽）
  - 负面证据显式回注实现

**Week 7（8/26-9/1）：子图装配与测试**
- Day 1-2：子图装配（F3-2）
  - `VulnHunterSubState` 定义
  - 子图节点连接与条件边
  - 最大迭代次数配置（默认 10 轮）
- Day 3-5：漏洞验证 Benchmark 测试
  - 构造标准漏洞测试集（10 类常见漏洞）
  - 记录每轮迭代过程与收敛轮次
  - PoC 生成成功率评估
- Day 6-7：防遗忘机制验证
  - 第 8-10 轮迭代约束保留验证
  - 负面证据不重复验证
  - Schema 强制约束测试

**Week 8（9/2-9/8）：优化与安全审计**
- Day 1-2：PoC 成功率优化
  - 扩充 Few-shot 示例库
  - 调整 Linter 白名单
  - 约束提取逻辑优化（路径归因）
- Day 3-4：沙箱安全审计（F5-2）
  - 构造恶意 PoC 测试集（含内核 exploit 尝试）
  - 验证 0 次逃逸
  - gVisor 生产环境升级方案文档
- Day 5-7：子图与主图联调
  - 研判子图 → 漏洞挖掘子图数据传递
  - 超时控制验证（600s）
  - 错误处理与回传

**Week 8 末交付**：M3 验收（漏洞验证闭环）
- [ ] PoC 生成成功率 ≥ 60%（Benchmark）
- [ ] 沙箱 0 逃逸验证
- [ ] 7 维记忆防遗忘验证（第 8-10 轮）
- [ ] Linter 拦截率 > 90%

---

### Week 9-11：阶段四（响应执行与系统联调）

**Week 9（9/9-9/15）：响应执行子图**
- Day 1-2：剧本匹配与生成（F3-3）
  - YAML 剧本库构建（10 类事件类型）
  - 规则匹配引擎（无 LLM 调用）
  - LLM 定制剧本生成（Structured Output）
- Day 3-4：操作分级与审批推送（F3-3）
  - L1-L5 操作分级逻辑
  - 企业微信/钉钉审批卡片推送（F4-2）
  - Webhook 回调接口（FastAPI）
- Day 5-7：HITL LangGraph interrupt 实现（F5-3）
  - `interrupt()` 挂起子图
  - Celery 定时任务检测超时
  - `resume()` 恢复执行
  - 审批记录写入 ES 审计日志

**Week 10（9/16-9/22）：API 与前端**
- Day 1-3：FastAPI 后端（F6-1）
  - 6 个核心 REST 端点实现
  - OAuth 2.0 + JWT 认证
  - RBAC 权限中间件
- Day 4-7：前端界面（F6-2）
  - React + Ant Design 脚手架
  - 4 个核心页面（事件队列、推理轨迹、审批列表、运营大屏）
  - API 对接与数据联调

**Week 11（9/23-9/29，前 5 天）：系统联调**
- Day 1-2：5 类联调测试场景
  - 场景 1：APT 攻击研判（预处理 → 主图 → 研判子图 → 响应子图）
  - 场景 2：漏洞利用验证（全链路含漏洞子图）
  - 场景 3：误报过滤（调度中枢噪音过滤）
  - 场景 4：HITL 审批拒绝（超时/驳回处理）
  - 场景 5：子图超时（强制终止 + 审计记录）
- Day 3-4：跨子图数据流验证
  - 主图状态裁剪验证（无污染）
  - 记忆管理器跨子图共享
  - 审计日志完整性核查
- Day 5：前端联调
  - API 端到端测试
  - 前端与后端数据格式对齐
  - 审批流前端演示

**Week 11 中期交付**：M4 验收（响应执行上线）
- [ ] 审批流端到端打通
- [ ] 5 类联调场景全部通过
- [ ] 响应时间（审批通过到操作完成）< 30s
- [ ] 前端 4 个页面功能完整

---

### Week 11-12：阶段五（生产加固）

**Week 11（9/23-9/29，后 2 天）：压力测试准备**
- Day 6-7：压测脚本与监控
  - Kafka 注入脚本（模拟 500 万条/日告警）
  - Prometheus + Grafana 监控配置
  - 压测环境搭建（K8s 集群）

**Week 12（9/30-10/4，仅前 5 个工作日）：生产加固**
- Day 1-2：压力测试
  - 预处理层吞吐量测试（≥ 20000 events/s 扩展后）
  - 端到端延迟测试（P99 < 30s）
  - 并发 50 事件处理测试
  - 72 小时稳定性测试启动
- Day 3：安全审计
  - SAST（Bandit + Semgrep）
  - 依赖漏洞扫描（Safety + pip-audit）
  - Prompt 注入测试（10 类攻击向量）
  - RBAC 权限越权测试
- Day 4：性能优化与 Bug 修复
  - 根据压测数据调优
  - 修复集成测试暴露的问题
  - 安全审计问题修复
- Day 5：部署准备与文档
  - Kubernetes 生产编排文件编写
  - 部署文档（环境要求、部署步骤、健康检查）
  - 运维手册（监控指标、告警规则、常见问题排查）

**Week 12 末交付**：M5 验收（生产环境就绪）
- [ ] 72h 稳定性测试通过（0 次重启、0 次数据丢失）
- [ ] 安全审计 0 个 High/Critical 问题
- [ ] Grafana 监控大屏上线
- [ ] K8s 生产部署文档完备
- [ ] MTTR 降低 ≥ 30%（与基线对比）

---

# 第五章 资源配置

## 5.1 人员组织与职责

### 推荐团队配置（最小可行团队）

| 角色 | 人数 | 职责 | 参与阶段 |
|------|------|------|---------|
| 技术负责人 / 架构师 | 1 | 架构设计、技术决策、代码评审、里程碑把控 | 全程 |
| LangGraph / AI Agent 开发工程师 | 2 | 编排层主图、三个子图、记忆管理器、模型适配层 | Week 2-11 |
| 安全工程师 | 1 | 脱敏引擎、Linter、沙箱加固、安全审计、HITL 审批流 | Week 1-12 |
| 后端工程师 | 1 | FastAPI 服务、工具箱集成、Kafka 消费、数据库客户端 | Week 1-11 |
| 前端工程师 | 1 | 态势大屏、审批卡片、推理轨迹可视化 | Week 10-12 |
| 测试工程师 | 1 | 单元/集成/E2E 测试框架搭建、性能基准测试、安全渗透测试 | Week 1-12（兼顾） |

> 说明：前端工程师可在 Week 1-9 期间协助后端开发；测试工程师应从 Week 1 开始同步搭建测试框架，确保各模块随开发进度完成测试。

---

### 按阶段人力投入

| 阶段 | 周期 | 主要投入角色 |
|------|------|------------|
| 阶段零 | Week 0-1 | 技术负责人 + 后端工程师 + 安全工程师 |
| 阶段一 | Week 1-3 | 技术负责人 + LangGraph 工程师（×2）+ 后端工程师 |
| 阶段二 | Week 3-5 | LangGraph 工程师（×2）+ 安全工程师（并行 Linter/沙箱） |
| 阶段三 | Week 5-8 | LangGraph 工程师（×2）+ 安全工程师 |
| 阶段四 | Week 8-11 | 全员（含前端工程师加入） |
| 阶段五 | Week 11-12 | 技术负责人 + 安全工程师 + 测试工程师 |

---

## 5.2 基础设施资源

### 开发环境（每位工程师本地）

| 资源 | 配置要求 |
|------|---------|
| 操作系统 | macOS / Linux（Windows + WSL2 可接受） |
| CPU | 8 核以上 |
| 内存 | 32GB 以上（本地运行 LLM 需 64GB+） |
| 存储 | SSD 500GB 以上 |
| GPU（可选） | NVIDIA GPU 24GB+ VRAM（本地 Qwen 推理用；原型阶段可用云端 API 替代） |

### 共享测试环境（团队共用）

| 服务 | 规格 | 备注 |
|------|------|------|
| Kafka | 1 台 4核8GB | 单节点，测试用 |
| Milvus standalone | 1 台 8核16GB SSD | 含 etcd + MinIO |
| Neo4j Community | 1 台 8核16GB | 开发测试用 |
| Redis | 1 台 2核4GB | Celery Broker + 缓存 |
| Elasticsearch | 1 台 8核16GB SSD | 日志 + 审计 |
| LLM 推理服务 | 1 台 A100 80GB（或云端 API） | 原型阶段用云端 API 替代 |
| CI/CD Runner | GitHub Actions 云端 Runner | 免费额度 or 自建 |

> 以上中间件由运维单独部署，开发团队仅需提供配置参数。

### 生产环境（K8s 集群，由运维规划）

| 组件 | 建议规格 | 节点数 |
|------|---------|--------|
| 预处理层（Consumer） | 4核8GB | ×3（水平扩展） |
| 编排层（LangGraph） | 8核16GB | ×2（高可用） |
| 执行层（沙箱池） | 4核8GB | ×5（预热容器池） |
| FastAPI 服务 | 4核8GB | ×2（高可用） |
| Milvus 集群 | 16核32GB SSD | ×3（2数据节点+1代理） |
| Neo4j Enterprise | 16核32GB SSD | ×3（主从复制） |
| vLLM 推理服务 | A100 80GB | ×2（双卡并行） |

---

## 5.3 外部依赖服务清单

以下服务需在项目开始前确认可用性，由运维或采购团队负责对接：

| 服务 | 用途 | 依赖方 |
|------|------|--------|
| Kafka（已部署） | 告警消息总线 | 预处理层 F1 |
| Milvus（已部署） | 向量知识库 | F4-1、F2-3 |
| Neo4j（已部署） | 安全知识图谱 | F4-1 |
| Redis（已部署） | Celery Broker + 检索缓存 | F3-3（HITL）+ F4-1 |
| Elasticsearch（已部署） | 审计日志、事件检索 | 全模块 |
| VirusTotal API Key | IOC 威胁评分 | F4-2 |
| AlienVault OTX API Key | 开源威胁情报 | F4-2 |
| 企业微信/钉钉 应用 | HITL 审批推送 | F3-3、F5-3 |
| vLLM 推理服务（私有化） | LLM 推理（生产阶段） | 模型适配层 |
| gVisor 运行时（生产） | 沙箱强隔离 | F5-2 |
| KMS 密钥管理服务 | 敏感数据加密 | 安全设计 |

---

# 第六章 测试方案

## 6.1 测试策略总览

采用经典测试金字塔：**单元测试（60%）+ 集成测试（25%）+ E2E 测试（10%）+ 专项测试（5%）**。

**核心原则**：
- 测试框架与业务代码同步开发，不在模块完成后补测试
- 使用 `testcontainers` 在 CI 中自动启动真实数据库实例
- 性能基准测试在独立压测环境中执行

---

## 6.2 单元测试（覆盖率目标 ≥ 90%）

**F1 预处理层**
- SanitizationEngine：PII 掩码各类规则（手机/邮箱/密码）、边界条件、重叠规则处理
- IOCExtractor：IP/域名/哈希/URL 提取、私有 IP 过滤、格式边界
- 工具：pytest + unittest.mock

**F2 编排层**
- 路由决策函数：各类事件特征 → 正确路由目标
- 调度中枢分类逻辑：Mock LLM 响应，验证 Pydantic Schema 约束

**F5 执行层**
- PoCLinter：语法验证、导入白名单、危险调用拦截

---

## 6.3 集成测试

**F3 研判子图**
- 测试数据集：50 条带标注事件（真阳性 30 / 误报 15 / 良性 5）
- 验收指标：研判准确率 ≥ 80%
- 使用 testcontainers 启动真实 Milvus + Neo4j

**F3 Vuln-Hunter 子图**
- 标准漏洞测试集：10 类常见漏洞（SQLi/XSS/SSRF/Buffer Overflow 等）
- 记录：成功轮次、迭代次数、PoC 有效性
- 防遗忘验证：第 8-10 轮 negative_evidence 包含前序失败路径

**F4 GraphRAG**
- 向量检索 Top-10 召回验证（相似度 ≥ 0.7）
- 图谱 N 跳查询（1/2/3 跳结果正确）
- RRF 融合排序与手工计算一致性

---

## 6.4 E2E 测试（5 类联调场景）

| 场景 | 路径 | 验证重点 |
|------|------|---------|
| 场景 1：APT 研判 | 预处理→主图→研判子图→响应子图 | GraphRAG 情报检索 + 审批流 |
| 场景 2：漏洞验证 | 全链路含漏洞子图 | 7 维记忆迭代 + 沙箱执行 |
| 场景 3：误报过滤 | 预处理→主图→忽略节点 | 调度中枢噪音过滤 |
| 场景 4：审批拒绝 | 响应子图→审批等待→驳回 | HITL 超时与驳回处理 |
| 场景 5：子图超时 | 研判子图执行超时 | 主图强制终止 + 审计记录 |

---

## 6.5 专项安全测试（Week 12）

| 测试项 | 通过标准 |
|--------|---------|
| SAST 扫描（Bandit + Semgrep） | 0 个 High/Critical 问题 |
| 依赖漏洞扫描（Safety） | 0 个已知高危 CVE |
| 沙箱逃逸测试 | 构造恶意 PoC（含内核 exploit），验证 0 次逃逸 |
| Prompt 注入测试 | 10 类注入向量全部被检测过滤 |
| RBAC 越权测试 | 低权限角色访问高权限 API 全部返回 403 |
| 敏感数据泄露测试 | Agent 输出中 0 次明文 PII/密码泄露 |
| TLS 配置检查（testssl.sh） | TLS 1.2+ 且无弱加密套件 |

---

## 6.6 性能基准测试（Week 12）

| 测试项 | 通过标准 |
|--------|---------|
| 预处理层吞吐量 | 10 实例扩展后 ≥ 20000 events/s |
| 端到端研判延迟 | 100 条高优先级告警 P99 < 30 秒 |
| 并发 50 事件处理 | CPU ≤ 80%，无死锁 |
| 72h 稳定性测试 | 0 次容器重启，0 条消息丢失 |

---

# 第七章 风险管控与应急预案

## 7.1 技术风险识别

| 风险项 | 概率 | 影响 | 应对策略 | 责任人 |
|--------|------|------|---------|--------|
| **风险 1：LLM 推理延迟过高** | 中 | 高 | ① 研判子图情报查询并发化（asyncio.gather）<br>② Redis 缓存同 IOC 24h 复用<br>③ 规则兜底层降低无效 LLM 调用 | 技术负责人 + LangGraph 工程师 |
| **风险 2：GraphRAG 召回质量不足** | 中 | 中 | ① 优先确保 MITRE ATT&CK + NVD CVE 完整入库<br>② 调整 Top-K（10→20）和相似度阈值（0.7→0.65）<br>③ 外部威胁情报 API 兜底 | 后端工程师 + 安全工程师 |
| **风险 3：Vuln-Hunter PoC 成功率低** | 高 | 中 | ① 构建 Few-shot PoC 示例库（按漏洞类型分类）<br>② 扩充 Linter 白名单<br>③ 约束提取逻辑优化（路径归因）<br>④ 迭代 5 轮未成功触发人工介入 | LangGraph 工程师 + 安全工程师 |
| **风险 4：沙箱安全逃逸** | 低 | 极高 | ① 原型阶段：Docker + SecComp Profile<br>② 生产阶段：强制 gVisor 用户态内核<br>③ 网络严格隔离（仅靶机互通）<br>④ 每季度红队演练 | 安全工程师 |
| **风险 5：外部 API 依赖中断** | 中 | 中 | ① Redis 缓存降低对威胁情报 API 的依赖<br>② 关键服务双重对接（VirusTotal + OTX）<br>③ 降级策略：API 失败时仅返回本地知识库结果 | 后端工程师 |

---

## 7.2 应急预案矩阵

| 故障场景 | 检测方式 | 应急措施 | 恢复时间目标（RTO） |
|---------|---------|---------|-------------------|
| Kafka Consumer Lag > 10000 | Prometheus 告警 | ① 立即扩容 Consumer 实例（自动 HPA）<br>② 临时降低非关键告警采集频率 | 15 分钟 |
| LLM API 错误率 > 5% | AlertManager 告警 | ① 云端 API 切换区域<br>② 私有化 vLLM 重启服务 | 10 分钟 |
| 沙箱容器崩溃率 > 10% | 监控大屏实时显示 | ① 检查沙箱容器池健康状态<br>② 重启沙箱节点<br>③ 临时降低 PoC 并发执行数 | 20 分钟 |
| Neo4j / Milvus 服务中断 | 健康检查失败 | ① 切换至备用节点（主从复制）<br>② 临时降级为纯向量检索或纯图谱检索 | 30 分钟 |
| HITL 审批超时堆积 | Celery 定时任务检测 | ① 升级告警至上级安全负责人<br>② 临时降低审批超时时间（L3: 5min → 3min） | 即时通知 |

---

## 7.3 回滚策略

**分阶段回滚原则**：
- **Week 0-2（预处理 + 主图）**：Git 分支回滚 + Docker 镜像回退
- **Week 3-8（子图开发）**：子图桩函数替代新子图，主图保持稳定
- **Week 9-11（联调 + 前端）**：Feature Flag 控制新功能开关
- **Week 12（生产）**：Kubernetes 滚动更新 + 旧版本镜像保留 7 天

**回滚触发条件**：
- 单元测试覆盖率 < 85%
- 集成测试失败率 > 10%
- 性能基准测试未达标（P99 延迟超标 50%）
- 安全审计发现 High/Critical 问题且 24 小时内无法修复

---

# 第八章 上线、运维与迭代计划

## 8.1 上线策略（灰度发布）

**灰度发布计划（Week 12 末 → Week 13）**

| 阶段 | 流量比例 | 持续时间 | 观察指标 | 回滚条件 |
|------|---------|---------|---------|---------|
| 灰度 1 | 5% 真实告警 | 24 小时 | 错误率、延迟、研判准确率 | 错误率 > 1% 或延迟 P99 > 45s |
| 灰度 2 | 20% 真实告警 | 48 小时 | 同上 + 吞吐量、资源利用率 | 错误率 > 0.5% 或 CPU > 85% |
| 灰度 3 | 50% 真实告警 | 72 小时 | 同上 + MTTR 对比 | MTTR 未降低或用户投诉 > 3 次 |
| 全量上线 | 100% | - | 持续监控 7 天 | 无回滚条件时正式切流 |

**回滚 SOP**：
1. 立即通知技术负责人与运维团队
2. Kubernetes 回滚至前一版本（`kubectl rollout undo`）
3. 验证旧版本服务恢复正常（健康检查 + 手工测试）
4. 事后复盘会议（24 小时内）

---

## 8.2 监控体系

### 8.2.1 Prometheus + Grafana 监控大屏

**系统层指标**
- Kafka Consumer Lag（分 Topic 监控）
- 各 Agent 平均推理延迟（P50/P95/P99）
- 沙箱执行成功率 / 超时率 / 崩溃率
- GraphRAG 检索平均延迟
- LLM API 调用成功率 / Token 消耗速率

**业务层指标**
- 事件处理吞吐量（events/min）
- 研判准确率（以人工抽样复核为基准）
- MTTR（平均事件响应时间）
- 审批通过率 / 驳回率
- Vuln-Hunter PoC 成功率（按迭代轮次分布）

### 8.2.2 AlertManager 告警规则

| 告警条件 | 严重级别 | 通知渠道 |
|---------|---------|---------|
| Kafka Consumer Lag > 10000 持续 5 分钟 | Critical | 电话 + 企业微信 |
| LLM API 错误率 > 5% 持续 2 分钟 | Warning | 企业微信 |
| 沙箱容器崩溃率 > 10% | Warning | 企业微信 |
| 主图处理队列积压 > 1000 | Warning | 企业微信 |
| 任意 Pod 重启次数 > 3 次/小时 | Critical | 电话 + 企业微信 |

---

## 8.3 SLA 承诺

| 指标 | 目标值 | 测量方式 |
|------|--------|---------|
| 服务可用性 | ≥ 99.5%（月均） | Uptime 监控（排除计划维护） |
| 端到端研判延迟 | P99 < 30 秒 | Prometheus 分位数统计 |
| 预处理层吞吐量 | ≥ 20000 events/s（扩展后） | Kafka 消费监控 |
| MTTR 降低幅度 | ≥ 30%（相比基线） | 事件处理时间戳差值统计 |
| 数据脱敏准确率 | PII 召回率 ≥ 99% | 定期抽样评估（每月 100 条） |

---

## 8.4 迭代路线图（未来 6 个月）

### 8.4.1 短期优化（1-2 个月）

**v1.2（Week 13-16）：模型切换与性能优化**
- 私有化部署 Qwen2.5-72B 替代云端 API
- GraphRAG 召回率优化至 90%+（扩充知识库）
- Vuln-Hunter PoC 成功率提升至 75%+（Few-shot 示例库扩充）
- 前端界面体验优化（实时推理轨迹、审批移动端适配）

**v1.3（Week 17-20）：多模态扩展**
- 接入图片类 IOC（恶意截图、钓鱼邮件图片）
- 支持 PDF 威胁报告自动解析入库
- Agent 推理过程可视化升级（流程图动画）

### 8.4.2 中期演进（3-6 个月）

**v2.0：闭环响应自动化**
- 新增"响应验证子图"：验证响应动作是否生效（如防火墙规则是否真正封禁）
- SOAR 平台对接：与 Splunk Phantom / Palo Alto Cortex XSOAR 集成
- 自定义剧本可视化编排器（拖拽式剧本设计）

**v2.1：多租户支持**
- 按业务单元隔离告警与知识库
- 差异化审批流（不同业务单元对应不同审批人）
- 成本核算与 Token 消耗统计（按租户）

---

**文档结束**

> **交付说明**：本开发计划覆盖项目从初始化到生产上线的完整 12 周周期，各章节对功能模块、技术方案、排期、资源、测试、风险、运维均有详细规划。外部中间件（Kafka、Milvus、Neo4j、Redis、ES、vLLM）由运维单独部署，项目团队仅需提供配置参数与接口对接。

> **版本信息**：v1.0 | 2026年7月6日 | 基于《安全AI_Agent项目开发文档 v1.1》制定
