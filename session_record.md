# 开发会话记录

> 日期：2026年7月6日
> 基于文档：《安全AI_Agent项目开发文档 v1.1》
> 开发计划：《安全AI_Agent开发计划_v1.1.md》

---

## 一、会话对话摘要

### 用户请求
1. 查看项目开发文档（v1.0），生成详细开发计划
2. 文档更新至 v1.1 后，重新生成包含 8 个章节的详细开发计划
3. 根据《安全AI_Agent开发计划_v1.1.md》，一步步完成项目开发工作
4. 保存本次会话记录

### AI 执行过程
- 读取并分析了 `安全AI_Agent项目开发文档.md`（v1.1，1505 行）
- 生成了 `安全AI_Agent开发计划_v1.1.md`（1072 行，8 个章节完整）
- 按计划从阶段零开始逐步实施，创建完整项目骨架与核心模块

---

## 二、已创建文件清单

### 配置与基础设施
| 文件路径 | 说明 |
|---------|------|
| `pyproject.toml` | Python 3.11+ 项目配置，全量依赖声明 |
| `.env.example` | 环境变量模板（LLM/Kafka/数据库/审批Webhook等） |
| `.pre-commit-config.yaml` | Ruff + mypy + Bandit 代码质量检查 |
| `.github/workflows/ci.yml` | CI/CD：Lint → Security → Test → Build |
| `deployments/docker/docker-compose.dev.yml` | 本地开发依赖（Kafka/Milvus/Neo4j/Redis/ES） |
| `scripts/healthcheck.sh` | 依赖服务健康检查脚本 |

### 公共模块 (`src/common/`)
| 文件路径 | 说明 |
|---------|------|
| `src/common/config/settings.py` | Pydantic Settings 配置管理，环境变量加载 |
| `src/common/logging/logger.py` | structlog 结构化日志 + PII 自动脱敏 |
| `src/common/audit/audit_logger.py` | Elasticsearch 不可篡改审计日志 |

### 预处理层 F1 (`src/preprocessing/`)
| 文件路径 | 说明 |
|---------|------|
| `src/preprocessing/rules/default_rules.yaml` | 9 条脱敏规则（密码/API Key/手机/邮件/身份证/哈希） |
| `src/preprocessing/sanitization/mask.py` | 掩码策略实现（重叠 span 优先级处理） |
| `src/preprocessing/sanitization/engine.py` | 脱敏引擎（线程安全 + watchdog 热更新） |
| `src/preprocessing/ioc_extractor/extractor.py` | IOC 提取（IP/域名/哈希/URL，私有地址过滤） |
| `src/preprocessing/consumer.py` | aiokafka 异步消费引擎 + Dead Letter Queue |

### 编排层 F2 (`src/orchestration/main_graph/`)
| 文件路径 | 说明 |
|---------|------|
| `src/orchestration/main_graph/state.py` | MainGraphState TypedDict（8字段极简状态） |
| `src/orchestration/main_graph/nodes/entry.py` | 入口节点（Schema 校验 + 审计日志） |
| `src/orchestration/main_graph/nodes/orchestrator.py` | 调度中枢（规则兜底 + LLM 分类 + Few-shot） |
| `src/orchestration/main_graph/nodes/aggregator.py` | 聚合节点 + 忽略节点 |
| `src/orchestration/main_graph/graph.py` | 主图装配（含子图桩函数） |

### 知识层 F4 (`src/knowledge/`)
| 文件路径 | 说明 |
|---------|------|
| `src/knowledge/models/adapter.py` | 统一 LLM 接口（Claude/OpenAI/vLLM 一键切换） |
| `src/knowledge/graphrag/vector/milvus_client.py` | Milvus 向量检索（Top-K=10，相似度≥0.65过滤） |
| `src/knowledge/graphrag/graph/neo4j_client.py` | Neo4j 图谱检索（APOC N 跳邻居查询） |
| `src/knowledge/graphrag/engine.py` | GraphRAG 融合引擎（并发检索 + RRF + Redis 缓存） |

### 执行层 F5 (`src/execution/`)
| 文件路径 | 说明 |
|---------|------|
| `src/execution/linter/poc_linter.py` | PoC 静态预检（语法/导入白名单/危险调用，目标P99<5ms） |
| `src/execution/sandbox/executor.py` | Docker 沙箱执行器（SecComp + 超时 + 立即销毁） |

### 子图层 F3 (`src/orchestration/subgraphs/`)
| 文件路径 | 说明 |
|---------|------|
| `investigation/state.py` | 研判子图状态定义 |
| `investigation/cti_analyst.py` | 情报专家 Agent（VirusTotal + OTX + GraphRAG） |
| `investigation/investigator.py` | 研判专家 Agent（CoT 5步推理 + Pydantic 约束输出） |
| `investigation/graph.py` | 研判子图装配 |
| `vuln_hunter/memory.py` | 7维记忆 Schema（VulnHunterMemory Pydantic Model） |
| `vuln_hunter/state.py` | Vuln-Hunter 子图状态 |
| `vuln_hunter/poc_generator.py` | PoC 生成→Linter→沙箱→约束提取→防遗忘迭代闭环 |
| `vuln_hunter/graph.py` | Vuln-Hunter 子图装配（最大 10 轮迭代） |
| `responder/state.py` | 响应执行子图状态 |
| `responder/playbook_matcher.py` | 剧本匹配器（规则优先 + LLM兜底 + L1-L5分级） |
| `responder/hitl_handler.py` | HITL 审批流（LangGraph interrupt + Webhook推送） |
| `responder/graph.py` | 响应执行子图装配 |

### API 层 F6
| 文件路径 | 说明 |
|---------|------|
| `src/api/main.py` | FastAPI 主入口（事件提交/查询/健康检查接口） |

### 测试
| 文件路径 | 说明 |
|---------|------|
| `tests/unit/preprocessing/test_sanitization.py` | 脱敏引擎单元测试（密码/手机/邮件/无误报） |

---

## 三、关键架构决策记录

| 决策点 | 选择 | 原因 |
|--------|------|------|
| 主图状态极简化 | 仅 8 个控制字段 | 防止 Vuln-Hunter 7维记忆撑爆主图上下文 |
| 子图状态隔离 | 子图仅向主图回传 3 项 | 保持主图轻量，避免中间数据泄漏 |
| 脱敏优先级 | credential > pii > hash | 密码类字段最高优先级防泄漏 |
| RRF 融合参数 | k=60 | 标准参数，无需训练，两路检索平衡融合 |
| 沙箱安全分层 | Linter + SecComp + gVisor | 多层防御，原型用 SecComp，生产用 gVisor |
| LLM 调用封装 | 统一 ModelAdapter | 一行代码切换云端/私有化，上层零修改 |
| 审批挂起机制 | LangGraph interrupt() | 等待期间不占用线程，节省资源 |

---

## 四、待完成工作（按优先级）

### 立即可做
- [ ] 更多单元测试：IOC 提取器、PoC Linter、GraphRAG
- [ ] 集成测试：testcontainers + 真实 Milvus/Neo4j
- [ ] 剧本库 YAML 示例文件（`src/orchestration/playbooks/*.yaml`）
- [ ] 沙箱 Dockerfile（`deployments/docker/Dockerfile.sandbox`）
- [ ] `.gitignore` 文件

### 短期（Week 2-3）
- [ ] 主图替换子图桩为真实子图
- [ ] FastAPI 完整路由：审批回调、推理轨迹、运营大屏
- [ ] OAuth 2.0 + JWT 认证中间件
- [ ] RBAC 权限模型（4个角色）

### 中期（Week 4-8）
- [ ] 知识库入库脚本（MITRE ATT&CK、NVD CVE）
- [ ] 工具箱集成（VirusTotal/防火墙/SIEM/EDR）
- [ ] React 前端界面
- [ ] Kubernetes 生产编排文件

---

## 五、快速启动命令

```bash
# 1. 安装依赖
pip install -e ".[dev]"

# 2. 启动本地依赖服务
docker compose -f deployments/docker/docker-compose.dev.yml up -d

# 3. 检查服务健康
bash scripts/healthcheck.sh

# 4. 配置环境变量
cp .env.example .env
# 编辑 .env，填入 ANTHROPIC_API_KEY（或 OPENAI_API_KEY）

# 5. 运行单元测试
pytest tests/unit/ -v

# 6. 启动 API 服务
python -m src.api.main
# 访问 http://localhost:8000/docs 查看 API 文档

# 7. 提交测试事件
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{"sanitized_text":"CVE-2024-1234 exploit from 203.0.113.5","iocs":{"ips":["203.0.113.5"]}}'
```

---

## 六、技术债务与注意事项

1. **主图子图桩** — `orchestration/main_graph/graph.py` 中的 `investigation_stub` 和 `vuln_hunter_stub` 是临时桩函数，Week 3-5 需替换为真实子图
2. **FastAPI 认证** — `api/main.py` 当前未启用 JWT 鉴权，生产前必须加入
3. **沙箱网络** — `executor.py` 中的 `sandbox_network` 需在 Docker 中提前创建: `docker network create sandbox-net`
4. **gVisor** — 原型阶段用 SecComp，生产阶段需运维在 K8s 节点安装 gVisor runtime
5. **Milvus 嵌入** — `milvus_client.py` 插入时需提前生成 768 维向量（BGE-large-zh-v1.5），当前未包含嵌入模型调用
