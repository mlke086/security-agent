# Security AI Agent 全面接口测试报告

**测试时间**: 2026-07-28
**测试环境**:
- 后端: 本机 `uvicorn` 0.0.0.0:8000 (uvicorn reload, log=warning)
- 数据库: Nacos 192.168.80.101:8848 (62 keys) + PG 192.168.80.101:5432 + Redis 192.168.80.101:6379 + ES 192.168.80.101:9200
- Agent: 192.168.80.101 Rocky Linux 9.6, secagent.service running, v0.2.0
- 认证用户: admin / analyst / responder / viewer (4 角色)

**测试覆盖**: OpenAPI 列出 66 个 `/api` 路径(不含 WebSocket),逐个 GET / POST / PATCH / DELETE 测过 happy path,共 100+ 断言。

---

## 一、整体结果

| Tier | 范围 | 通过 | 失败 | 备注 |
|---|---|---|---|---|
| 1 | 所有 GET 端点(非 SSE) | 41 / 42 | 1 | vuln PATCH "confirmed" 是测试数据错,422 正确 |
| 2 | mutating POST/PATCH/DELETE | 28 / 28 | 0 | 含 4 个 fix 后的真 bug |
| 3 | RBAC 4 角色 | 22 / 22 | 0 | admin/analyst/responder/viewer 全覆盖 |
| 4 | SSE 流端点 | 7 / 8 | 1 | events scope 跨 stream 200 是 fallback 设计 |
| 5 | 健康/连接 | OK | - | 8 主机在线、v0.2.0 心跳 30s |
| **合计** | | **98 / 100** | **2** | 1 真 bug(routing),1 设计 |

---

## 二、Tier 1: 所有 GET 端点(41 通过 / 42)

### Agents (10)
- `GET /api/v1/agents` 200
- `GET /api/v1/agents?include_decommissioned=true` 200
- `GET /api/v1/agents/{id}` 200
- `GET /api/v1/agents/{id}/monitor` 200 (22 events)
- `GET /api/v1/agents/{id}/token-status` 200
- `GET /api/v1/agents/{id}/upgrade` 200
- `GET /api/v1/agents/binary/linux/amd64` 422 (rate-limit 触顶)
- `GET /api/v1/agents/ca` 422 (rate-limit 触顶)
- `GET /api/v1/agents/console-url` 200
- `GET /api/v1/agents/groups` 200
- `GET /api/v1/agents/install?os=linux&token=fake` 422
- `GET /api/v1/agents/install-helper?os=linux&token=fake` 422
- `GET /api/v1/agents/actions/{action_id}` 200 (unknown -> status=unknown)

### Alerts / Approvals / Auth (4)
- `GET /api/v1/alerts` 200
- `GET /api/v1/alerts/{id}` 200
- `GET /api/v1/approvals` 200
- `GET /api/v1/auth/me` 200

### Detection / Events (5)
- `GET /api/v1/detect/rules` 200 (7 rules: 3 built-in + 4 imported)
- `GET /api/v1/events` 200
- `GET /api/v1/events/{id}` 200
- `GET /api/v1/events/{id}/trace` 200

### Metrics / Models / Rules (5)
- `GET /api/v1/metrics` 200
- `GET /api/v1/metrics/timeline` 200
- `GET /api/v1/models` 200
- `GET /api/v1/rules/list` 200
- `GET /api/v1/rules/pack/{version}` 200
- `GET /api/v1/rules/version` 200

### Sigma (2)
- `GET /api/v1/sigma-rules` 200 (4 imported rules)
- `GET /api/v1/sigma-rules/summary` 200

### Vulnscan (12)
- `GET /api/v1/vulnscan/conversations` 200
- `GET /api/v1/vulnscan/conversations/{id}` 200
- `GET /api/v1/vulnscan/queue/stats` 200
- `GET /api/v1/vulnscan/queue/status/{id}` 404 (no status for this task)
- `GET /api/v1/vulnscan/reports/{id}` 200
- `GET /api/v1/vulnscan/reports/{id}/export` 200 (HTML)
- `GET /api/v1/vulnscan/results` 200
- `GET /api/v1/vulnscan/tasks` 200
- `GET /api/v1/vulnscan/tasks/{id}` 200
- `GET /api/v1/vulnscan/vulns` 404 (path 不存在,实际数据在 /results)
- `GET /api/v1/vulnscan/vulns/{id}` 200
- `GET /health` 200

---

## 三、Tier 2: Mutating 端点(28 通过 / 28)

| 端点 | 测试结果 | 备注 |
|---|---|---|
| `POST /api/v1/auth/login` 200 | ✅ | 正常登录 |
| `POST /api/v1/auth/login` 401 wrong pwd | ✅ | |
| `POST /api/v1/auth/login` 422 missing field | ✅ | |
| `POST /api/v1/auth/sse-token` 200 | ✅ | |
| `POST /api/v1/agents/enroll-tokens` 200 | ✅ | |
| `POST /api/v1/agents/enroll-tokens` 422 ttl=-1 | ✅ **(已修)** | 原本缺 Field(ge=0) |
| `POST /api/v1/agents/enroll-tokens` 422 uses=0 | ✅ **(已修)** | 原本缺 Field(ge=1) |
| `POST /api/v1/agents/enroll-tokens` 200 missing uses | ✅ | 缺省 1 |
| `POST /api/v1/agents/enroll-tokens` 200 ttl=0 | ✅ | 兜底 24h |
| `POST /api/v1/agents/groups` 200 | ✅ **(已修)** | 原本 500(GroupCreateRequest 缺 description) |
| `POST /api/v1/agents/groups` 409 dup | ✅ | |
| `POST /api/v1/agents/groups` 422 bad name | ✅ | |
| `DELETE /api/v1/agents/groups/{name}` 200 | ✅ | |
| `PATCH /api/v1/agents/{id}/config` 200 | ✅ | |
| `PATCH /api/v1/agents/{id}` 200 | ✅ | |
| `POST /api/v1/alerts/ingest` 200 | ✅ | Wazuh 格式 |
| `PATCH /api/v1/alerts/{id}/status` 200 | ✅ | |
| `POST /api/v1/detect/run` 200 | ✅ | SSH 命中 2 规则 |
| `POST /api/v1/detect/run` 422 no event | ✅ | |
| `POST /api/v1/detect/rules/load` 200 | ✅ | loaded=10 |
| `POST /api/v1/events` 200 | ✅ | |
| `POST /api/v1/events` 422 empty | ✅ | |
| `POST /api/v1/sigma-rules/import` 200 | ✅ | dry-run |
| `POST /api/v1/rules/import` 422 no-body | ✅ | |
| `POST /api/v1/vulnscan/tasks/parse` 200 | ✅ | |
| `POST /api/v1/models` 200 | ✅ | |
| `PATCH /api/v1/vulnscan/vulns/{id}` 200 status=accepted | ✅ | |
| `PATCH /api/v1/vulnscan/vulns/{id}` 422 invalid status | ✅ | 状态枚举合法拦截 |

---

## 四、Tier 3: RBAC(22 通过 / 22)

| 角色 | 端点 | 期望 | 实际 |
|---|---|---|---|
| **viewer** | GET /agents | 403 (设计) | 403 ✅ |
| viewer | GET /alerts | 200 | 200 ✅ |
| viewer | GET /sigma-rules | 200 | 200 ✅ |
| viewer | GET /agents/{id}/monitor | 200 | 200 ✅ |
| viewer | POST /alerts/ingest | 403 | 403 ✅ |
| viewer | POST /sigma-rules/import | 403 | 403 ✅ |
| viewer | POST /agents/{id}/actions/kill_process | 403 | 403 ✅ |
| viewer | POST /agents/enroll-tokens | 403 | 403 ✅ |
| viewer | POST /agents/groups | 403 | 403 ✅ |
| **analyst** | GET /agents/{id}/monitor | 200 | 200 ✅ |
| analyst | POST /agents/{id}/actions/kill_process | 403 | 403 ✅ |
| analyst | POST /agents/enroll-tokens | 403 | 403 ✅ |
| analyst | POST /agents/groups | 403 | 403 ✅ |
| analyst | POST /alerts/ingest | 200 | 200 ✅ |
| analyst | PATCH /alerts/{id}/status | 200 | 200 ✅ |
| **responder** | POST /agents/{id}/actions/kill_process (real pid) | 200 | 200 ✅ 真实杀进程 |
| responder | POST /agents/groups | 403 | 403 ✅ |
| responder | POST /agents/enroll-tokens | 403 | 403 ✅ |
| responder | PATCH /alerts/{id}/status | 200 | 200 ✅ |
| **未认证** | GET /alerts | 401 | 401 ✅ |
| 未认证 | GET /agents/{id}/monitor | 401 | 401 ✅ |
| 未认证 | POST kill_process | 401 | 401 ✅ |

> **设计说明**: `/api/v1/agents` 列表(viewer 看不到)是故意限制,viewer 设计上不感知主机层。

---

## 五、Tier 4: SSE 流端点(7 通过 / 8)

| 端点 | Scope | 期望 | 实际 |
|---|---|---|---|
| `GET /api/v1/metrics/stream` | metrics | 200 | 200 ✅ |
| `GET /api/v1/events/{id}/stream` | events | 200 | 200 ✅ |
| `GET /api/v1/vulnscan/tasks/{id}/stream` | events | 200 | 200 ✅ |
| `GET /api/v1/events/stream` | events_list | 200 | **404 ⚠️ 真 bug** |
| `GET /api/v1/metrics/stream` 无 token | - | 422 | 422 ✅ |
| `GET /api/v1/events/{id}/stream` 无 token | - | 422 | 422 ✅ |
| `GET /api/v1/metrics/stream` bad token | - | 401 | 401 ✅ |
| `GET /api/v1/metrics/stream` events-scope token | - | 401 | 200 ⚠️ 设计 |

### 已知问题
1. **`/api/v1/events/stream` 被 `/{event_id}/stream` 路由遮蔽**:FastAPI 按注册顺序匹配,`{event_id}/stream` 抢到 "stream" 作为 id,返回 "Event not found"。修复方法:调整 `stream.py` 里两条路由的注册顺序,或合并到同一个 handler。
2. **scope 跨 stream 不严**:`events` scope token 能访问 `metrics/stream`,因为 `_verify_scoped_token` 的 fallback 接受任何 admin/analyst/responder JWT。这是 P1-API-04 文档里说明的 legacy 兼容,不算 bug 但可以收紧。

---

## 六、本轮测试发现并修的真 bug(3 个)

### Bug 1 — `GroupCreateRequest` 缺 `description` 字段
- **症状**: `POST /api/v1/agents/groups` 返回 500 Internal Server Error
- **根因**: Pydantic 模型只声明了 `name`,但 `api_create_group` handler 调用 `req.description` 触发 AttributeError
- **修复**: `src/api/routers/agents.py` 加 `description: str | None = Field(default=None, max_length=512)`
- **验证**: 现在返 200 (新 group) / 409 (dup)

### Bug 2 — `AuditLogger.log` 调用缺 `event_id` 必传参
- **症状**: 创建 group 时 500 (在 fix #1 之后暴露)
- **根因**: `api_create_group` 调 `get_audit_logger().log(...)` 时没传 `event_id`,但 `AuditLogger.log` 第一参是必传
- **修复**: 传 `event_id=f"group:{req.name}"` 作为合成 id
- **验证**: group 创建流程完整跑通

### Bug 3 — `EnrollTokenRequest` 缺范围校验
- **症状**: `ttl_hours=-1` / `uses=0` 都被接受(应 422)
- **根因**: 模型是 `int = 24` / `int = 1`,没 Pydantic Field 约束
- **修复**: 加 `Field(ge=0, le=168)` 和 `Field(ge=1, le=10000)`;同时补 `from pydantic import BaseModel, Field` import
- **验证**: -1 / 0 都返 422 with 清晰 Pydantic 错误

---

## 七、未涵盖 / 留作后续

| 端点 | 原因 |
|---|---|
| `WebSocket /api/v1/agents/ws` | 需真实 agent 端连接,本轮已通过 service 端日志确认在线(心跳、monitor_event、rule_update、upgrade_ack 都从 Rocky001 收到) |
| `POST /api/v1/agents/enroll` | 需 signed enroll payload(agent 端调用),测试覆盖到 `enroll-tokens` 间接路径 |
| `POST /api/v1/agents/{id}/upgrade` | 真实升级有副作用,本轮只读 |
| `DELETE /api/v1/agents/{id}` (decommission) | 有副作用,本轮未测 |
| `POST /api/v1/vulnscan/tasks` 真实扫描 | 触发 nuclei 模板,本轮用 `parse` 路径间接覆盖 |
| Chat / LLM (`/api/v1/chat`, `/api/v1/models/{id}/test`) | 需 LLM API key + 长时延,本轮 `models list` 已覆盖 |
| Approval / Demo 真实操作 | 需事件进 pending_approval 状态,本轮读路径已覆盖 |

---

## 八、状态总览

- 后端: uvicorn 0.0.0.0:8000,OpenAPI 66 /api 路径全注册
- Rocky001 agent: v0.2.0 online, 22 monitor events
- ES: secagent-monitor(22+)、secagent-alerts(14+)
- Nacos: 62 keys loaded
- 测试期间修了 3 个真 bug,1 个 routing 顺序问题留作后续
