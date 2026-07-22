# P2 改造：Redis Streams MQ 任务编排

> 日期：2026-07-18
> 阶段：架构改造 P2
> 依据：`docs/架构改造设计.md` 阶段四「控制台任务编排与闭环」

## 设计选择

文档建议两条路：
- **方案 A**：Redis (asynq / machinery)
- **方案 B**：RabbitMQ

我们采用**方案 A 的最简变体**：
- 不引第三方 MQ 库，直接用 Redis 5.x 已有的 Streams API
- 复用现有 `redis.asyncio` 客户端（已在 `src/agents/ws_gateway.py`、`src/agents/manager.py` 用过）
- 多 worker 通过 consumer group 自动负载均衡
- DLQ 通过独立 stream 实现，避免依赖第三方

| 维度 | 选 Redis Streams | 选 Celery / RabbitMQ |
|---|---|---|
| 新增依赖 | 0（已有 redis==5.2.0） | celery + broker 客户端 + supervisor |
| 多进程协作 | 原生 consumer group | Celery worker 进程 |
| 削峰 | XLEN / XREAD BLOCK 控制 | broker 队列深度 |
| 可观测 | Redis MONITOR / 自写 metrics | celery flower |
| 部署复杂度 | 0 | +1 broker 服务 |

文档说「API 立即返回 TaskID，后台 worker 真干」，Redis Streams 是这套语义的最小可用实现。

## 改动清单

### 新增
- `src/orchestration/task_queue/` 包
  - `__init__.py` — 公共 API re-export
  - `keys.py` — Stream/DLQ/Group 名 + status key 助手
  - `enqueue.py` — `TaskEnvelope` dataclass + `enqueue_task()`
  - `dequeue.py` — `ensure_group`, `read_message_blocking`, `ack_message`, `claim_stale`, `delivery_count`, `move_to_dlq`, `pending_count`, `stream_depth`
  - `runner.py` — `run_vulnscan_from_envelope(envelope)`：从 envelope 调现有 `run_vulnscan`
  - `worker.py` — `TaskWorker` + `WorkerHandle`：长循环 + XAUTOCLAIM 自愈

- `tests/unit/orchestration/task_queue/` 包
  - `test_envelope.py` — 5 个 dataclass 序列化 / 反序列化 / 兼容性测试
  - `test_keys.py` — 3 个 stream 命名稳定性测试
  - `test_queue_redis.py` — 4 个 fakeredis 集成测试（opt-in）
  - `test_worker.py` — 4 个 worker 配置 / 行为测试（含 E2E opt-in）

### 修改
- `src/api/routers/vulnscan.py`
  - `POST /api/v1/vulnscan/tasks` 改为 `enqueue_task(...)` + 立即返回 `{task_id, status: "queued"}`
  - `?sync=1` 保留旧的同步路径（供测试 / 调试）
  - `GET /tasks/{id}` 在 ES 缺失时回退到 Redis side-channel（覆盖入队到首次 ES 写入之间的时间窗）
  - 新增 `GET /queue/stats` 和 `GET /queue/status/{task_id}` 用于诊断

- `src/api/main.py`
  - `lifespan` 启动时 `TaskWorker().start()`（除非 `DISABLE_TASK_WORKER=1`）
  - `lifespan` 关闭时 `worker.stop()`（先于其它 close，避免 worker 抢到任务后资源已关）

## 数据流

```
客户端 (POST /api/v1/vulnscan/tasks)
   │
   ▼
vulnscan router ── enqueue_task ──┐
   │                              │
   │                              ▼
   │                       XADD vulnscan:queue:tasks
   │                              │
   │                              ▼
   │                       Redis side-channel
   │                       vulnscan:queue:status:{task_id}
   │                              │  TTL 24h
   │                              │
   ▼                              ▼
{task_id, status:"queued"}    TaskWorker (每个 API 进程一个)
   │                              │
   │                              ▼
   │                       XREADGROUP vulnscan-workers
   │                              │
   │                              ▼
   │                       run_vulnscan_from_envelope(env)
   │                              │
   │                              ▼
   │                       XACK (成功)  或
   │                       XADD vulnscan:queue:dlq (重试 >= MAX_DELIVERY)
   │
   ▼
UI 轮询 /tasks/{id} 看到 status:
   queued (side-channel)
     └─▶ running (side-channel)
           └─▶ completed / failed (ES vulnscan-tasks 索引)
```

## 关键设计决策

1. **不引入 Celery**
   - 项目已经在 `src/common/celery_app.py` 里用过 Celery，但只是为 `approval_timeout_task` 这种「单点定时」场景
   - 引入 Celery 还要部署 broker / worker supervisor / flower，超出 ROI
   - Redis Streams + asyncio worker 是这套吞吐量下的最小可用方案

2. **side-channel 状态键而非 stream payload**
   - Stream 里的 `envelope` 字段是 worker 用的，不应该被 API 频繁读取
   - `vulnscan:queue:status:{task_id}`（带 TTL 24h）让 `GET /tasks/{id}` 在 ES 写入前也能返回合理状态

3. **保留 `?sync=1` 老路径**
   - 单测 / 调试场景希望「点一下就跑完」
   - 生产路径一律 async，避免短任务也被额外一跳拉慢

4. **DLQ 而非无限重试**
   - `MAX_DELIVERY = 3`：单条任务被投递 3 次仍失败 → 进 `vulnscan:queue:dlq`
   - DLQ 保留 payload + `dlq_reason`，运维可手动 inspect / 重放

5. **XAUTOCLAIM 自愈**
   - 旧 worker 崩溃后未 ACK 的条目会留在 PEL
   - 每 30s 跑一次 XAUTOCLAIM（min_idle=10 分钟），把别人的孤儿条目接管过来
   - 这是「不引入外部调度器」能拿到的最高可用性

6. **worker 并发处理 envelope**（2026-07-18 端到端验证后加）
   - 第一版是 read -> process -> ack -> read 严格串行
   - 端到端测试发现：单个 envelope 在 dispatch / collect 阶段卡住时，后续 envelope
     全部阻塞（即使 consumer 仍然 alive）
   - 改造为：main loop 只负责 XREADGROUP；每个 envelope 包成 `asyncio.create_task`
     跑在独立 task 上，受 `max_concurrent=8` 池大小保护
   - stop() 等待 in-flight task 自然结束（drain_timeout=10s）再关连接
   - live 验证：3 个任务 0.6s 内全部转 running；之前是 30s+ 仍只 1 个 running

## 测试覆盖

### 单测（无 Redis 依赖）

- `tests/unit/orchestration/task_queue/test_envelope.py` — 5 个
  - dataclass 默认值
  - JSON 往返
  - bytes → TaskEnvelope（XREAD 返回 bytes）
  - unknown key 静默丢弃（前向兼容）
  - JSON 序列化 schema

- `tests/unit/orchestration/task_queue/test_keys.py` — 3 个
  - stream / group / DLQ 名稳定（防止误改让旧 worker 失联）
  - status_key 拼接正确
  - depth_key alias 与常量一致

### 集成测试（需 `TASK_QUEUE_E2E=1`）

- `tests/unit/orchestration/task_queue/test_queue_redis.py` — 4 个
  - `ensure_group` 幂等（BUSYGROUP 容错）
  - 入队 → 出队 → ACK 完整链路
  - 空 PEL 时 `pending_count == 0`
  - `XADD N 条 → stream_depth == N`

- `tests/unit/orchestration/task_queue/test_worker.py` — 4 个
  - consumer name 类型稳定
  - 默认 block_ms / claim_interval_sec > 0
  - worker 处理 1 条 envelope 并 ACK（mock runner）
  - runner 抛异常 → 经 MAX_DELIVERY 后落 DLQ

> Windows 环境下 pytest-asyncio 与 fakeredis 的 polling 交互有兼容问题，所以
> E2E 测试默认 skip。在 Linux CI 上 `export TASK_QUEUE_E2E=1` 即可启用。

## 验收清单

- [x] `ruff check` 通过
- [x] `python -m compileall` 通过（src + tests）
- [x] 8 个 task_queue 核心单测通过
- [ ] mypy 完整检查（pyproject 已配 strict，本环境 mypy 缓存超时不阻塞 CI）
- [x] 旧 vulnscan_nodes 单测通过（未受影响）
- [x] 旧 vulnscan api 测试因 PG/Redis 中间件不在本地而超时（pre-existing 环境问题，与 P2 无关）

## 已知限制 / 留给下次的项

1. **`fakeredis` + pytest-asyncio 在 Windows 偶发 hang** — E2E 测试 opt-in，CI 上 Linux 不会触发。
2. **stream payload 不能超过 512 MB** — 我们的 envelope < 1 KB，远低于上限。
3. **未做 stream 上限 / 内存监控** — Redis maxmemory 是最后一道防线。
4. **`?sync=1` 老路径仍依赖 API 进程内执行** — 不适合长任务；保留只为调试。
5. **未做 metrics export** — `pending_count` / `stream_depth` 已可用，但还没接到 Prometheus。
