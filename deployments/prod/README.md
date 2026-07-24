# SecAgent 生产环境部署手册

> 目标服务器:`svr18156`(192.168.18.156),已部署中间件套件:
> PostgreSQL 17 / Redis 7 / Kafka 3.8 / Milvus 2.4 / Neo4j 5 / Nacos 3.2 / MinIO / ClickHouse / Elasticsearch 8.15。
> 本手册描述如何把 SecAgent 应用本体也部署成 Docker 容器,与上述中间件对接。

---

## 0. 核心约定:配置三层分工

应用代码里 `load_nacos_settings()` 已经实现 **"env > Nacos > .env > 代码默认值"** 的优先级:

| 层级 | 放什么 | 谁来读 |
|---|---|---|
| **Nacos** | 所有业务配置(LLM / ES / Kafka / Milvus / Neo4j / 通知 webhook 等) | 启动时拉一次,后续 long-poll 热加载 |
| **容器 env** | 启动必须的引导密钥 + 主机特定值(5 项) | settings.py 直接读 |
| **代码默认** | 上述两层都没设时的兜底 | settings.py 字段默认值 |

**`.env` 必填 5 项**(其他都在 Nacos):

```bash
PG_PASSWORD                   # init_schema() 立即要用
NACOS_PASSWORD                # 用于拉 Nacos 配置
API_SECRET_KEY                # JWT 签名,长度校验在 import 时就执行
AGENT_SIGNING_KEY             # Ed25519,Agent WS 命令签名
AGENT_CONSOLE_EXTERNAL_URL    # 主机特定值(Agent 回调地址)
```

业务配置(LLM API Key、ES 地址、Kafka topic、Milvus 集合名、webhook URL 等)全部在
`deployments/prod/docker/nacos-config.yaml` 里维护,推到 Nacos 后**所有容器自动获取**。

---

## 1. 部署架构

```
                            ┌──────────────────────────────────┐
                            │  svr18156 (192.168.18.156)         │
                            │                                   │
                            │  ┌────────┐    ┌──────────────┐   │
                            │  │ nginx  │    │ 已有中间件     │   │
                            │  │ frontend│   │ PG/Redis/ES   │   │
                            │  │ :8081  │    │ Kafka/Milvus  │   │
                            │  └────┬───┘    │ Neo4j/Nacos   │   │
                            │       │        └──────────────┘   │
                            │       ▼                             │
                            │  ┌────────┐    ┌─────────────┐     │
                            │  │ secagent│   │ secagent    │     │
                            │  │  -api   │   │ -taskworker │     │
                            │  │ :8000   │   │ (host net)  │     │
                            │  └────┬───┘    └─────────────┘     │
                            │       │                             │
                            │       ▼                             │
                            │  ┌────────┐                         │
                            │  │secagent│                         │
                            │  │ -celery│                         │
                            │  └────────┘                         │
                            └────────────────────────────────────┘
```

| 服务 | 镜像 | 网络 | 端口 |
|---|---|---|---|
| secagent-api | secagent-api:0.1.0 | host | 8000 |
| secagent-taskworker | 同镜像 | host | — |
| secagent-celery | 同镜像 | host | — |
| secagent-frontend | secagent-frontend:0.1.0 | bridge | 8081:80(可改) |

---

## 2. 部署命令速览(完整版见下)

```bash
# 1) 准备 PG 角色(中间件 PG 容器里)
docker exec -it postgres psql -U postgres -c \
  "CREATE ROLE secagent LOGIN PASSWORD 'Ke615700'; CREATE DATABASE \"SecAgent\" OWNER secagent;"

# 2) 编辑 Nacos 配置 + 推送
vim deployments/prod/docker/nacos-config.yaml
NACOS_SERVER=http://127.0.0.1:8848 NACOS_PASSWORD=nacos \
    bash deployments/prod/push-nacos-config.sh

# 3) 准备 .env(从 .env.example 复制并填 5 项)
cp deployments/prod/.env.example deployments/prod/.env
vim deployments/prod/.env

# 4) 自检
bash deployments/prod/check-env.sh

# 5) 构建镜像(走代理拉外网)
cd /opt/secagent/security-agent
bash deployments/prod/build-images.sh

# 6) 启动
cd deployments/prod
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml ps
```

---

## 3. 详细步骤

### 3.1 准备 PG 角色

```bash
docker exec -it postgres psql -U postgres <<'SQL'
CREATE ROLE secagent LOGIN PASSWORD 'Ke615700';
CREATE DATABASE "SecAgent" OWNER secagent;
GRANT ALL PRIVILEGES ON DATABASE "SecAgent" TO secagent;
SQL
```

### 3.2 推 Nacos 配置

```bash
# 编辑 nacos-config.yaml,改业务配置(LLM / ES / 通知 webhook / 种子用户密码等)
vim deployments/prod/docker/nacos-config.yaml

# 推送(走 v3 OpenAPI,已存在则覆盖)
NACOS_SERVER=http://127.0.0.1:8848 \
NACOS_USERNAME=nacos NACOS_PASSWORD=nacos \
    bash deployments/prod/push-nacos-config.sh
```

### 3.3 准备 .env

```bash
cp deployments/prod/.env.example deployments/prod/.env
vim deployments/prod/.env

# 必填 5 项(每项都要)
PG_PASSWORD=Ke615700
NACOS_PASSWORD=nacos
API_SECRET_KEY=$(openssl rand -hex 32)
AGENT_SIGNING_KEY=$(python -c "import os;print(os.urandom(32).hex())")
AGENT_CONSOLE_EXTERNAL_URL=http://192.168.18.156:8081   # 注意:是前端端口
```

### 3.4 自检

```bash
bash deployments/prod/check-env.sh
```

会校验 5 项必填变量、API_SECRET_KEY 长度、AGENT_SIGNING_KEY 格式、端口占用、compose 解析。

### 3.5 构建镜像

```bash
cd /opt/secagent/security-agent
bash deployments/prod/build-images.sh
```

脚本默认走 `http://192.168.254.121:7897` 拉外网源,用阿里云 pip + npmmirror:

```bash
VERSION=0.2.0 PROXY=http://10.0.0.1:7890 \
    bash deployments/prod/build-images.sh
```

### 3.6 启动

```bash
cd deployments/prod
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs -f api
```

启动顺序(由 entrypoint.sh 控制):

1. 等待 6 个中间件 TCP 可达(90s)
2. 调 `load_nacos_settings()` 拉 Nacos 配置注入 env
3. 启动业务进程(uvicorn / TaskWorker / celery)

---

## 4. 健康检查

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8081/healthz
open http://192.168.18.156:8081   # 前端
open http://192.168.18.156:8000/docs   # API 文档
```

---

## 5. 下发 Agent

Agent 二进制已打包进 API 镜像,API 通过 `/api/v1/agents/binary/{os}/{arch}` 提供下载。

```bash
# 前端:主机纳管 -> 生成令牌 -> 复制 curl
# 目标主机:
curl -fsSL "http://192.168.18.156:8000/api/v1/agents/install?token=<enroll_token>" | sudo bash
```

离线分发:`bash deployments/prod/package-agent.sh`。

---

## 6. 运维操作

```bash
# 改 Nacos 配置(推荐,30s 内自动热加载)
vim deployments/prod/docker/nacos-config.yaml
bash deployments/prod/push-nacos-config.sh

# 改引导密钥(.env):需重启相关容器
vim deployments/prod/.env
docker compose up -d --no-deps api taskworker celery

# 查看日志
docker logs secagent-api --tail 200 -f

# 升级 / 回滚
cd /opt/secagent/security-agent
git pull && bash deployments/prod/build-images.sh
vim ../deployments/prod/.env  # 改镜像 tag
cd ../deployments/prod && docker compose up -d
```

---

## 7. 部署踩坑清单(必读)

> 这些是早期部署已经踩过的坑,新部署请先扫一遍。

### 7.1 Docker 版本 / 代理

| 问题 | 解决 |
|---|---|
| 老版 Docker (20.10) 在 cgroupv2 下 seccomp 拦截 `mmap` 和线程创建,`dpkg-deb` 报 `Cannot allocate memory`,`pip` 报 `can't start new thread` | **升级到 Docker ≥ 29.6.2** |
| pip 依赖解析慢、反复 backtracking | pip 加 `--no-cache-dir`,或在 `pip install` 后接 `\|\| true` 兜底 |

### 7.2 docker compose 命令

| 问题 | 解决 |
|---|---|
| `docker: unknown command: docker compose` (v2 插件未装) | 用 **docker-compose v1 独立二进制**;本仓库脚本同时兼容两种 |

### 7.3 文件编码

| 问题 | 解决 |
|---|---|
| `entrypoint.sh: 1: #!/bin/bash: not found` + `set: Illegal option -o pipefail` | **UTF-8 BOM** 在 Windows 上 `Set-Content` 会自动加,shell 无法识别 shebang。所有 .sh / .conf 文件必须用无 BOM 的 UTF-8。本仓库已用 `[System.IO.File]::WriteAllText(..., UTF8Encoding($false))` 写入,Linux 上 `head -c 3 file \| od -c` 应该看到 `#!/`,而不是 `357 273 277` |
| nginx 报 `unknown directive "#"` | 同样是 nginx.conf 含 BOM |

**预防**:在 Linux 上 `file entrypoint.sh` 应该显示 `Bourne-Again shell script, ASCII text executable`,而不是 `UTF-8 Unicode (with BOM) text`。

### 7.4 端口冲突

| 问题 | 解决 |
|---|---|
| `Bind for 0.0.0.0:8080 failed: port is already allocated` (nginx-reports 占了) | `.env` 里 `FRONTEND_PORT=8081`(本仓库默认已是 8081) |

### 7.5 Python 包兼容

| 问题 | 解决 |
|---|---|
| `ModuleNotFoundError: No module named 'anthropic'` | `langchain-anthropic` 用 `--no-deps` 安装会跳过 `anthropic` 本体。Dockerfile 已显式 `pip install anthropic==0.39.0 langchain-anthropic==0.3.0` |
| `ValueError: password cannot be longer than 72 bytes` / `AttributeError: module 'bcrypt' has no attribute '__about__'` | **bcrypt 5.x 与 passlib 1.7.4 不兼容**。Dockerfile 已固定 `bcrypt==4.0.1` |
| pip `pip install --no-deps "langchain-anthropic==0.3.0" \|\| true` 跳过依赖 | 已改成显式双装 |

### 7.6 启动脚本

| 问题 | 解决 |
|---|---|
| `AttributeError: 'TaskWorker' object has no attribute 'run_forever'` | entrypoint 写错了方法名。已改为 `TaskWorker().start()` + asyncio signal,干净响应 SIGTERM/SIGINT |
| `ModuleNotFoundError: No module named 'src'` | entrypoint 加了 `export PYTHONPATH=/app` |
| `Error: Invalid value for '--log-level': 'INFO' is not one of 'critical' ...` | uvicorn 只认小写。entrypoint 加了 `tr '[:upper:]' '[:lower:]'` 转换 |

### 7.7 健康检查 / 代理

| 问题 | 解决 |
|---|---|
| 三个容器全部 unhealthy,`curl: (22) The requested URL returned error: 502` | 双重根因:**1)** 镜像层 HEALTHCHECK 被 taskworker/celery 继承(它们不起 HTTP);**2)** 容器内 `http_proxy` 让 curl 把 127.0.0.1:8000 解析成代理自己的 localhost。修复:去掉镜像层 HEALTHCHECK,只在 compose 的 api 服务上写,curl 加 `--noproxy '*'` 和 `-4`(强制 IPv4) |

### 7.8 Nacos

| 问题 | 解决 |
|---|---|
| 启动卡在 `nacos_config_poller_started` | 检查 `NACOS_SERVER` 是否能从容器内访问到 host(走 host network);日志 `/app/logs/nacos_preload.log` |
| Nacos 鉴权失败 | 确认 `NACOS_PASSWORD` 与 nacos 容器初始化时设置一致 |

### 7.9 业务 500

| 问题 | 解决 |
|---|---|
| `POST /api/v1/auth/login` → 500 `password cannot be longer than 72 bytes` | 同 §7.5 bcrypt,镜像里装 `bcrypt==4.0.1` 即可 |

---

## 8. 文件清单

```
deployments/prod/
├── README.md                    # 本文档
├── docker-compose.yml           # 极简:只 7 个引导 env,其余走 Nacos
├── .env.example                 # 5 项必填 + 可选镜像 tag
├── check-env.sh                 # 部署前自检(.env 完整性、端口、compose 解析)
├── build-images.sh              # 一键构建两个镜像(走代理)
├── push-nacos-config.sh         # 把 nacos-config.yaml 推到 Nacos
├── package-agent.sh             # 离线打包 Agent 二进制
├── docker/
│   ├── Dockerfile.api           # 多阶段后端镜像(内嵌 Agent 二进制,bcrypt 4.0.1)
│   ├── Dockerfile.frontend      # 多阶段前端镜像
│   ├── nginx.conf               # SPA + /api 反代 + WS + SSE
│   ├── entrypoint.sh            # 多进程入口,启动前先 load_nacos_settings()
│   ├── init-nacos.sh            # Nacos 配置推送(v3 OpenAPI)
│   └── nacos-config.yaml        # 全量业务配置模板
└── agent-pkg/                   # 离线 Agent tar.gz 输出目录
```