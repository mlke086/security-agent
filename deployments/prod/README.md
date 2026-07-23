# SecAgent 生产环境部署手册

> 目标服务器:`svr18156`(192.168.18.156),已通过 docker-compose 部署了中间件套件:
> PostgreSQL 17 / Redis 7 / Kafka 3.8 / Milvus 2.4 / Neo4j 5 / Nacos 3.2 / MinIO / ClickHouse / Elasticsearch 8.15。
> 本手册描述如何把 SecAgent 应用本体也部署成 Docker 容器,与上述中间件对接。

---

## 1. 部署架构总览

```
                            ┌─────────────────────────────┐
                            │       svr18156 (192.168.18.156) │
                            │                                 │
                            │  ┌─────────┐  ┌─────────────┐  │
                            │  │ nginx   │  │  已有中间件   │  │
                            │  │ frontend│  │ PG/Redis/ES  │  │
                            │  │ :8080   │  │ Kafka/Milvus │  │
                            │  └────┬────┘  │ Neo4j/Nacos  │  │
                            │       │       └─────────────┘  │
                            │       ▼                          │
                            │  ┌─────────┐  ┌─────────────┐  │
                            │  │ secagent│  │ secagent    │  │
                            │  │  -api   │  │ -taskworker │  │
                            │  │ :8000   │  │ (host net)  │  │
                            │  └─────────┘  └─────────────┘  │
                            │       │                          │
                            │       ▼                          │
                            │  ┌─────────┐                     │
                            │  │ secagent│                     │
                            │  │ -celery │                     │
                            │  └─────────┘                     │
                            └─────────────────────────────────┘
                                      ▲            ▲
                                      │            │
                              ┌───────┴──┐    ┌────┴──────┐
                              │ secagent │    │ secagent  │
                              │  frontend│    │   agent   │
                              │   (nginx)│    │ (主机侧)   │
                              └──────────┘    └───────────┘
```

容器角色:

| 服务 | 镜像 | 网络 | 端口 |
|---|---|---|---|
| secagent-api | secagent-api:0.1.0 | host | 8000 |
| secagent-taskworker | secagent-api:0.1.0 (同镜像) | host | — |
| secagent-celery | secagent-api:0.1.0 (同镜像) | host | — |
| secagent-frontend | secagent-frontend:0.1.0 | bridge | 8080:80 |

> 后端 3 个进程使用同一镜像,通过 `command` 字段切换 entrypoint 行为,
> 走 `host` 网络直接访问宿主中间件,避免与已有容器互相干扰。

---

## 2. 准备服务器端运行环境

```bash
# 1. 安装 docker 与 docker-compose(如果还没有)
yum install -y docker docker-compose-plugin
systemctl enable --now docker

# 2. 创建部署目录
mkdir -p /opt/secagent/{deploy,data/rules,logs/{api,taskworker,celery}}
cd /opt/secagent

# 3. 从版本库拷贝整个项目(下文以 git 拉取为例)
git clone https://your.git/security-agent.git
# 或者用 rsync 推送源码到服务器后,目录结构如下:
# /opt/secagent/security-agent/
#   ├─ src/
#   ├─ frontend/
#   ├─ pyproject.toml
#   └─ deployments/prod/...
```

---

## 3. 准备 PostgreSQL 角色和数据库

应用需要在 PostgreSQL 里建 `secagent` 角色和 `SecAgent` 库(中间件 pg 容器里做一次即可):

```bash
# 进入宿主机或任何能访问 pg 容器网络的 shell
docker exec -it postgres psql -U postgres <<'SQL'
CREATE ROLE secagent LOGIN PASSWORD 'Ke615700';
CREATE DATABASE "SecAgent" OWNER secagent;
GRANT ALL PRIVILEGES ON DATABASE "SecAgent" TO secagent;
SQL
```

> 角色密码(`Ke615700`)需要与最终 `.env` 里的 `PG_PASSWORD` 一致。

---

## 4. 配置 Nacos(可选,推荐)

应用启动时会从 Nacos 拉取全量配置,优先级 **容器 env > Nacos > .env**。
生产推荐用 Nacos 集中管理,这样改配置不用重启容器。

`deployments/prod/docker/nacos-config.yaml` 是默认模板,可以直接推送到 Nacos:

```bash
# 在宿主机执行(走容器内 init-nacos.sh 镜像里也有)
docker exec -it secagent-api \
    bash /app/deployments/prod/docker/init-nacos.sh
```

或在宿主机直接调 Nacos API:

```bash
curl -X POST "http://127.0.0.1:8848/nacos/v1/auth/login" \
    -d "username=nacos&password=nacos"

# 拿到 accessToken 后,POST 配置
curl -X POST "http://127.0.0.1:8848/nacos/v3/admin/cs/config" \
    -H "accessToken: <token>" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "dataId=security-agent.yaml" \
    --data-urlencode "groupName=SECURITY" \
    --data-urlencode "namespaceId=prod" \
    --data-urlencode "type=yaml" \
    --data-urlencode "content=$(cat deployments/prod/docker/nacos-config.yaml)"
```

应用启动后,Nacos 的修改会自动通过 long-poll 推送到应用并热加载。

---

## 5. 准备 .env 密钥文件

```bash
cd /opt/secagent/security-agent/deployments/prod
cp .env.example .env
vim .env
```

需要填写的关键变量:

| 变量 | 说明 | 示例 |
|---|---|---|
| `PG_PASSWORD` | 与第 3 步一致 | `Ke615700` |
| `REDIS_PASSWORD` | redis://:密码@host | `redis_password_2026` |
| `NEO4J_PASSWORD` | Neo4j 密码 | `neo4j_password_2026` |
| `NACOS_PASSWORD` | Nacos 密码 | `nacos` |
| `API_SECRET_KEY` | JWT 签名,≥32 字符 | `openssl rand -hex 32` |
| `AGENT_SIGNING_KEY` | Ed25519 私钥,64 hex | `python -c "import os;print(os.urandom(32).hex())"` |
| `AGENT_CONSOLE_EXTERNAL_URL` | Agent 端回调的服务器地址 | `http://192.168.18.156:8000` |
| `OPENAI_API_KEY` | LLM API Key | `sk-xxx` |
| `DEFAULT_ADMIN_PASSWORD` 等 4 个 | 种子用户密码,≥12 字符 | 见 .env.example |

生成示例:

```bash
echo "API_SECRET_KEY=$(openssl rand -hex 32)"
echo "AGENT_SIGNING_KEY=$(python3 -c "import os;print(os.urandom(32).hex())")
```

---

## 6. 编译 Docker 镜像(走代理拉外网源)

服务器出网需要代理 `http://192.168.254.121:7897`(管理员提供)。
国内源推荐用阿里云 pip 镜像和 npmmirror。

```bash
cd /opt/secagent/security-agent

# ---------- 后端镜像 ----------
docker build \
    -t secagent-api:0.1.0 \
    -f deployments/prod/docker/Dockerfile.api \
    --build-arg HTTP_PROXY=http://192.168.254.121:7897 \
    --build-arg HTTPS_PROXY=http://192.168.254.121:7897 \
    --build-arg NO_PROXY=127.0.0.1,localhost,192.168.0.0/16 \
    --build-arg PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
    --build-arg PIP_TRUSTED_HOST=mirrors.aliyun.com \
    .

# ---------- 前端镜像 ----------
docker build \
    -t secagent-frontend:0.1.0 \
    -f deployments/prod/docker/Dockerfile.frontend \
    --build-arg NPM_REGISTRY=https://registry.npmmirror.com \
    --build-arg HTTP_PROXY=http://192.168.254.121:7897 \
    --build-arg HTTPS_PROXY=http://192.168.254.121:7897 \
    .
```

> 验证镜像:`docker images | grep secagent`

---

## 7. 启动服务

```bash
cd /opt/secagent/security-agent/deployments/prod

# 首次部署建议前台跑,看启动日志
docker compose -f docker-compose.yml up

# 后台跑
docker compose -f docker-compose.yml up -d

# 查看状态
docker compose -f docker-compose.yml ps

# 跟踪日志
docker compose -f docker-compose.yml logs -f api
```

启动顺序与依赖:

1. **entrypoint.sh 等待所有中间件可达**(postgres/redis/ES/kafka/milvus/neo4j,kafka 探测)
2. **首次启动**(`RUN_INIT_PG=true`):执行 `init-pg.sql`,幂等
3. **首次启动**(`RUN_INIT_NACOS=true`):把 `nacos-config.yaml` 推送到 Nacos
4. **拉全量配置**:从 env 拉取,缺失 key 从 Nacos 补
5. **业务进程启动**:uvicorn / TaskWorker / Celery worker / nginx

---

## 8. 健康检查与首次登录

```bash
# 后端健康
curl -fsS http://127.0.0.1:8000/health
# {"status":"ok"}

# 前端
curl -fsS http://127.0.0.1:8080/healthz
# ok

# OpenAPI 文档
curl -fsS http://127.0.0.1:8000/docs | head -3

# 登录(用 .env 里设置的密码)
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"<DEFAULT_ADMIN_PASSWORD>"}'
```

浏览器打开:

- 前端:`http://192.168.18.156:8080`
- 后端:`http://192.168.18.156:8000`
- API 文档:`http://192.168.18.156:8000/docs`

> 登录后右上角点 **「注入演示数据」** 即可生成样例事件、扫描任务、漏洞数据。

---

## 9. 下发 Agent 到目标主机

容器镜像里已经打包了 Agent 二进制,API 通过 `/api/v1/agents/binary/{os}/{arch}` 提供下载。

### 9.1 在前端创建注册令牌

打开「主机纳管」页面 → 设置组、TTL → 点 **「生成令牌」** → 复制 curl 命令。

### 9.2 在目标主机一键安装

```bash
# 在被纳管的主机上(任意 Linux amd64/arm64)
curl -fsSL "http://192.168.18.156:8000/api/v1/agents/install?token=<enroll_token>" | sudo bash
```

或手动下载安装包:

```bash
# 在目标主机
curl -fsSL http://192.168.18.156:8000/api/v1/agents/binary/linux/amd64?token=<enroll_token> -o secagent-agent
chmod +x secagent-agent
sudo ./secagent-agent --console http://192.168.18.156:8000 --enroll-token <enroll_token>
```

### 9.3 Windows / macOS

下载对应平台的二进制,放在 `/usr/local/bin` 或 `C:\Program Files\secagent`,用相同令牌 enroll。

### 9.4 离线分发

如果目标主机不能访问主控:

```bash
# 在能访问外网的跳板机上打包
cd /opt/secagent/security-agent
bash deployments/prod/package-agent.sh
# 产出:deployments/prod/agent-pkg/secagent-agent-<ver>-<ts>.tar.gz

# 拷贝到目标机后展开
tar xzf secagent-agent-*.tar.gz
cd secagent-agent
sudo bash packaging/install.sh <enroll_token> http://192.168.18.156:8000
```

---

## 10. 关键运维操作

### 10.1 查看 / 调整日志

```bash
docker logs secagent-api --tail 200 -f
docker logs secagent-taskworker --tail 200 -f
docker logs secagent-celery --tail 200 -f

# ES 审计
curl -s "http://127.0.0.1:9200/security-agent-audit/_search?size=5&pretty"
```

### 10.2 修改配置(三种方式)

1. **改 .env 后重启**(最暴力)
   ```bash
   vim .env
   docker compose up -d --no-deps api
   ```

2. **改 Nacos 配置**(热加载,推荐)
   ```bash
   # 调 Nacos API 更新
   docker exec -it secagent-api \
       bash /app/deployments/prod/docker/init-nacos.sh
   ```
   应用通过 long-poll 自动接收,无需重启。

3. **改前端 API 反代**(nginx 配置)
   ```bash
   docker exec -it secagent-frontend nginx -s reload
   ```

### 10.3 数据库迁移 / 升级

```bash
# 升级时执行 PG schema(应用启动时自动做)
docker compose restart api

# 手动触发
docker exec -it secagent-api \
    bash -c 'PGPASSWORD=$PG_PASSWORD psql -h $POSTGRES_HOST -U $PG_USER -d $PG_DATABASE -f /app/deployments/prod/docker/init-pg.sql'
```

### 10.4 模型管理(LLM)

前端 **「模型管理」** 页面 → 新增 / 切换默认模型。
修改后立即生效,不需重启。

### 10.5 规则同步

前端 **「规则管理」** → 「联网更新(NVD/国外)」,会自动调用 NVD API 拉取最新规则并签名下发到所有在线 Agent。
首次同步会持续 5~30 分钟,视网络与 API 配额而定。

### 10.6 数据备份建议

```bash
# Postgres
docker exec postgres pg_dump -U secagent SecAgent > backup_$(date +%F).sql

# Elasticsearch(可使用 elasticdump 或快照)
curl -X PUT "http://127.0.0.1:9200/_snapshot/secagent_backup" \
    -H "Content-Type: application/json" \
    -d '{"type":"fs","settings":{"location":"/backup"}}'

# Nacos 配置(可选)
curl "http://127.0.0.1:8848/nacos/v3/admin/cs/config?dataId=security-agent.yaml&groupName=SECURITY&namespaceId=prod"
```

---

## 11. 升级 / 回滚

```bash
# 1) 拉取新代码 / 新镜像
cd /opt/secagent/security-agent
git pull

# 2) 重新构建镜像
docker build -t secagent-api:0.2.0 ... -f deployments/prod/docker/Dockerfile.api .
docker build -t secagent-frontend:0.2.0 ... -f deployments/prod/docker/Dockerfile.frontend .

# 3) 在 .env 里改 SECAGENT_IMAGE_API / SECAGENT_IMAGE_FRONTEND,再 up
vim ../deployments/prod/.env
docker compose -f docker-compose.yml up -d

# 回滚:把 tag 改回旧版,再 up
```

---

## 12. 故障排查速查

| 现象 | 检查 |
|---|---|
| 启动报 `P1-SEC-06: admin password is unset` | `.env` 里 `DEFAULT_ADMIN_PASSWORD` 未设或太短(≥12) |
| 启动报 `Elasticsearch... timeout` | `ES_HOSTS` 是否能从容器内访问到宿主(走 host network) |
| 启动报 `kafka... connection refused` | Kafka 容器是否启动了 `KAFKA_ADVERTISED_LISTENERS` 指向 `127.0.0.1:9092` |
| Nacos push 失败 | `NACOS_SERVER=http://127.0.0.1:8848` 是否可达,鉴权用户密码是否正确 |
| 前端 502 | nginx 反代目标是 `secagent-api:8000`,但前端用 bridge 网络 → 改成 host 网络或加 host 别名 |
| API 401 | 密码不对,看 `.env` 是否生效,或 `/auth/login` 返回的 body |
| 看不到菜单(管理员) | 浏览器 localStorage 里旧 token,清掉重新登录 |

---

## 13. 文件清单(本目录)

```
deployments/prod/
├── docker-compose.yml          # 主 compose:api + taskworker + celery + frontend
├── .env.example                # .env 模板(必填的密钥清单)
├── README.md                   # 本文档
├── package-agent.sh            # Agent 二进制打包脚本(离线分发)
├── docker/
│   ├── Dockerfile.api          # 后端镜像(多阶段,含 Agent 二进制)
│   ├── Dockerfile.frontend     # 前端镜像(nginx + 静态)
│   ├── nginx.conf              # 前端 nginx 配置(SPA + /api 反代)
│   ├── entrypoint.sh           # 容器入口脚本(api/taskworker/celery 多进程切换)
│   ├── init-pg.sql             # 一次性 PG schema 初始化
│   ├── init-nacos.sh           # 一次性 Nacos 配置推送
│   └── nacos-config.yaml       # Nacos 配置模板
└── agent-pkg/                  # 离线 Agent 安装包输出目录
```
---

## 14. 常用脚本

| 脚本 | 用途 |
|---|---|
| `build-images.sh` | 一键构建两个 Docker 镜像,自动应用代理和国内源 |
| `push-nacos-config.sh` | 把 `nacos-config.yaml` 推送到 Nacos(运维手动) |
| `package-agent.sh` | 打包 Agent 二进制成 tar.gz,用于离线分发 |
| `docker/init-nacos.sh` | 容器内调用,镜像启动时自动执行 |
| `docker/init-pg.sql` | 容器内调用,PG schema 初始化 |

```bash
# 一键构建
VERSION=0.1.0 PROXY=http://192.168.254.121:7897 \
    bash deployments/prod/build-images.sh

# 推送 Nacos 配置
NACOS_SERVER=http://127.0.0.1:8848 \
NACOS_USERNAME=nacos NACOS_PASSWORD=nacos \
    bash deployments/prod/push-nacos-config.sh

# 离线打包 Agent
bash deployments/prod/package-agent.sh
```
