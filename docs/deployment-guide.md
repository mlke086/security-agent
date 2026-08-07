# Security AI Agent — Deployment Guide

## 1. Prerequisites
- Python >= 3.11
- Redis, Neo4j, Kafka, Elasticsearch, Milvus (or use docker-compose)
- Docker (for sandbox execution)
- Node.js 18+ (for frontend)

## 2. Quick Start (Development)
```powershell
git clone <repo>
cd security-agent
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
cp .env.example .env  # edit with your settings
uvicorn src.api.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev  # http://localhost:3000
```

## 3. Environment Variables

> **V13 配置分层（重要）**：业务配置全部放 **Nacos**（`deployments/prod/docker/nacos-config.yaml` 是模板，推送到 Nacos 后 30s 热更新）。
> `.env` **只留引导/密钥**（Nacos 加载前就要用，且受白名单保护写不进 Nacos）：

| `.env` 必留变量 | 说明 |
|---|---|
| `NACOS_SERVER / NACOS_DATA_ID / NACOS_GROUP / NACOS_NAMESPACE / NACOS_USERNAME / NACOS_PASSWORD` | Nacos bootstrap 连接 |
| `API_SECRET_KEY` | JWT 签名（≥16 位，校验器强制，不能进 Nacos） |
| `AGENT_SIGNING_KEY` | Ed25519 私钥（64 hex，不能进 Nacos） |
| `DEFAULT_ADMIN/ANALYST/VIEWER/RESPONDER_PASSWORD` | 种子密码（生产 ≥12 位） |
| `DEV_MODE` | 可选（会被 Nacos 的 `dev_mode` 覆盖） |

**走 Nacos 的配置**（模板里都有，生产按需改）：`llm_provider / openai_api_key / openai_base_url / openai_model`、`kafka_*`、`milvus_*`、`neo4j_*`、`redis_url`、`es_*`、`pg_*`（含 `pg_password`）、`sandbox_*`、`nuclei_*`、`rules_sync_* / nvd_*`、`virustotal/alienvault` key、`wechat/dingtalk` webhook、`log_level`、`store_backend` 等。

**V13 AI search-agent（新增，走 Nacos）**：
```yaml
serper_enabled: true          # 用 Serper 则 true
serper_api_key: <Serper key>
tavily_enabled: false         # 用 Tavily 则 true
tavily_api_key: <Tavily key>
```
> 额度按次计费，代码内 `_needs_realtime` 三层门控（强实时词直搜 / 弱信号 LLM 复核 / 无信号不搜）+ Redis 30min 缓存。**两个都 false = 关闭搜索**。

## 4. K8s Deployment
```bash
# Create secrets first
kubectl create namespace security-agent
kubectl apply -f deployments/k8s/configmap.yaml
kubectl apply -f deployments/k8s/secret.yaml
kubectl apply -f deployments/k8s/deployment.yaml
kubectl apply -f deployments/k8s/service.yaml
kubectl apply -f deployments/k8s/hpa.yaml

# Check status
kubectl get all -n security-agent
```

## 4b. Production Deployment (docker-compose)
生产部署使用 `deployments/prod/`（详见其 README.md）。流程：

```bash
# 1. 编辑 Nacos 配置并推送（首次部署必须先做，业务配置全在这里）
vim deployments/prod/docker/nacos-config.yaml   # 模板里 ${XXX} 占位符替换成真实值
NACOS_SERVER=http://127.0.0.1:8848 NACOS_PASSWORD=nacos \
    bash deployments/prod/push-nacos-config.sh   # group 用 SECURITY（大写）

# 2. 构建镜像（默认 tag 0.1.0；PROXY 指向可出网的代理）
cd deployments/prod
VERSION=0.1.0 PROXY=http://192.168.254.121:7897 bash build-images.sh

# 3. 准备 .env（只填引导密钥，业务配置走 Nacos）
cp deployments/prod/.env.example .env   # 填 5 项引导密钥，见 §3

# 4. 启动
cd deployments/prod
docker compose -f docker-compose.yml up -d

# 5. 健康检查
curl -fsS http://127.0.0.1:8000/health    # API
curl -fsS http://127.0.0.1:8081/healthz   # 前端
```

> ⚠️ **V13 D0-1 凭据出库（部署必读）**：
> - `settings.py` 的 `pg_password/redis_url/neo4j_password` **默认值已置空**，Nacos 模板里的 `${...}` 占位符会被 `nacos_loader` 跳过不注入——**必须**在 Nacos 里填真实值（或走 `.env`/Secret 注入），否则中间件连不上（登录 500 `password authentication failed`）。
> - 曾进过 git 历史的真实凭据（`sk-c6b12a0e…`、`AGENT_SIGNING_KEY=f2113ad0…`、PG/Redis/Neo4j 密码、NVD key、Serper/Tavily key）**生产上线前必须轮换**。
> - `uvicorn --forwarded-allow-ips` 已收紧为 `TRUSTED_PROXY`（默认 127.0.0.1+内网段），确认前端 nginx 容器 IP 在段内。

### 架构要点
- **API/TaskWorker/Celery**：`network_mode: host`，直接占宿主机 8000 端口
- **前端**：bridge 网络 `8081:80`，nginx 反代 `/api` 到后端——
  compose 用 `extra_hosts: secagent-api:host-gateway` 让 nginx 经宿主机网关
  访问 host 网络模式的 API 容器
- **配置**：业务配置走 Nacos（`deployments/prod/docker/nacos-config.yaml`），
  docker-compose 只注入引导变量（中间件地址 + 密钥）

### Nacos 配置（含 nuclei 内网下载）
`nacos-config.yaml` 是配置源，**首次部署需推送到 Nacos**：

```bash
# 在 API 容器内执行（或本地改 NACOS_SERVER 后执行）
docker exec secagent-api bash /app/deployments/prod/docker/init-nacos.sh
```

> ⚠️ **group 大小写必须对齐**：应用实际读的 group = docker-compose 注入的
> `NACOS_GROUP=SECURITY`（大写），Nacos 配置必须落在 SECURITY group 下。
> 三个脚本默认值不一致，务必按推送方核对：
> - `push-nacos-config.sh`：默认 `SECURITY`（大写）✓ **推荐用它**
> - `init-nacos.sh`：V12 5.12 后默认小写 `security`（对齐 settings 默认），
>   用它必须显式 `NACOS_GROUP=SECURITY bash init-nacos.sh`
> 配置落错 group → 应用读不到（曾导致 nuclei 下载版本为空、安装脚本失败）。

**nuclei 配置项**（Nacos 中的 `NUCLEI_*`，代码默认已为空串，必须由 Nacos 提供）：
```yaml
NUCLEI_DOWNLOAD_BASE_URL: "http://<内网镜像>:8081"
NUCLEI_VERSION: "3.11.0"
NUCLEI_TEMPLATES_VERSION: "10.4.6"
```

Agent 安装脚本由服务端生成时会注入上述值；缺失时 install.sh 显示
`Downloading nuclei CLI v from internal mirror...`（版本空）并降级 matcher-only。

### Sigma 规则导入（前端报"尚未导入"时执行）
`scripts/import_sigma_rules.py` 解析 Sigma 规则，把可用的 `.yml` 复制进
`src/detection/rules/imported/` 并写 `manifest.json`；Detector 启动时递归加载该目录。

> ⚠️ **两个已知坑**：
> 1. **镜像里没有 `scripts/`**——Dockerfile 只 COPY `src`/`docs`/`deployments`，
>    容器内不能直接跑这个脚本，需先 `docker cp` 进去。
> 2. 仓库里 `src/detection/rules/imported/manifest.json` 是本地测试导入残留（5 条
>    sigma_zoo），**未跟踪进 git**——服务器 clone 构建的镜像 imported/ 是空的，
>    这就是前端一直提示"尚未导入"的原因。

```bash
# 0) 准备真实 Sigma 规则源（仓库内只有测试规则，不算数）
git clone --depth 1 https://github.com/SigmaHQ/sigma /opt/sigma/sigma   # 网络不行走代理/镜像

# 1) 把脚本 + 规则源拷进运行中的容器
docker exec secagent-api mkdir -p /app/scripts
docker cp scripts/import_sigma_rules.py secagent-api:/app/scripts/import_sigma_rules.py
docker cp /opt/sigma/sigma/rules/. secagent-api:/tmp/sigma/

# 2) 容器内执行导入（默认写入 /app/src/detection/rules/imported/ + manifest.json）
docker exec -it secagent-api python scripts/import_sigma_rules.py /tmp/sigma

# 3) 热重载 Detector（admin token，无需重启）
curl -s -X POST -H "Authorization: Bearer <admin_token>" http://127.0.0.1:8000/api/v1/detect/rules/load
```

> ⚠️ 容器内 `/app` 非挂载卷，**容器重建后导入的规则会丢**。持久化方案二选一：
> - **bind mount**：`docker-compose.yml` 的 api 服务加
>   `- ./rules-imported:/app/src/detection/rules/imported`，`docker compose up -d`
>   重建后再按上面导入，规则落在宿主机 `./rules-imported`，重启保留。
>   （taskworker/celery 若也跑检测则同样加。）
> - **重打镜像**：宿主机 venv 里先 `python scripts/import_sigma_rules.py <rules_dir>`
>   再 build，规则内嵌进镜像。

## 5. Docker Build & Sandbox
```bash
# Build app image
docker build -t security-agent:latest -f deploy/docker/Dockerfile .

# Build sandbox (on server 192.168.80.101)
ssh root@192.168.80.101
docker build --ulimit nproc=4096 \
  --build-arg http_proxy=http://192.168.254.121:7897 \
  -t security-agent-sandbox /tmp/sandbox-build/
docker network create --driver bridge sandbox-net
```

## 6. Knowledge Base Ingestion
```bash
python scripts/import_attack_stix.py
python scripts/ingest_knowledge.py
```

## 7. Testing
```bash
pytest tests/unit/ -v
python tests/e2e/test_scenarios.py
```

## 8. Security Notes
- Bandit: 2 Medium issues (intentional: bind 0.0.0.0 for ingress, /tmp for sandbox)
- JWT tokens expire after 120 minutes (configurable)
- All user passwords hashed with bcrypt
- Audit logs are append-only via Elasticsearch
- Sandbox containers run with no-new-privileges + seccomp
