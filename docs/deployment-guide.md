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
| Variable | Default | Description |
|----------|---------|-------------|
| LLM_PROVIDER | claude | claude \| openai \| vllm |
| OPENAI_API_KEY | - | OpenAI/DeepSeek key |
| OPENAI_BASE_URL | - | OpenAI-compatible endpoint |
| KAFKA_BOOTSTRAP_SERVERS | localhost:9092 | Kafka broker |
| NEO4J_URI | bolt://localhost:7687 | Neo4j connection |
| NEO4J_PASSWORD | changeme | Neo4j password |
| REDIS_URL | redis://localhost:6379/0 | Redis connection |
| ES_HOSTS | http://localhost:9200 | Elasticsearch |
| MILVUS_HOST | localhost | Milvus host |
| API_SECRET_KEY | change-this-secret-key | JWT signing key |

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
# 1. 构建镜像（默认 tag 0.1.0；PROXY 指向可出网的代理）
cd deployments/prod
VERSION=0.1.0 PROXY=http://192.168.254.121:7897 bash build-images.sh

# 2. 准备环境变量
cp deployments/prod/.env.example .env   # 编辑 PG/Redis/ES/Nacos 地址与密钥

# 3. 启动
cd deployments/prod
docker compose -f docker-compose.yml up -d

# 4. 健康检查
curl -fsS http://127.0.0.1:8000/health    # API
curl -fsS http://127.0.0.1:8081/healthz   # 前端
```

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

> ⚠️ **group 大小写**：init-nacos.sh 默认 `NACOS_GROUP=SECURITY`（大写），
> 但应用读取用 `nacos_group=security`（小写）。**推送前必须对齐**：
> `NACOS_GROUP=security bash init-nacos.sh`，否则配置落到错误 group，
> 应用读不到（曾导致 nuclei 下载版本为空、安装脚本 nuclei 失败）。

**nuclei 配置项**（Nacos 中的 `NUCLEI_*`，代码默认已为空串，必须由 Nacos 提供）：
```yaml
NUCLEI_DOWNLOAD_BASE_URL: "http://<内网镜像>:8081"
NUCLEI_VERSION: "3.11.0"
NUCLEI_TEMPLATES_VERSION: "10.4.6"
```

Agent 安装脚本由服务端生成时会注入上述值；缺失时 install.sh 显示
`Downloading nuclei CLI v from internal mirror...`（版本空）并降级 matcher-only。

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
