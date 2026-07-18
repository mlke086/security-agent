"""Sprint 4: Run safety, create deployment guide."""
import subprocess, json, os

print("=== Safety Check ===")
proc = subprocess.run(
    [".venv/Scripts/safety.exe", "check", "--json"],
    capture_output=True, text=True, timeout=30,
)
try:
    data = json.loads(proc.stdout)
    vulns = data.get("vulnerabilities", [])
    print(f"Vulnerabilities found: {len(vulns)}")
    for v in vulns[:5]:
        pkg = v.get("package_name", "?")
        ver = v.get("vulnerable_spec", "?")
        adv = v.get("advisory", "?")[:80]
        print(f"  [{pkg} {ver}] {adv}")
except:
    print(f"Exit code: {proc.returncode}, stderr: {proc.stderr[:200]}")

print("\n=== Deployment Guide ===")
guide = """# Security AI Agent — Deployment Guide

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
.venv\\Scripts\\Activate.ps1
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
| LLM_PROVIDER | claude | claude \\| openai \\| vllm |
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

## 5. Docker Build & Sandbox
```bash
# Build app image
docker build -t security-agent:latest -f deploy/docker/Dockerfile .

# Build sandbox (on server 192.168.80.101)
ssh root@192.168.80.101
docker build --ulimit nproc=4096 \\
  --build-arg http_proxy=http://192.168.254.121:7897 \\
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
"""

path = "V:/project/security-agent/docs/deployment-guide.md"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    f.write(guide)
print(f"Created: {path}")
print("Sprint 4 — Deployment guide written")
