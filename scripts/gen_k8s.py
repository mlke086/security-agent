"""Sprint 4: Generate K8s manifests and deployment guide."""
import os, subprocess

K8S_DIR = "V:/project/security-agent/deployments/k8s"
os.makedirs(K8S_DIR, exist_ok=True)

manifests = {}

# 1. Namespace
manifests["namespace.yaml"] = """apiVersion: v1
kind: Namespace
metadata:
  name: security-agent
"""

# 2. ConfigMap
manifests["configmap.yaml"] = """apiVersion: v1
kind: ConfigMap
metadata:
  name: security-agent-config
  namespace: security-agent
data:
  LLM_PROVIDER: "openai"
  OPENAI_MODEL: "deepseek-chat"
  OPENAI_BASE_URL: "https://api.deepseek.com/v1"
  KAFKA_BOOTSTRAP_SERVERS: "kafka:9092"
  KAFKA_TOPIC_RAW_ALERTS: "raw-alerts"
  MILVUS_HOST: "milvus"
  MILVUS_PORT: "19530"
  MILVUS_COLLECTION: "threat_intel"
  NEO4J_URI: "bolt://neo4j:7687"
  NEO4J_USER: "neo4j"
  REDIS_URL: "redis://redis:6379/0"
  ES_HOSTS: "http://elasticsearch:9200"
  LOG_LEVEL: "INFO"
  API_HOST: "0.0.0.0"
  API_PORT: "8000"
"""

# 3. Secret (placeholder — use kubectl create secret in production)
manifests["secret.yaml"] = """apiVersion: v1
kind: Secret
metadata:
  name: security-agent-secrets
  namespace: security-agent
type: Opaque
stringData:
  OPENAI_API_KEY: "<your-deepseek-api-key>"
  NEO4J_PASSWORD: "neo4j_password_2026"
  API_SECRET_KEY: "<random-64-char-string>"
  VIRUSTOTAL_API_KEY: ""
  ALIENVAULT_OTX_API_KEY: ""
  WECHAT_WORK_WEBHOOK: ""
  DINGTALK_WEBHOOK: ""
"""

# 4. Deployment
manifests["deployment.yaml"] = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-agent
  namespace: security-agent
  labels:
    app: security-agent
spec:
  replicas: 2
  selector:
    matchLabels:
      app: security-agent
  template:
    metadata:
      labels:
        app: security-agent
    spec:
      containers:
      - name: api
        image: security-agent:latest
        imagePullPolicy: IfNotPresent
        command: ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: security-agent-config
        - secretRef:
            name: security-agent-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 15
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 10
      - name: celery-worker
        image: security-agent:latest
        imagePullPolicy: IfNotPresent
        command: ["celery", "-A", "src.common.celery_app", "worker", "--loglevel=info"]
        envFrom:
        - configMapRef:
            name: security-agent-config
        - secretRef:
            name: security-agent-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
"""

# 5. Service
manifests["service.yaml"] = """apiVersion: v1
kind: Service
metadata:
  name: security-agent
  namespace: security-agent
  labels:
    app: security-agent
spec:
  type: ClusterIP
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  selector:
    app: security-agent
"""

# 6. HPA
manifests["hpa.yaml"] = """apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: security-agent
  namespace: security-agent
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: security-agent
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
"""

for name, content in manifests.items():
    path = os.path.join(K8S_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Created: {path}")

# Security audit summary
print("\n=== Security Audit Summary ===")
proc = subprocess.run(
    [".venv/Scripts/python.exe", "-m", "bandit", "-r", "src", "-q"],
    capture_output=True, text=True, cwd="V:/project/security-agent",
)
print(proc.stdout if proc.stdout.strip() else proc.stderr[:500])

print(f"\nTotal K8s files: {len(manifests)}")
print("Sprint 4 — K8s manifests created")
