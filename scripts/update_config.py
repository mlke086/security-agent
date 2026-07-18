path = r"V:\project\security-agent\src\common\config\settings.py"
content = open(path, "r", encoding="utf-8").read()

replacements = {
    "vllm_base_url: str = \"http://localhost:8000\"": "vllm_base_url: str = \"http://192.168.80.101:8000\"",
    "kafka_bootstrap_servers: str = \"localhost:9092\"": "kafka_bootstrap_servers: str = \"192.168.80.101:9092\"",
    "milvus_host: str = \"localhost\"": "milvus_host: str = \"192.168.80.101\"",
    "neo4j_uri: str = \"bolt://localhost:7687\"": "neo4j_uri: str = \"bolt://192.168.80.101:7687\"",
    "neo4j_password: str = \"changeme\"": "neo4j_password: str = \"neo4j_password_2026\"",
    "redis_url: str = \"redis://localhost:6379/0\"": "redis_url: str = \"redis://:redis_password_2026@192.168.80.101:6379/0\"",
    "es_hosts: str = \"http://localhost:9200\"": "es_hosts: str = \"http://192.168.80.101:9200\"",
}

for old, new in replacements.items():
    if old in content:
        content = content.replace(old, new)

open(path, "w", encoding="utf-8").write(content)
print("settings.py updated!")

# Update .env.example
env_path = r"V:\project\security-agent\.env.example"
env_content = open(env_path, "r", encoding="utf-8").read()

env_replacements = {
    "VLLM_BASE_URL=http://localhost:8000": "VLLM_BASE_URL=http://192.168.80.101:8000",
    "KAFKA_BOOTSTRAP_SERVERS=localhost:9092": "KAFKA_BOOTSTRAP_SERVERS=192.168.80.101:9092",
    "MILVUS_HOST=localhost": "MILVUS_HOST=192.168.80.101",
    "NEO4J_URI=bolt://localhost:7687": "NEO4J_URI=bolt://192.168.80.101:7687",
    "NEO4J_PASSWORD=changeme": "NEO4J_PASSWORD=neo4j_password_2026",
    "REDIS_URL=redis://localhost:6379/0": "REDIS_URL=redis://:redis_password_2026@192.168.80.101:6379/0",
    "ES_HOSTS=http://localhost:9200": "ES_HOSTS=http://192.168.80.101:9200",
}

for old, new in env_replacements.items():
    if old in env_content:
        env_content = env_content.replace(old, new)

open(env_path, "w", encoding="utf-8").write(env_content)
print(".env.example updated!")
