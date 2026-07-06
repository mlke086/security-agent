#!/usr/bin/env bash
# 验证所有本地开发依赖服务是否就绪
set -euo pipefail

PASS=0
FAIL=0

check() {
  local name=$1
  local cmd=$2
  if eval "$cmd" &>/dev/null; then
    echo "[OK]  $name"
    PASS=$((PASS+1))
  else
    echo "[FAIL] $name"
    FAIL=$((FAIL+1))
  fi
}

check "Kafka"         "nc -z localhost 9092"
check "Milvus"        "curl -sf http://localhost:19530/healthz"
check "Neo4j"         "curl -sf http://localhost:7474"
check "Redis"         "redis-cli -h localhost ping | grep -q PONG"
check "Elasticsearch" "curl -sf http://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
