#!/bin/bash
# =====================================================================
# SecAgent container entrypoint
# 接收一个 CMD 参数决定启动什么进程:
#   api          -> uvicorn src.api.main:app
#   taskworker   -> 消费 Redis Stream 中的 vulnscan 任务
#   celery       -> Celery worker (HITL 审批超时兜底)
#   beat         -> Celery beat(可选,周期任务)
#   init-pg      -> 仅执行一次 PG schema 初始化(由 init-pg.sql)
#   init-nacos   -> 仅执行一次 Nacos 配置推送
#   --           -> 后面的命令透传(运维 / 调试)
#
# 环境约定:
#   - 业务中间件统一走 env var,见 nacos-config.yaml 里的 key 列表
#   - 不启用 Nacos 时,直接用 env var(由 docker-compose 注入)
# =====================================================================

set -euo pipefail

target="${1:-api}"
shift || true

log() { printf '[entrypoint %s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# ---- 0. 等基础依赖可达(只等一次) ----
wait_for() {
    local name="$1" host="$2" port="$3" timeout="${4:-60}"
    local end=$((SECONDS + timeout))
    while (( SECONDS < end )); do
        if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
            log "$name reachable at ${host}:${port}"
            return 0
        fi
        sleep 1
    done
    log "WARNING: $name NOT reachable at ${host}:${port} after ${timeout}s -- proceeding anyway"
    return 0
}

# ---- 1. 等待中间件就绪 ----
: "${POSTGRES_HOST:=127.0.0.1}"; : "${POSTGRES_PORT:=5432}"
: "${REDIS_HOST:=127.0.0.1}";   : "${REDIS_PORT:=6379}"
: "${ES_HOSTS:=http://127.0.0.1:9200}"
: "${MILVUS_HOST:=127.0.0.1}";   : "${MILVUS_PORT:=19530}"
: "${NEO4J_URI:=bolt://127.0.0.1:7687}"
: "${KAFKA_BOOTSTRAP_SERVERS:=127.0.0.1:9092}"

# 从 ES_HOSTS 解析第一个 host:port 用于连通性探测
ES_PROBE=$(echo "$ES_HOSTS" | sed -E 's#https?://##; s#/.*##; s#:# #; q' || true)
ES_HOST=${ES_PROBE% *}; ES_PORT=${ES_PROBE#* }
[[ -z "$ES_HOST" || -z "$ES_PORT" ]] && { ES_HOST=127.0.0.1; ES_PORT=9200; }
NEO4J_PROBE=$(echo "$NEO4J_URI" | sed -E 's#^bolt://##; s#:# #')
NEO4J_HOST=${NEO4J_PROBE% *}; NEO4J_PORT=${NEO4J_PROBE#* }
KAFKA_PROBE=$(echo "$KAFKA_BOOTSTRAP_SERVERS" | head -n1 | cut -d: -f1,2)
KAFKA_HOST=${KAFKA_PROBE%:*}; KAFKA_PORT=${KAFKA_PROBE#*:}

for probe in \
    "postgres ${POSTGRES_HOST} ${POSTGRES_PORT}" \
    "redis ${REDIS_HOST} ${REDIS_PORT}" \
    "elasticsearch ${ES_HOST} ${ES_PORT}" \
    "milvus ${MILVUS_HOST} ${MILVUS_PORT}" \
    "neo4j ${NEO4J_HOST} ${NEO4J_PORT}" \
    "kafka ${KAFKA_HOST} ${KAFKA_PORT}" \
; do
    set -- $probe
    wait_for "$1" "$2" "$3" 90
done

# ---- 2. 一次性初始化(只在 api / taskworker / celery 上,且 env 显式开启) ----
if [[ "${RUN_INIT_PG:-false}" == "true" && ("$target" == "api" || "$target" == "init-pg") ]]; then
    log "Initializing PostgreSQL schema (SecAgent DB)..."
    if [[ -f /app/deployments/prod/docker/init-pg.sql ]]; then
        PGPASSWORD="${PG_PASSWORD:-}" psql \
            -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" \
            -U "${PG_USER:-secagent}" -d "${PG_DATABASE:-SecAgent}" \
            -v ON_ERROR_STOP=0 \
            -f /app/deployments/prod/docker/init-pg.sql || log "PG init returned non-zero (may already be initialized)"
    fi
fi

if [[ "${RUN_INIT_NACOS:-false}" == "true" && ("$target" == "api" || "$target" == "init-nacos") ]]; then
    log "Pushing Nacos config (idempotent)..."
    bash /app/deployments/prod/docker/init-nacos.sh || log "Nacos push returned non-zero"
fi

# ---- 3. 启业务进程 ----
case "$target" in
    api)
        log "Starting uvicorn (api)..."
        cd /app
        exec python -m uvicorn src.api.main:app \
            --host "${API_HOST:-0.0.0.0}" \
            --port "${API_PORT:-8000}" \
            --workers "${API_WORKERS:-2}" \
            --proxy-headers \
            --forwarded-allow-ips='*' \
            --log-level "${LOG_LEVEL:-info}"
        ;;
    taskworker)
        log "Starting TaskWorker (vulnscan Redis Stream consumer)..."
        cd /app
        exec python -c "
import asyncio, os
from src.orchestration.task_queue import TaskWorker
w = TaskWorker()
asyncio.run(w.run_forever())
"
        ;;
    celery)
        log "Starting Celery worker (HITL timeouts)..."
        cd /app
        exec celery -A src.common.celery_app worker \
            --loglevel="${LOG_LEVEL:-INFO}" \
            --concurrency="${CELERY_CONCURRENCY:-2}" \
            -Q security-agent-tasks
        ;;
    beat)
        log "Starting Celery beat (scheduler)..."
        cd /app
        exec celery -A src.common.celery_app beat \
            --loglevel="${LOG_LEVEL:-INFO}"
        ;;
    init-pg)
        log "One-shot PG init complete."
        ;;
    init-nacos)
        log "One-shot Nacos push complete."
        ;;
    --)
        log "Passthrough command: $*"
        exec "$@"
        ;;
    *)
        log "Unknown target '$target' -- passing through"
        exec "$target" "$@"
        ;;
esac
