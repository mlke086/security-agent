#!/bin/bash
# =====================================================================
# SecAgent container entrypoint
# CMD 决定启动哪个进程:
#   api          -> uvicorn src.api.main:app
#   taskworker   -> 消费 Redis Stream 中的 vulnscan 任务
#   celery       -> Celery worker (HITL 审批超时)
#   beat         -> Celery beat(可选)
#   init-nacos   -> 仅执行一次 Nacos 配置推送(运维)
#   --           -> 透传
#
# 关键约定:
#   1) 所有容器进程启动前都先调一次 load_nacos_settings(),
#      确保 broker / ES / 模型等配置已落入 env。
#   2) docker-compose 只注入启动必须的引导变量:
#        - 中间件地址 / Nacos bootstrap
#        - PG 凭据(init_schema 用)
#        - 真正不能进 Nacos 的密钥(API_SECRET_KEY / AGENT_SIGNING_KEY)
#      其他全部走 Nacos。
# =====================================================================

set -euo pipefail

target="${1:-api}"
shift || true

# PYTHONPATH 必须在所有 python 调用前设置,否则 python -c 找不到 src.*
export PYTHONPATH="${PYTHONPATH:-}:/app"

log() { printf '[entrypoint %s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# 小写化 LOG_LEVEL(uvicorn/celery 不接受大写)
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ---- 0. 预加载 Nacos 配置 ----
preload_nacos() {
    if [[ -z "${NACOS_SERVER:-}" ]]; then
        log "NACOS_SERVER unset -- skip Nacos preload (env-only mode)"
        return 0
    fi
    log "Preloading Nacos config from ${NACOS_SERVER} ..."
    cd /app
    if ! python -c "
import asyncio
from src.common.config.settings import load_nacos_settings, reload_settings
asyncio.run(load_nacos_settings())
reload_settings()
" 2>&1 | tee -a /app/logs/nacos_preload.log; then
        log "WARN: Nacos preload failed -- continuing with env-only config"
    fi
}

# ---- 1. 等基础依赖可达 ----
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

: "${POSTGRES_HOST:=127.0.0.1}"; : "${POSTGRES_PORT:=5432}"
: "${REDIS_HOST:=127.0.0.1}";   : "${REDIS_PORT:=6379}"
: "${ES_HOSTS:=http://127.0.0.1:9200}"
: "${MILVUS_HOST:=127.0.0.1}";   : "${MILVUS_PORT:=19530}"
: "${NEO4J_URI:=bolt://127.0.0.1:7687}"
: "${KAFKA_BOOTSTRAP_SERVERS:=127.0.0.1:9092}"

ES_PROBE=$(echo "$ES_HOSTS" | sed -E 's#https?://##; s#/.*##; s#:# #')
ES_HOST=${ES_PROBE% *}; ES_PORT=${ES_PROBE#* }
[[ -z "$ES_HOST" || -z "$ES_PORT" ]] && { ES_HOST=127.0.0.1; ES_PORT=9200; }
NEO4J_PROBE=$(echo "$NEO4J_URI" | sed -E 's#^bolt://##; s#:# #')
NEO4J_HOST=${NEO4J_PROBE% *}; NEO4J_PORT=${NEO4J_PROBE#* }
KAFKA_PROBE=$(echo "$KAFKA_BOOTSTRAP_SERVERS" | cut -d: -f1,2)
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

# ---- 2. Nacos 预加载 ----
preload_nacos

# ---- 3. 一次性 Nacos 推送(可选,运维手动跑) ----
if [[ "${RUN_INIT_NACOS:-false}" == "true" && "$target" == "init-nacos" ]]; then
    log "Pushing Nacos config (idempotent)..."
    bash /app/deployments/prod/docker/init-nacos.sh || log "Nacos push returned non-zero"
    exit 0
fi

# ---- 4. 启业务进程 ----
# uvicorn --log-level 只认小写,统一转一次
UVICORN_LOG_LEVEL=$(lc "${LOG_LEVEL:-info}")

case "$target" in
    api)
        log "Starting uvicorn (api), log-level=${UVICORN_LOG_LEVEL}"
        cd /app
        exec python -m uvicorn src.api.main:app \
            --host "${API_HOST:-0.0.0.0}" \
            --port "${API_PORT:-8000}" \
            --workers "${API_WORKERS:-2}" \
            --proxy-headers \
            --forwarded-allow-ips='*' \
            --log-level "${UVICORN_LOG_LEVEL}"
        ;;
    taskworker)
        log "Starting TaskWorker (vulnscan Redis Stream consumer)..."
        cd /app
        # TaskWorker 真实接口是 start()/stop(),没有 run_forever。
        # 用 signal 监听 SIGTERM / SIGINT 干净退出。
        exec python -c "
import asyncio, signal
from src.orchestration.task_queue import TaskWorker

async def main():
    w = TaskWorker()
    handle = w.start()
    stop = asyncio.Event()

    def _on_term():
        stop.set()
    loop = asyncio.get_event_loop()
    for s in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(s, _on_term)

    log = __import__('src.common.logging.logger', fromlist=['get_logger']).get_logger('entrypoint.taskworker')
    log.info('taskworker_started', consumer=handle.consumer)
    await stop.wait()
    await handle.stop(timeout=10.0)
    log.info('taskworker_stopped')

asyncio.run(main())
"
        ;;
    celery)
        log "Starting Celery worker (HITL timeouts)..."
        cd /app
        exec celery -A src.common.celery_app worker \
            --loglevel="${UVICORN_LOG_LEVEL}" \
            --concurrency="${CELERY_CONCURRENCY:-2}" \
            -Q security-agent-tasks
        ;;
    beat)
        log "Starting Celery beat (scheduler)..."
        cd /app
        exec celery -A src.common.celery_app beat \
            --loglevel="${UVICORN_LOG_LEVEL}"
        ;;
    init-nacos)
        log "Nacos push done."
        ;;
    --)
        log "Passthrough: $*"
        exec "$@"
        ;;
    *)
        log "Unknown target '"$target"' -- passing through"
        exec "$target" "$@"
        ;;
esac