#!/bin/sh
# 阶段 4-2:celery 服务 entrypoint(无 HTTP,依赖日志关键字 + pgrep 探活)。
set -eu

echo "celery_starting" >&2

# Redis 兜底:无 REDIS_URL 时用 localhost(本机有 redis 中间件)
: "${REDIS_URL:=redis://127.0.0.1:6379/0}"
export REDIS_URL

# Nacos bootstrap(共享配置由 Nacos 提供;若 nacos_server 未设则用 env-only)
: "${NACOS_SERVER:=}"
: "${NACOS_NAMESPACE:=prod}"
: "${NACOS_GROUP:=security}"
: "${NACOS_DATA_IDS:=security-agent-shared.yaml,security-agent-celery.yaml}"
export NACOS_SERVER NACOS_NAMESPACE NACOS_GROUP NACOS_DATA_IDS

# fail-fast:本机中间件可达性检查(简易 TCP 探活)
if [ -n "$NACOS_SERVER" ]; then
    # 从 http://host:port 抽 host:port
    HOST_PORT=$(echo "$NACOS_SERVER" | sed -E 's#^https?://##')
    HOST=$(echo "$HOST_PORT" | cut -d: -f1)
    PORT=$(echo "$HOST_PORT" | cut -d: -f2)
    PORT=${PORT:-8848}
    echo "celery_nacos_probe host=$HOST port=$PORT" >&2
    if ! curl -sf --max-time 5 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
        echo "[FATAL] nacos ${HOST}:${PORT} unreachable" >&2
        exit 1
    fi
fi

# Redis 可达性
REDIS_HOST=$(echo "$REDIS_URL" | sed -E 's#^redis://##' | cut -d: -f1)
REDIS_PORT=$(echo "$REDIS_URL" | sed -E 's#^redis://##' | cut -d: -f2 | cut -d/ -f1)
REDIS_PORT=${REDIS_PORT:-6379}
echo "celery_redis_probe host=$REDIS_HOST port=$REDIS_PORT" >&2
if ! curl -sf --max-time 5 "http://${REDIS_HOST}:${REDIS_PORT}/" >/dev/null 2>&1; then
    # Redis 不响应 HTTP,这是预期。改用 nc 或 python socket 检查。
    python -c "
import socket, sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect(('${REDIS_HOST}', int('${REDIS_PORT}')))
    print('redis_ok')
except Exception as e:
    print(f'[FATAL] redis unreachable: {e}', file=sys.stderr)
    sys.exit(1)
" || exit 1
fi

echo "celery_ready" >&2

# exec CMD
exec "$@"