#!/bin/sh
# 阶段 5 收尾:scan-engine 服务 entrypoint(fail-fast 检查)。
#
# 检查项:
#   - Redis Stream 可达(vulnscan:tasks consumer 启动前提)
#   - Docker socket 可用(沙箱执行依赖)
#   - GRAPHRAG_BASE_URL 可达(若已配置)
set -eu

echo "scan_engine_starting" >&2

# fail-fast:Redis(任务队列与 WS pub/sub 共用)
: "${REDIS_URL:=redis://127.0.0.1:6379/0}"
REDIS_HOST=$(echo "$REDIS_URL" | sed -E 's#^redis://##' | cut -d: -f1)
REDIS_PORT=$(echo "$REDIS_URL" | sed -E 's#^redis://##' | cut -d: -f2 | cut -d/ -f1)
REDIS_PORT=${REDIS_PORT:-6379}
echo "scan_engine_redis_probe host=$REDIS_HOST port=$REDIS_PORT" >&2
python -c "
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${REDIS_HOST}', int('${REDIS_PORT}')))
    print('scan_engine_redis_ok')
except Exception as e:
    print(f'[FATAL] redis unreachable: {e}', file=sys.stderr)
    sys.exit(1)
" || exit 1

# fail-fast:Docker socket(沙箱执行)
if [ ! -S "${DOCKER_HOST:-/var/run/docker.sock}" ]; then
    echo "[WARN] DOCKER_HOST=${DOCKER_HOST:-/var/run/docker.sock} not a socket; sandbox actions will fail" >&2
fi

# 可选:graphrag 可达性(失败不阻塞,仅警告——graphrag 不可达时 cti_analyst 静默降级)
: "${GRAPHRAG_BASE_URL:=http://127.0.0.1:8002}"
HOST_PORT=$(echo "$GRAPHRAG_BASE_URL" | sed -E 's#^https?://##')
HOST=$(echo "$HOST_PORT" | cut -d: -f1)
PORT=$(echo "$HOST_PORT" | cut -d: -f2)
PORT=${PORT:-8002}
echo "scan_engine_graphrag_probe host=$HOST port=$PORT" >&2
if ! curl -sf --max-time 3 "http://${HOST}:${PORT}/healthz" >/dev/null 2>&1; then
    echo "[WARN] graphrag ${HOST}:${PORT} unreachable; cti_analyst will degrade silently" >&2
fi

echo "scan_engine_ready" >&2
exec "$@"