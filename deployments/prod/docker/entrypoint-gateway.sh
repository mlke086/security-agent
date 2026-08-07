#!/bin/sh
# 阶段 5 收尾:gateway 服务 entrypoint(fail-fast 检查)。
#
# 检查项:
#   - API_SECRET_KEY 长度 ≥16 位(pydantic model_validator)
#   - Postgres 可达(若 PG_HOST 非空)
#   - Nacos 配置加载成功(load_nacos_settings 不抛错)
#
# 与 entrypoint-celery.sh / entrypoint-graphrag.sh 风格一致。
set -eu

echo "gateway_starting" >&2

# fail-fast:API_SECRET_KEY
: "${API_SECRET_KEY:?[FATAL] API_SECRET_KEY is required for JWT signing}"
if [ "${#API_SECRET_KEY}" -lt 16 ]; then
    echo "[FATAL] API_SECRET_KEY must be ≥16 chars (got ${#API_SECRET_KEY})" >&2
    exit 1
fi

# fail-fast:Postgres 可达
: "${PG_HOST:=127.0.0.1}"
: "${PG_PORT:=5432}"
echo "gateway_pg_probe host=$PG_HOST port=$PG_PORT" >&2
python -c "
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${PG_HOST}', int('${PG_PORT}')))
    print('gateway_pg_ok')
except Exception as e:
    print(f'[FATAL] gateway pg unreachable: {e}', file=sys.stderr)
    sys.exit(1)
" || exit 1

# fail-fast:Nacos bootstrap(可选,无 Nacos 则走 env-only)
: "${NACOS_SERVER:=}"
if [ -n "$NACOS_SERVER" ]; then
    HOST_PORT=$(echo "$NACOS_SERVER" | sed -E 's#^https?://##')
    HOST=$(echo "$HOST_PORT" | cut -d: -f1)
    PORT=$(echo "$HOST_PORT" | cut -d: -f2)
    PORT=${PORT:-8848}
    echo "gateway_nacos_probe host=$HOST port=$PORT" >&2
    if ! curl -sf --max-time 5 "http://${HOST}:${PORT}/" >/dev/null 2>&1; then
        echo "[WARN] nacos ${HOST}:${PORT} unreachable, falling back to env-only config" >&2
    fi
fi

echo "gateway_ready" >&2
exec "$@"