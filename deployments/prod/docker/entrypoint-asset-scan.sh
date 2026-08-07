#!/bin/sh
# 需求②:asset-scan 服务 entrypoint(fail-fast 检查)。
#
# 检查项:
#   - nmap / masscan 二进制存在(核心发现工具, 缺失即 FATAL)
#   - nuclei 存在性(缺失仅警告: CPE 规则匹配仍可用, nuclei 模块自动跳过)
#   - Redis Stream 可达(assetscan:queue:tasks consumer 启动前提)
set -eu

echo "asset_scan_starting" >&2

# fail-fast:nmap / masscan(agentless 扫描的核心依赖)
for bin in nmap masscan; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[FATAL] $bin not found; install it or rebuild the image" >&2
        exit 1
    fi
done
echo "asset_scan_tools_ok" >&2

# nuclei 缺失仅警告(CVE 匹配可走 CPE 规则, nuclei 模块自动跳过)
if ! command -v nuclei >/dev/null 2>&1; then
    echo "[WARN] nuclei not found; nuclei module will be skipped" >&2
fi

# fail-fast:Redis(任务队列)
: "${REDIS_URL:=redis://127.0.0.1:6379/0}"
REDIS_HOST=$(echo "$REDIS_URL" | sed -E 's#^redis://##' | cut -d: -f1)
REDIS_PORT=$(echo "$REDIS_URL" | sed -E 's#^redis://##' | cut -d: -f2 | cut -d/ -f1)
REDIS_PORT=${REDIS_PORT:-6379}
echo "asset_scan_redis_probe host=$REDIS_HOST port=$REDIS_PORT" >&2
python -c "
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('${REDIS_HOST}', int('${REDIS_PORT}')))
    print('asset_scan_redis_ok')
except Exception as e:
    print(f'[FATAL] redis unreachable: {e}', file=sys.stderr)
    sys.exit(1)
" || exit 1

echo "asset_scan_ready" >&2
exec "$@"
