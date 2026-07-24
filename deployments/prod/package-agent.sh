#!/bin/bash
# =====================================================================
# 打包 Agent 二进制 + 安装脚本 -> 发布 tar.gz
# 输出:
#   deployments/prod/agent-pkg/secagent-agent-<version>.tar.gz
# 内容:
#   linux/{amd64,arm64}/agent
#   windows/amd64/agent.exe
#   install.sh / install.ps1
#   VERSION
#   ca.pem(若存在)
#   checksums.txt
# =====================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIST="$ROOT/deployments/agent/dist"
OUT_DIR="$ROOT/deployments/prod/agent-pkg"
mkdir -p "$OUT_DIR"

if [[ ! -d "$DIST" ]]; then
    echo "agent dist not found: $DIST" >&2
    exit 1
fi

VERSION=$(cat "$DIST/VERSION" 2>/dev/null || echo "0.0.0")
TS=$(date +%Y%m%d-%H%M%S)
TGZ="$OUT_DIR/secagent-agent-${VERSION}-${TS}.tar.gz"

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING/secagent-agent"
cp -r "$DIST" "$STAGING/secagent-agent/dist"
cp -r "$ROOT/agent/packaging" "$STAGING/secagent-agent/packaging"

# 计算 sha256
( cd "$STAGING/secagent-agent" && find . -type f -print0 \
    | xargs -0 sha256sum > checksums.txt )

tar -czf "$TGZ" -C "$STAGING" secagent-agent
echo "[ok] packaged: $TGZ"

ls -lh "$TGZ"
