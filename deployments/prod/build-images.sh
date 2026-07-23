#!/bin/bash
# =====================================================================
# 一键构建所有 SecAgent 镜像
# 默认走代理 192.168.254.121:7897 拉外网源
# 用法:
#   bash build-images.sh                     # 默认 tag 0.1.0
#   VERSION=0.2.0 bash build-images.sh       # 自定义版本
#   PROXY=http://10.0.0.1:7890 bash build-images.sh   # 自定义代理
# =====================================================================

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
PROXY="${PROXY:-http://192.168.254.121:7897}"
NO_PROXY="${NO_PROXY:-127.0.0.1,localhost,192.168.0.0/16}"
PIP_INDEX_URL="${PIP_INDEX_URL:-https://mirrors.aliyun.com/pypi/simple/}"
PIP_TRUSTED_HOST="${PIP_TRUSTED_HOST:-mirrors.aliyun.com}"
NPM_REGISTRY="${NPM_REGISTRY:-https://registry.npmmirror.com}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo " Build SecAgent images"
echo "   version:    $VERSION"
echo "   proxy:      $PROXY"
echo "   pip index:  $PIP_INDEX_URL"
echo "   npm mirror: $NPM_REGISTRY"
echo "============================================================"

echo
echo "[1/2] Building API image..."
docker build \
    -t "secagent-api:${VERSION}" \
    -f deployments/prod/docker/Dockerfile.api \
    --build-arg HTTP_PROXY="$PROXY" \
    --build-arg HTTPS_PROXY="$PROXY" \
    --build-arg NO_PROXY="$NO_PROXY" \
    --build-arg PIP_INDEX_URL="$PIP_INDEX_URL" \
    --build-arg PIP_TRUSTED_HOST="$PIP_TRUSTED_HOST" \
    .

echo
echo "[2/2] Building frontend image..."
docker build \
    -t "secagent-frontend:${VERSION}" \
    -f deployments/prod/docker/Dockerfile.frontend \
    --build-arg NPM_REGISTRY="$NPM_REGISTRY" \
    --build-arg HTTP_PROXY="$PROXY" \
    --build-arg HTTPS_PROXY="$PROXY" \
    .

echo
echo "============================================================"
echo "Done. Built images:"
docker images | grep -E "secagent-(api|frontend)" || true
