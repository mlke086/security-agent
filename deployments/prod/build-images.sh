#!/bin/bash
# =====================================================================
# 一键构建所有 SecAgent 镜像
# 默认走代理 192.168.254.121:7897 拉外网源
# 用法:
#   bash build-images.sh                     # 默认 tag 0.1.0
#   VERSION=0.2.0 bash build-images.sh       # 自定义版本
#   PROXY=http://10.0.0.1:7890 bash build-images.sh   # 自定义代理
#   SKIP_BASE=1 bash build-images.sh         # 跳过 base 镜像 (已有)
#   SKIP_ASSET_SCAN=1 bash build-images.sh  # 跳过 asset-scan 镜像
# =====================================================================

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
PROXY="${PROXY:-http://192.168.254.121:7897}"
NO_PROXY="${NO_PROXY:-127.0.0.1,localhost,192.168.0.0/16}"
PIP_INDEX_URL="${PIP_INDEX_URL:-https://mirrors.aliyun.com/pypi/simple/}"
PIP_TRUSTED_HOST="${PIP_TRUSTED_HOST:-mirrors.aliyun.com}"
NPM_REGISTRY="${NPM_REGISTRY:-https://registry.npmmirror.com}"
SKIP_BASE="${SKIP_BASE:-0}"
SKIP_ASSET_SCAN="${SKIP_ASSET_SCAN:-0}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo " Build SecAgent images"
echo "   version:        $VERSION"
echo "   proxy:          $PROXY"
echo "   pip index:      $PIP_INDEX_URL"
echo "   npm mirror:     $NPM_REGISTRY"
echo "   skip_base:      $SKIP_BASE"
echo "   skip_asset_scan: $SKIP_ASSET_SCAN"
echo "============================================================"

BUILD_PROXY_ARGS=(
    --build-arg HTTP_PROXY="$PROXY"
    --build-arg HTTPS_PROXY="$PROXY"
    --build-arg NO_PROXY="$NO_PROXY"
)
PIP_ARGS=(
    --build-arg PIP_INDEX_URL="$PIP_INDEX_URL"
    --build-arg PIP_TRUSTED_HOST="$PIP_TRUSTED_HOST"
)

# 1) base 镜像 (secagent-base:<ver>) -------------------------------------
# V13 (2026-08-07): 之前 build-images.sh 漏建 base, 直接构建服务层会失败
# (FROM secagent-base:0.1.0 not found). 现在先建 base 再建服务.
if [[ "$SKIP_BASE" != "1" ]]; then
    echo
    echo "[1/N] Building base image..."
    docker build \
        -t "secagent-base:${VERSION}" \
        -f deployments/prod/docker/Dockerfile.base \
        "${BUILD_PROXY_ARGS[@]}" \
        "${PIP_ARGS[@]}" \
        .
else
    echo
    echo "[1/N] Skipping base image (SKIP_BASE=1)"
fi

# 2) api + 3) scan-engine + 4) asset-scan 等服务 ------------------------
step=2
build_service() {
    local name="$1"
    local dockerfile="$2"
    shift 2
    local extra=("$@")
    echo
    echo "[$step/N] Building ${name}..."
    docker build \
        -t "secagent-${name}:${VERSION}" \
        -f "deployments/prod/docker/Dockerfile.${dockerfile}" \
        "${BUILD_PROXY_ARGS[@]}" \
        "${PIP_ARGS[@]}" \
        "${extra[@]}" \
        .
    step=$((step + 1))
}

build_service api        api
build_service scan-engine scan-engine
build_service graphrag   graphrag
build_service celery     celery
build_service ai         ai
build_service preprocessing preprocessing

# 3) asset-scan (独立构建, 涉及 asset-pkgs COPY) -----------------------
# V13 (2026-08-07): asset-scan 此前完全没构建入口, 此处补上.
# Dockerfile 双轨: 含 asset-pkgs/ 时离线安装, 否则 apt + GitHub.
if [[ "$SKIP_ASSET_SCAN" != "1" ]]; then
    echo
    echo "[$step/N] Building asset-scan (offline-first if asset-pkgs present)..."
    if [[ -d "$ROOT/deployments/prod/asset-pkgs" ]]; then
        echo "  asset-pkgs/ detected ($(du -sh "$ROOT/deployments/prod/asset-pkgs" | cut -f1))"
    else
        echo "  asset-pkgs/ MISSING; Dockerfile will fall back to apt + GitHub"
    fi
    docker build \
        -t "secagent-asset-scan:${VERSION}" \
        -f deployments/prod/docker/Dockerfile.asset-scan \
        "${BUILD_PROXY_ARGS[@]}" \
        "${PIP_ARGS[@]}" \
        .
    step=$((step + 1))
else
    echo
    echo "[$step/N] Skipping asset-scan (SKIP_ASSET_SCAN=1)"
    step=$((step + 1))
fi

# 4) gateway + 5) frontend -----------------------------------------------
build_service gateway  gateway
build_service frontend frontend

echo
echo "============================================================"
echo "Done. Built images:"
docker images | grep -E "secagent-" || true
