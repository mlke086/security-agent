#!/bin/bash
# =====================================================================
# 部署前自检:.env 是否完整、docker-compose 是否能解析
# 用法:  bash deployments/prod/check-env.sh
# =====================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/deployments/prod"

echo "[check-env] validating .env ..."

if [[ ! -f .env ]]; then
    echo "[check-env] FAIL: .env not found. Run: cp .env.example .env && vim .env"
    exit 1
fi

# 必填的引导密钥
required=(
    PG_PASSWORD
    NACOS_PASSWORD
    API_SECRET_KEY
    AGENT_SIGNING_KEY
    AGENT_CONSOLE_EXTERNAL_URL
)

ok=1
for k in "${required[@]}"; do
    v=$(grep -E "^${k}=" .env | head -1 | cut -d= -f2- || true)
    if [[ -z "$v" || "$v" == *"change-me"* ]]; then
        echo "  [ ] $k  -- MISSING or placeholder"
        ok=0
    else
        echo "  [x] $k  -- set"
    fi
done

# API_SECRET_KEY 长度校验(>=16, 推荐 >=32)
api_key=$(grep -E "^API_SECRET_KEY=" .env | cut -d= -f2- || true)
if [[ ${#api_key} -lt 16 ]]; then
    echo "  [!] API_SECRET_KEY 长度 ${#api_key} < 16,建议 openssl rand -hex 32"
    ok=0
fi

# AGENT_SIGNING_KEY 必须 64 hex
sign_key=$(grep -E "^AGENT_SIGNING_KEY=" .env | cut -d= -f2- || true)
if [[ -n "$sign_key" && ! "$sign_key" =~ ^[0-9a-f]{64}$ ]]; then
    echo "  [!] AGENT_SIGNING_KEY 不是 64 hex 格式"
    ok=0
fi

# 检查端口是否被占用
port=$(grep -E "^FRONTEND_PORT=" .env | cut -d= -f2- || echo 8081)
if command -v ss >/dev/null 2>&1 && ss -ltn "( sport = :${port} )" | grep -q LISTEN; then
    echo "  [!] FRONTEND_PORT=${port} 已被占用,改 .env 里 FRONTEND_PORT"
fi

# 检查 docker-compose 能否解析
if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
        echo "[check-env] docker compose (v2):"
        docker compose -f docker-compose.yml config -q && echo "  [x] compose config OK" || { echo "  [!] compose config 失败"; ok=0; }
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "[check-env] docker-compose (v1):"
        docker-compose -f docker-compose.yml config -q && echo "  [x] compose config OK" || { echo "  [!] compose config 失败"; ok=0; }
    else
        echo "  [!] 未检测到 docker / docker-compose"
    fi
fi

if [[ $ok -eq 1 ]]; then
    echo "[check-env] OK -- 可以运行 docker compose up"
    exit 0
else
    echo "[check-env] FAIL -- 修上面标红/感叹号的项目"
    exit 1
fi