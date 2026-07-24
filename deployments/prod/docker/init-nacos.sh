#!/bin/bash
# =====================================================================
# Nacos 配置推送脚本
# 把 nacos-config.yaml 推送到 Nacos,作为生产环境的集中配置源。
# - 幂等:已存在则覆盖更新(便于变更热加载)。
# - 调用 Nacos OpenAPI v3:
#       POST /nacos/v3/admin/cs/config  (发布 / 更新)
# =====================================================================

set -euo pipefail

NACOS_SERVER="${NACOS_SERVER:-http://127.0.0.1:8848}"
NACOS_USERNAME="${NACOS_USERNAME:-nacos}"
NACOS_PASSWORD="${NACOS_PASSWORD:-nacos}"
NACOS_NAMESPACE="${NACOS_NAMESPACE:-prod}"
NACOS_GROUP="${NACOS_GROUP:-SECURITY}"
NACOS_DATA_ID="${NACOS_DATA_ID:-security-agent.yaml}"

CONFIG_FILE="${1:-/app/deployments/prod/docker/nacos-config.yaml}"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[init-nacos] config file not found: $CONFIG_FILE" >&2
    exit 1
fi

# 1) 登录拿 token(Nacos >= 2.x 强制要求)
login() {
    curl -fsS -X POST "${NACOS_SERVER}/nacos/v1/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${NACOS_USERNAME}&password=${NACOS_PASSWORD}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('accessToken',''))"
}

# 2) 发布 / 更新配置(POST = 创建;已存在则返回 400,我们降级用 PUT 更新)
publish() {
    local token="$1"
    local body
    body=$(jq -Rs . < "$CONFIG_FILE")

    # 先尝试创建
    local code
    code=$(curl -s -o /tmp/nacos_publish.json -w "%{http_code}" \
        -X POST "${NACOS_SERVER}/nacos/v3/admin/cs/config" \
        -H "accessToken: ${token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "dataId=${NACOS_DATA_ID}" \
        --data-urlencode "groupName=${NACOS_GROUP}" \
        --data-urlencode "namespaceId=${NACOS_NAMESPACE}" \
        --data-urlencode "type=yaml" \
        --data-urlencode "content=${body}" \
        --data-urlencode "appName=security-agent" || true)

    if [[ "$code" == "200" ]]; then
        echo "[init-nacos] config created: ${NACOS_DATA_ID} @ ${NACOS_NAMESPACE}/${NACOS_GROUP}"
        return 0
    fi

    # 已存在:改用 update(POST 同接口,Nacos 在已存在时直接更新)
    code=$(curl -s -o /tmp/nacos_publish.json -w "%{http_code}" \
        -X PUT "${NACOS_SERVER}/nacos/v3/admin/cs/config" \
        -H "accessToken: ${token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "dataId=${NACOS_DATA_ID}" \
        --data-urlencode "groupName=${NACOS_GROUP}" \
        --data-urlencode "namespaceId=${NACOS_NAMESPACE}" \
        --data-urlencode "type=yaml" \
        --data-urlencode "content=${body}" \
        --data-urlencode "appName=security-agent" || true)

    if [[ "$code" == "200" ]]; then
        echo "[init-nacos] config updated: ${NACOS_DATA_ID}"
        return 0
    fi

    echo "[init-nacos] FAILED (code=$code):" >&2
    cat /tmp/nacos_publish.json >&2 || true
    return 1
}

# 3) 探测 Nacos 可达(简单轮询)
for i in {1..30}; do
    if curl -fsS "${NACOS_SERVER}/nacos/v1/auth/login" \
        -d "username=${NACOS_USERNAME}&password=${NACOS_PASSWORD}" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

token=$(login || true)
if [[ -z "$token" ]]; then
    echo "[init-nacos] WARN: anonymous mode (Nacos 未开启鉴权)"
    token=""
fi

publish "$token"
