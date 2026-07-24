#!/bin/bash
# =====================================================================
# 推送 Nacos 配置(运维独立调用)
# 用法:
#   NACOS_SERVER=http://127.0.0.1:8848 \
#   NACOS_USERNAME=nacos NACOS_PASSWORD=nacos \
#   bash push-nacos-config.sh
#
# 注意:
#   - 使用 Nacos OpenAPI v3(/admin/cs/config)
#   - 已存在则覆盖,内容变化后应用通过 long-poll 热加载
# =====================================================================

set -euo pipefail

NACOS_SERVER="${NACOS_SERVER:-http://127.0.0.1:8848}"
NACOS_USERNAME="${NACOS_USERNAME:-nacos}"
NACOS_PASSWORD="${NACOS_PASSWORD:-nacos}"
NACOS_NAMESPACE="${NACOS_NAMESPACE:-prod}"
NACOS_GROUP="${NACOS_GROUP:-SECURITY}"
NACOS_DATA_ID="${NACOS_DATA_ID:-security-agent.yaml}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG_FILE="$ROOT/deployments/prod/docker/nacos-config.yaml"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "config file not found: $CONFIG_FILE" >&2
    exit 1
fi

echo "[push-nacos-config] -> ${NACOS_SERVER}"
echo "  namespace=${NACOS_NAMESPACE}  group=${NACOS_GROUP}  dataId=${NACOS_DATA_ID}"

# 1) 登录拿 token(Nacos >= 2.x 要求)
TOKEN=$(curl -fsS -X POST "${NACOS_SERVER}/nacos/v1/auth/login" \
    -d "username=${NACOS_USERNAME}&password=${NACOS_PASSWORD}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('accessToken',''))")
if [[ -z "$TOKEN" ]]; then
    echo "ERROR: failed to get accessToken from ${NACOS_SERVER}/v1/auth/login" >&2
    exit 1
fi
echo "[push-nacos-config] got accessToken (${#TOKEN} chars)"

# 2) 推送配置(POST v3 接口:不存在则创建,已存在则更新)
HTTP_CODE=$(curl -s -o /tmp/nacos_push.json -w "%{http_code}" \
    -X POST "${NACOS_SERVER}/nacos/v3/admin/cs/config" \
    -H "accessToken: ${TOKEN}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "dataId=${NACOS_DATA_ID}" \
    --data-urlencode "groupName=${NACOS_GROUP}" \
    --data-urlencode "namespaceId=${NACOS_NAMESPACE}" \
    --data-urlencode "type=yaml" \
    --data-urlencode "content=$(cat "$CONFIG_FILE")" \
    --data-urlencode "appName=security-agent" || true)

if [[ "$HTTP_CODE" == "200" ]]; then
    echo "[push-nacos-config] OK"
    exit 0
fi

echo "[push-nacos-config] FAILED (HTTP $HTTP_CODE):" >&2
cat /tmp/nacos_push.json >&2 || true
exit 1
