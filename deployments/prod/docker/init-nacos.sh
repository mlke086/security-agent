#!/bin/bash
# =====================================================================
# Nacos 配置推送脚本(部署时一次性 init,支持多 dataId)
# 阶段 5:从单 nacos-config.yaml 改为遍历 docker/nacos/*.yaml 7 个文件,
# 先 POST 创建,已存在则 fallback PUT 更新。
#
# 与 push-nacos-config.sh 区别:
#   - 本脚本是 init 容器入口(init-nacos service 在 compose 里),只跑一次
#   - push-nacos-config.sh 是运维脚本,可重复推(变更覆盖)
# - 调用 Nacos OpenAPI v3:
#       POST /nacos/v3/admin/cs/config  (创建)
#       PUT  /nacos/v3/admin/cs/config  (更新)
# =====================================================================

set -euo pipefail

NACOS_SERVER="${NACOS_SERVER:-http://127.0.0.1:8848}"
NACOS_USERNAME="${NACOS_USERNAME:-nacos}"
NACOS_PASSWORD="${NACOS_PASSWORD:-nacos}"
NACOS_NAMESPACE="${NACOS_NAMESPACE:-prod}"
# V12 5.12 (2026-08-02): group 必须小写 `security`,见 push-nacos-config.sh
NACOS_GROUP="${NACOS_GROUP:-security}"

# 阶段 5:dataId 与 nacos/*.yaml 一一对应
DATA_IDS=(
    "security-agent-shared.yaml"
    "security-agent-gateway.yaml"
    "security-agent-ai.yaml"
    "security-agent-scan-engine.yaml"
    "security-agent-graphrag.yaml"
    "security-agent-celery.yaml"
    "security-agent-preprocessing.yaml"
)

CONFIG_DIR="${1:-/app/deployments/prod/docker/nacos}"

if [[ ! -d "$CONFIG_DIR" ]]; then
    echo "[init-nacos] config dir not found: $CONFIG_DIR" >&2
    exit 1
fi

# 1) 登录拿 token
login() {
    curl -fsS -X POST "${NACOS_SERVER}/nacos/v1/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${NACOS_USERNAME}&password=${NACOS_PASSWORD}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('accessToken',''))"
}

# 2) 推送单个 dataId(POST 优先,失败则 PUT)
publish() {
    local token="$1"
    local data_id="$2"
    local config_file="$3"
    local body
    body=$(jq -Rs . < "$config_file")

    # 先 POST 创建
    local code
    code=$(curl -s -o /tmp/nacos_publish.json -w "%{http_code}" \
        -X POST "${NACOS_SERVER}/nacos/v3/admin/cs/config" \
        -H "accessToken: ${token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "dataId=${data_id}" \
        --data-urlencode "groupName=${NACOS_GROUP}" \
        --data-urlencode "namespaceId=${NACOS_NAMESPACE}" \
        --data-urlencode "type=yaml" \
        --data-urlencode "content=${body}" \
        --data-urlencode "appName=security-agent" || true)

    if [[ "$code" == "200" ]]; then
        echo "[init-nacos] created: ${data_id} @ ${NACOS_NAMESPACE}/${NACOS_GROUP}"
        return 0
    fi

    # 已存在 → PUT 更新
    code=$(curl -s -o /tmp/nacos_publish.json -w "%{http_code}" \
        -X PUT "${NACOS_SERVER}/nacos/v3/admin/cs/config" \
        -H "accessToken: ${token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "dataId=${data_id}" \
        --data-urlencode "groupName=${NACOS_GROUP}" \
        --data-urlencode "namespaceId=${NACOS_NAMESPACE}" \
        --data-urlencode "type=yaml" \
        --data-urlencode "content=${body}" \
        --data-urlencode "appName=security-agent" || true)

    if [[ "$code" == "200" ]]; then
        echo "[init-nacos] updated: ${data_id}"
        return 0
    fi

    echo "[init-nacos] FAIL ${data_id} (code=$code):" >&2
    cat /tmp/nacos_publish.json >&2 || true
    return 1
}

# 3) 等待 Nacos 可达(简易重试,30 次 × 2s = 60s)
for i in $(seq 1 30); do
    if curl -fsS "${NACOS_SERVER}/nacos/v1/auth/login" \
        -d "username=${NACOS_USERNAME}&password=${NACOS_PASSWORD}" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

token=$(login || true)
if [[ -z "$token" ]]; then
    echo "[init-nacos] WARN: anonymous mode (Nacos 未开启鉴权)" >&2
    token=""
fi

# 4) 循环推送每个 dataId
FAILED=0
for data_id in "${DATA_IDS[@]}"; do
    file_name="${data_id#security-agent-}.yaml"
    config_file="${CONFIG_DIR}/${file_name}"
    if [[ ! -f "$config_file" ]]; then
        echo "[init-nacos] SKIP: ${config_file} not found" >&2
        FAILED=$((FAILED + 1))
        continue
    fi
    if ! publish "$token" "$data_id" "$config_file"; then
        FAILED=$((FAILED + 1))
    fi
done

if [[ "$FAILED" -gt 0 ]]; then
    echo "[init-nacos] COMPLETED WITH ${FAILED} FAILURE(S)" >&2
    exit 1
fi
echo "[init-nacos] ALL ${#DATA_IDS[@]} dataIds OK"