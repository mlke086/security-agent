#!/bin/bash
# =====================================================================
# 推送 Nacos 配置(运维独立调用,支持多 dataId)
# 阶段 5:从单 dataId security-agent.yaml 改造为多 dataId 循环推送,
# 与 deployments/prod/docker/nacos/*.yaml 一一对应。
#
# 用法:
#   NACOS_SERVER=http://127.0.0.1:8848 \
#   NACOS_USERNAME=nacos NACOS_PASSWORD=nacos \
#   bash push-nacos-config.sh
#
# 注意:
#   - 使用 Nacos OpenAPI v3(/admin/cs/config)
#   - 字段存在则覆盖(便于变更热更新)
#   - 默认 group=security(与 settings.py nacos_group 默认一致)
# =====================================================================

set -euo pipefail

NACOS_SERVER="${NACOS_SERVER:-http://127.0.0.1:8848}"
NACOS_USERNAME="${NACOS_USERNAME:-nacos}"
NACOS_PASSWORD="${NACOS_PASSWORD:-nacos}"
NACOS_NAMESPACE="${NACOS_NAMESPACE:-prod}"
# V12 5.12 (2026-08-02): group 必须小写 `security` —— 大写 SECURITY 会推到错 group
NACOS_GROUP="${NACOS_GROUP:-security}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NACOS_DIR="$ROOT/deployments/prod/docker/nacos"

# 阶段 5:dataId 列表与 nacos/*.yaml 一一对应(8 个文件)
DATA_IDS=(
    "security-agent-shared.yaml"
    "security-agent-gateway.yaml"
    "security-agent-ai.yaml"
    "security-agent-scan-engine.yaml"
    "security-agent-asset-scan.yaml"
    "security-agent-graphrag.yaml"
    "security-agent-celery.yaml"
    "security-agent-preprocessing.yaml"
)

if [[ ! -d "$NACOS_DIR" ]]; then
    echo "nacos config dir not found: $NACOS_DIR" >&2
    exit 1
fi

echo "[push-nacos-config] -> ${NACOS_SERVER}"
echo "  namespace=${NACOS_NAMESPACE}  group=${NACOS_GROUP}"
echo "  dataIds: ${#DATA_IDS[@]} files"

# 1) 登录拿 token(Nacos >= 2.x 强制要求)
TOKEN=$(curl -fsS -X POST "${NACOS_SERVER}/nacos/v1/auth/login" \
    -d "username=${NACOS_USERNAME}&password=${NACOS_PASSWORD}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('accessToken',''))")
if [[ -z "$TOKEN" ]]; then
    echo "ERROR: failed to get accessToken from ${NACOS_SERVER}/v1/auth/login" >&2
    exit 1
fi
echo "[push-nacos-config] got accessToken (${#TOKEN} chars)"

# 2) 循环推每个 dataId
FAILED=0
for data_id in "${DATA_IDS[@]}"; do
    # dataId 是 `security-agent-shared.yaml`, 本地文件是 `shared.yaml` (无 security-agent- 前缀),
    # 所以直接取 dataId 去掉 `security-agent-` 前缀即可, 不要追加 `.yaml`。
    config_file="$NACOS_DIR/${data_id#security-agent-}"
    if [[ ! -f "$config_file" ]]; then
        echo "[push-nacos-config] SKIP: $config_file not found" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    HTTP_CODE=$(curl -s -o /tmp/nacos_push.json -w "%{http_code}" \
        -X POST "${NACOS_SERVER}/nacos/v3/admin/cs/config" \
        -H "accessToken: ${TOKEN}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "dataId=${data_id}" \
        --data-urlencode "groupName=${NACOS_GROUP}" \
        --data-urlencode "namespaceId=${NACOS_NAMESPACE}" \
        --data-urlencode "type=yaml" \
        --data-urlencode "content=$(cat "$config_file")" \
        --data-urlencode "appName=security-agent" || true)

    if [[ "$HTTP_CODE" == "200" ]]; then
        echo "[push-nacos-config] OK   ${data_id}"
    else
        echo "[push-nacos-config] FAIL ${data_id} (HTTP $HTTP_CODE):" >&2
        cat /tmp/nacos_push.json >&2 || true
        echo >&2
        FAILED=$((FAILED + 1))
    fi
done

if [[ "$FAILED" -gt 0 ]]; then
    echo "[push-nacos-config] COMPLETED WITH ${FAILED} FAILURE(S)" >&2
    exit 1
fi
echo "[push-nacos-config] ALL ${#DATA_IDS[@]} dataIds OK"