#!/bin/sh
# 阶段 6.2:graphrag 服务 entrypoint(模型存在性 fail-fast)。
# 严禁静默降级(embedding 是调查链路核心)。
set -eu

MODEL_PATH="${EMBEDDING_MODEL_PATH:-/opt/models/bge-large-zh-v1.5}"
echo "graphrag_embedding_model_probe path=$MODEL_PATH" >&2

if [ ! -f "${MODEL_PATH}/config.json" ]; then
    echo "[FATAL] embedding model not found at ${MODEL_PATH}" >&2
    echo "[FATAL] mount -v /opt/models/bge-large-zh-v1.5:${MODEL_PATH} or set EMBEDDING_MODEL_PATH" >&2
    exit 1
fi

echo "graphrag_embedding_model_ok" >&2
exec "$@"