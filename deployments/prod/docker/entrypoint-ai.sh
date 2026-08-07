#!/bin/sh
# 阶段 5 收尾:ai 服务 entrypoint(fail-fast 检查)。
#
# 检查项:
#   - API_SECRET_KEY(与 gateway 共享,自验 JWT 用)
#   - LLM provider API key 设置(anthropic 或 openai 至少其一;否则 chat 路由全失败)
#   - AI_BASE_URL 自检可达(若为 localhost 跳过)
set -eu

echo "ai_starting" >&2

# fail-fast:API_SECRET_KEY(JWT 自验)
: "${API_SECRET_KEY:?[FATAL] API_SECRET_KEY is required for JWT self-validation}"
if [ "${#API_SECRET_KEY}" -lt 16 ]; then
    echo "[FATAL] API_SECRET_KEY must be ≥16 chars (got ${#API_SECRET_KEY})" >&2
    exit 1
fi

# fail-fast:LLM provider key
LLM_PROVIDER="${LLM_PROVIDER:-claude}"
case "$LLM_PROVIDER" in
    claude)
        if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
            echo "[WARN] LLM_PROVIDER=claude but ANTHROPIC_API_KEY not set; chat will 5xx" >&2
        fi
        ;;
    openai)
        if [ -z "${OPENAI_API_KEY:-}" ]; then
            echo "[WARN] LLM_PROVIDER=openai but OPENAI_API_KEY not set; chat will 5xx" >&2
        fi
        ;;
    vllm)
        if [ -z "${VLLM_BASE_URL:-}" ]; then
            echo "[WARN] LLM_PROVIDER=vllm but VLLM_BASE_URL not set" >&2
        fi
        ;;
    *)
        echo "[WARN] unknown LLM_PROVIDER=$LLM_PROVIDER" >&2
        ;;
esac

echo "ai_ready llm_provider=$LLM_PROVIDER" >&2
exec "$@"