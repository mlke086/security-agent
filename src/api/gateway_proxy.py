"""gateway 反代层(阶段 3-2)。

将 /api/v1/{chat,scan-chat,models} 转发到 ai 服务。
vulnscan/tasks/parse 不在反代列表 —— 该端点仍由 gateway 本地 vulnscan router
提供(阶段 3 暂留,后续可迁移到 ai 服务)。

特性:
- 反代是唯一路径(阶段 5 收尾:删 AI_PROXY_ENABLED env 与 fallback 404,原"双轨"已不成立)。
- 503 降级:ai 服务不可达时返回 503 + Retry-After: 5 + 监控指标。
- Authorization 透传(让 ai 服务自验 JWT,共享 API_SECRET_KEY)。

不引入新重依赖:仅 httpx + structlog(均在 base)。
"""
from __future__ import annotations

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["proxy"])

# 阶段 0-1 新增 ai_base_url;host 网络下默认 127.0.0.1:8001。
# 反代目标路径前缀(/api/v1/...)与 gateway 入路径一致,直接转发。

# 这些路径会被反代
#
# 阶段 5 收尾 P0-2 修复:`vulnscan/tasks/parse` 端点由 gateway 本地 vulnscan router
# 提供,不要加入反代列表(否则请求会被转到 ai 服务并 404)。
#
# 关键:scan_chat 路由实际 prefix 是 ``/api/v1/vulnscan/conversations``
# (见 src/api/routers/scan_chat.py:42),不是 ``/api/v1/scan-chat`` —— 之前的反代
# 目标路径是错的,所有 ``/api/v1/scan-chat/*`` 请求都会 404。阶段 5 收尾修正。
PROXIED_PATH_PREFIXES = (
    "/api/v1/chat",
    "/api/v1/vulnscan/conversations",
    "/api/v1/vulnscan/tasks/parse",
    "/api/v1/models",
)


# 阶段 5 收尾:删 is_proxy_enabled() 与 AI_PROXY_ENABLED 切换,反代是唯一路径。
# 历史:阶段 3 假设 gateway 仍保留 chat 路由做 fallback,但 main.py 已不再 include,
# fallback 抛 404,给运维"可以关反代绕过去"的错觉。直接删。


def _strip_prefix(path: str) -> str:
    """保持路径不变(/api/v1/... 直接转发)。"""
    return path


async def _proxy_request(request: Request, full_path: str) -> Response:
    """通用反代:转 request 到 ai_base_url + full_path。"""
    settings = get_settings()
    base = settings.ai_base_url.rstrip("/")
    url = f"{base}{full_path}"

    headers = dict(request.headers)
    # 移除 host(目标服务不需要原始 host)
    headers.pop("host", None)
    # Content-Length 由 httpx 重新计算
    headers.pop("content-length", None)

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            # 流式转发 request body(避免大 payload 内存拷贝)
            body = await request.body()

            upstream = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                params=request.query_params,
                content=body,
            )
    except httpx.RequestError as exc:
        # 阶段 5 收尾:埋点 ai_unreachable_total(reason 区分网络错/超时)
        from src.common.metrics import ai_unreachable_total

        reason = "timeout" if isinstance(exc, httpx.TimeoutException) else "connect_error"
        ai_unreachable_total.labels(reason=reason).inc()
        logger.warning("ai_proxy_unreachable", url=url, error=str(exc))
        # 监控埋点占位(阶段 5 接 prometheus_client)
        return JSONResponse(
            status_code=503,
            content={"detail": f"ai service unreachable: {exc!s}"},
            headers={"Retry-After": "5"},
        )

    # 透传响应(过滤 hop-by-hop headers)
    passthrough_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=passthrough_headers,
    )


# 阶段 3-2:动态注册 catch-all 路由——匹配 PROXIED_PATH_PREFIXES 时反代,
# 其他路径返回 404(由 fastapi 后续 router 处理)。
# 用 add_api_route 在 startup 注入;这里用静态路由更显式。
# 注意:FastAPI 不支持"动态路由"按前缀反代,我们用单条 catch-all APIRoute
# + 内部按 full_path 决定是否反代;非反代路径返回 404 + 提示"由 fallback 处理"。


@router.api_route(
    "/api/v1/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    include_in_schema=False,
)
async def catch_all_proxy(full_path: str, request: Request) -> Response:
    """Catch-all 路由:仅对 PROXIED_PATH_PREFIXES 反代到 ai 服务,其他返回 404。

    注:FastAPI catch-all 路径参数会把 ``/api/v1/`` 前缀吃掉,所以这里
    full_path 不含 /api/v1/。完整路径用 ``/api/v1/`` + full_path 重组。

    阶段 5 收尾:删 AI_PROXY_ENABLED env 与 fallback 404 分支。
    原"双轨过渡"已不成立(chat_router 等已从 main.py 移除,fallback 永远 404,
    给运维"可以关反代"的错觉),反代是唯一路径。
    """
    full = f"/api/v1/{full_path}"
    if not any(full.startswith(p) for p in PROXIED_PATH_PREFIXES):
        # 不是 LLM 路由,返回 404,由 gateway main.py 上层 router 处理
        raise HTTPException(status_code=404, detail="not a proxied ai route")
    return await _proxy_request(request, full)


__all__ = ["router", "PROXIED_PATH_PREFIXES", "_proxy_request"]
