"""ai 服务入口(阶段 3)。

承载 chat/scan_chat/models 等 LLM 路由。网关入口路径不变(/api/v1/chat 等),
由 gateway 通过 httpx 反代(见 src/api/gateway_proxy.py 阶段 3-2)。

- lifespan:加载 Nacos 配置(shared + ai dataId);
- 路由:include src.api.routers.{chat,scan_chat,models}
- /healthz:基础检查 + Nacos 配置加载状态
- uvicorn --host 127.0.0.1 --port 8001(由 entrypoint-ai.sh 提供)
- 双轨过渡期由 gateway AI_PROXY_ENABLED env 控制(阶段 3-2;**阶段 5 已删**,反代是唯一路径)。
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.common.logging.logger import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """ai 服务 lifespan:加载 Nacos 配置(多 dataId 合并指纹,阶段 0-2)。"""
    logger.info("ai_starting")
    try:
        from src.common.config.settings import load_nacos_settings

        await load_nacos_settings()
        logger.info("ai_nacos_settings_loaded")
    except Exception as exc:  # noqa: BLE001
        # Nacos 不可达时静默回退到 env-only 配置(与原 api/main.py 一致)
        logger.warning("ai_nacos_settings_load_failed", error=str(exc))
    yield
    logger.info("ai_stopping")


app = FastAPI(
    title="secagent-ai",
    version="0.1.0",
    description="LLM/对话/意图/系统问答/联网搜索/模型管理独立服务",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict[str, str]:
    """健康检查。"""
    return {"status": "ok", "service": "ai"}


# 阶段 3-1:include LLM 路由(路径与 gateway 旧版一致 /api/v1/...)
from src.ai.routers.vulnscan_parse import router as vulnscan_parse_router  # noqa: E402
from src.api.routers.chat import router as chat_router  # noqa: E402
from src.api.routers.models import router as models_router  # noqa: E402
from src.api.routers.scan_chat import router as scan_chat_router  # noqa: E402

app.include_router(chat_router)
app.include_router(scan_chat_router)
app.include_router(models_router)
app.include_router(vulnscan_parse_router)
# 阶段 5:/metrics 端点(prometheus_client)
from src.common.metrics import metrics_router as _metrics_router  # noqa: E402

app.include_router(_metrics_router)


# 避免 ruff 误判 asyncio 未使用
_ = asyncio
