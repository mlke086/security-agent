"""阶段 5 收尾 P0-2:vulnscan intent 解析端点(自 gateway 迁入)。

原位置:``src/api/routers/vulnscan.py::api_parse_intent``(gateway 镜像无 langchain,
该端点函数内 ``get_model_adapter`` 会 ModuleNotFoundError → 500)。

迁移到 ai 服务:ai 镜像带 langchain + langchain-openai/anthropic(无 langgraph),
``src/api/auth`` / ``src/agents/models`` / ``src/knowledge/models/adapter`` 均已在
ai 镜像 COPY 范围。gateway 侧通过 gateway_proxy 反代本端点(见
``src/api/gateway_proxy.PROXIED_PATH_PREFIXES``)。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from src.agents.models import ScanIntent
from src.api.auth.routes import require_role

router = APIRouter(prefix="/api/v1/vulnscan", tags=["vulnscan"])


@router.post("/tasks/parse")
async def api_parse_intent(
    body: dict[str, Any],
    current_user=Depends(require_role("admin", "analyst")),
):
    """解析自然语言意图 → ScanIntent(LLM 结构化输出)。

    原 gateway 实现迁入后路径前缀一致(/api/v1/vulnscan/tasks/parse),
    gateway 反代透传,调用方无感知。依赖 langchain 的 model adapter,
    仅存在于 ai 镜像,gateway 不再携带。
    """
    from src.knowledge.models.adapter import get_model_adapter

    adapter = get_model_adapter()
    intent_text = body.get("intent_text", "")
    result = await adapter.chat_completion(
        messages=[{"role": "user", "content": f"Parse: {intent_text}"}],
        schema=ScanIntent,
    )
    return result
