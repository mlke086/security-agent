"""LLM model management REST endpoints (需求4 模型管理)."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.knowledge.models import store as model_store
from src.knowledge.models.adapter import get_model_adapter

router = APIRouter(prefix="/api/v1/models", tags=["models"])


class ModelCreateRequest(BaseModel):
    # pydantic reserves the "model_" namespace; opt out so `model_name` is
    # accepted without a warning.
    model_config = ConfigDict(protected_namespaces=())

    name: str = Field(..., min_length=1, max_length=128)
    provider: str = Field(..., description="openai | claude | vllm")
    model_name: str = Field(..., min_length=1, max_length=128)
    api_key: str = ""
    base_url: str = ""
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1, le=200000)
    supports_structured: bool = True
    enabled: bool = True
    is_default: bool = False


class ModelUpdateRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    name: str | None = None
    provider: str | None = None
    model_name: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=200000)
    supports_structured: bool | None = None
    enabled: bool | None = None


def _serialize(m: model_store.ModelConfig) -> dict:
    # P0-1 安全：列表/详情不返回明文 api_key，仅返回是否已配置，避免泄露给
    # analyst 角色 / 浏览器侧 XSS 窃取。新 key 走独立字段提交。
    return {
        "id": m.id,
        "name": m.name,
        "provider": m.provider,
        "model_name": m.model_name,
        "has_key": bool(m.api_key),
        "base_url": m.base_url,
        "temperature": m.temperature,
        "max_tokens": m.max_tokens,
        "supports_structured": m.supports_structured,
        "enabled": m.enabled,
        "is_default": m.is_default,
    }


@router.get("")
async def api_list_models(current_user=Depends(require_role("admin", "analyst"))):
    models = await model_store.list_models()
    return {"items": [_serialize(m) for m in models]}


@router.post("")
async def api_create_model(
    req: ModelCreateRequest,
    current_user=Depends(require_role("admin")),
):
    if req.provider not in ("openai", "claude", "vllm"):
        raise HTTPException(status_code=422, detail="provider 必须是 openai/claude/vllm 之一")
    m = await model_store.create_model(
        name=req.name,
        provider=req.provider,
        model_name=req.model_name,
        api_key=req.api_key,
        base_url=req.base_url,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
        supports_structured=req.supports_structured,
        enabled=req.enabled,
        is_default=req.is_default,
    )
    get_model_adapter().invalidate()
    await get_audit_logger().log(
        event_id="model",
        node="models.router",
        action="create",
        actor=current_user.username,
        details={"id": m.id, "name": m.name},
    )
    return _serialize(m)


@router.patch("/{model_id}")
async def api_update_model(
    model_id: int,
    req: ModelUpdateRequest,
    current_user=Depends(require_role("admin")),
):
    fields = req.model_dump(exclude_none=True)
    if "provider" in fields and fields["provider"] not in ("openai", "claude", "vllm"):
        raise HTTPException(status_code=422, detail="provider 必须是 openai/claude/vllm 之一")
    m = await model_store.update_model(model_id, **fields)
    if not m:
        raise HTTPException(status_code=404, detail="模型不存在")
    get_model_adapter().invalidate()
    await get_audit_logger().log(
        event_id="model",
        node="models.router",
        action="update",
        actor=current_user.username,
        details={"id": model_id, "fields": list(fields.keys())},
    )
    return _serialize(m)


@router.delete("/{model_id}")
async def api_delete_model(
    model_id: int,
    current_user=Depends(require_role("admin")),
):
    was_default = await model_store.get_model(model_id)
    ok = await model_store.delete_model(model_id)
    if not ok:
        raise HTTPException(status_code=404, detail="模型不存在")
    get_model_adapter().invalidate()
    # 若删的是默认模型，自动把第一个启用的模型设为默认
    if was_default and was_default.is_default:
        remaining = await model_store.list_models()
        if remaining:
            await model_store.set_default_model(remaining[0].id)
            get_model_adapter().invalidate()
    await get_audit_logger().log(
        event_id="model",
        node="models.router",
        action="delete",
        actor=current_user.username,
        details={"id": model_id},
    )
    return {"status": "ok"}


@router.post("/{model_id}/default")
async def api_set_default(
    model_id: int,
    current_user=Depends(require_role("admin")),
):
    m = await model_store.set_default_model(model_id)
    if not m:
        raise HTTPException(status_code=404, detail="模型不存在")
    get_model_adapter().invalidate()
    await get_audit_logger().log(
        event_id="model",
        node="models.router",
        action="set_default",
        actor=current_user.username,
        details={"id": model_id},
    )
    return _serialize(m)


@router.post("/{model_id}/test")
async def api_test_model(
    model_id: int,
    current_user=Depends(require_role("admin")),
):
    """测试模型连通性：用该模型发一条简单 prompt，返回是否成功及响应。"""
    m = await model_store.get_model(model_id)
    if not m:
        raise HTTPException(status_code=404, detail="模型不存在")
    if not m.enabled:
        raise HTTPException(status_code=422, detail="模型已禁用，请先启用")
    adapter = get_model_adapter()
    try:
        reply = await adapter.chat_completion(
            messages=[{"role": "user", "content": "请回复：OK"}],
            model_id=model_id,
            temperature=0.0,
        )
        return {"ok": True, "reply": str(reply)[:500]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:500]}
