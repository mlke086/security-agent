from typing import TypeVar, overload

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)
T = TypeVar("T", bound=BaseModel)


class ModelNotFoundError(Exception):
    """Raised when a caller-specified model_id no longer exists in the DB.

    P1-5 修复：区分「默认模型缺失（回退 .env）」与「指定模型已删除（应报错）」。
    前者静默回退是合理的（系统启动初期/PG 不可用），后者会让用户以为用模型 A
    实际用模型 B，必须显式失败。
    """


class ModelAdapter:
    """Unified LLM interface supporting claude / openai / vllm backends.

    需求4（模型管理）：模型配置从 PG ``llm_models`` 表读取（默认模型或调用方指定的
    ``model_id``），运行时可切换、无需重启。首次取默认模型时若表为空，会从 .env
    迁移一条配置作为默认，保证旧部署平滑过渡。已构造的 LangChain 客户端按
    ``model_id`` 缓存；模型配置变更后调用 ``invalidate()`` 清缓存。

    保留 ``chat_completion(messages, schema, temperature)`` 旧签名，所有现有调用
    点（7 个节点 + 路由）无需改动；新增可选 ``model_id`` 参数支持按模型调用。
    """

    # P2-3 修复：缓存 TTL。进程级缓存无法跨 worker 广播 invalidate，多 worker
    # 下 admin 改模型后其他 worker 仍持旧客户端。加 TTL 让缓存最多存活 60s，
    # 配合 invalidate（同 worker 立即生效），把跨 worker 不一致窗口收敛到 60s。
    _CACHE_TTL_SEC = 60

    def __init__(self) -> None:
        # model_id(或 "default") -> (provider, llm, cached_at_monotonic)
        self._cache: dict[str, tuple[str, BaseChatModel, float]] = {}

    async def _resolve(self, model_id: int | None) -> tuple[str, BaseChatModel]:
        """Resolve a model_id (None=default) to a (provider, llm) pair, cached."""
        import time

        cache_key = str(model_id) if model_id is not None else "default"
        cached = self._cache.get(cache_key)
        if cached is not None:
            provider, llm, cached_at = cached
            if (time.monotonic() - cached_at) < self._CACHE_TTL_SEC:
                return provider, llm
            # TTL 过期，淘汰重读
            self._cache.pop(cache_key, None)

        from src.knowledge.models.store import (
            get_default_model,
            get_model,
            migrate_env_model_if_empty,
        )

        cfg = None
        try:
            if model_id is not None:
                cfg = await get_model(model_id)
            else:
                # Ensure the table is seeded from .env on first use.
                await migrate_env_model_if_empty()
                cfg = await get_default_model()
        except Exception as exc:
            logger.warning("llm_model_resolve_failed", model_id=model_id, error=str(exc))
            cfg = None

        if cfg is None:
            # P1-5 修复：调用方显式指定了 model_id 却查不到（已删除）-> 抛错，
            # 不静默回退 .env（否则用户以为用模型 A 实际用 .env 模型 B）。
            # 仅 model_id is None（走默认）时才允许 .env 兜底。
            if model_id is not None:
                raise ModelNotFoundError(f"模型 id={model_id} 不存在或已删除")
            # Fallback: build from .env so the adapter still works before any
            # model has been configured / when PG is unavailable.
            llm, provider = self._build_from_env()
            self._cache[cache_key] = (provider, llm, time.monotonic())
            return provider, llm

        llm = self._build_llm(cfg)
        self._cache[cache_key] = (cfg.provider, llm, time.monotonic())
        return cfg.provider, llm

    @staticmethod
    def _build_llm(cfg) -> BaseChatModel:
        """Construct a LangChain chat client from a ModelConfig."""
        if cfg.provider == "claude":
            return ChatAnthropic(
                model=cfg.model_name,
                api_key=cfg.api_key,
                temperature=cfg.temperature,
                max_tokens=cfg.max_tokens,
            )
        # openai / vllm -> OpenAI-compatible protocol via ChatOpenAI.
        kwargs = {
            "model": cfg.model_name,
            "api_key": cfg.api_key or "EMPTY",
            "temperature": cfg.temperature,
        }
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        return ChatOpenAI(**kwargs)

    @staticmethod
    def _build_from_env() -> tuple[BaseChatModel, str]:
        """Env fallback (pre-DB / PG-unavailable). Returns (llm, provider)."""
        settings = get_settings()
        provider = settings.llm_provider
        if provider == "claude":
            llm = ChatAnthropic(
                model="claude-sonnet-4-5",
                api_key=settings.anthropic_api_key,
                temperature=0.1,
                max_tokens=4096,
            )
        elif provider == "openai":
            kwargs = {
                "model": settings.openai_model,
                "api_key": settings.openai_api_key,
                "temperature": 0.1,
            }
            if settings.openai_base_url:
                kwargs["base_url"] = settings.openai_base_url
            llm = ChatOpenAI(**kwargs)
        else:  # vllm
            llm = ChatOpenAI(
                model=settings.vllm_model,
                base_url=settings.vllm_base_url,
                api_key=settings.openai_api_key or "EMPTY",
                temperature=0.1,
            )
        return llm, provider

    def invalidate(self, model_id: int | None = None) -> None:
        """Drop cached client(s). Call after a model config is edited/deleted.
        model_id=None clears the entire cache."""
        if model_id is None:
            self._cache.clear()
        else:
            self._cache.pop(str(model_id), None)
            self._cache.pop("default", None)  # default may have referenced it

    @overload
    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        schema: type[T],
        temperature: float = 0.1,
        model_id: int | None = None,
    ) -> T: ...

    @overload
    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        schema: None = None,
        temperature: float = 0.1,
        model_id: int | None = None,
    ) -> str: ...

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        schema: type[T] | None = None,
        temperature: float = 0.1,
        model_id: int | None = None,
    ) -> T | str:
        # P1-KNOW-03 (2026-07-20): four bugs fixed here.
        # 1) assistant role was incorrectly mapped to HumanMessage, polluting
        #    multi-turn reasoning with an apparent user turn.
        # 2) Unknown roles (tool / function / custom) were silently dropped.
        #    We now raise so the caller can decide (cheaper than debugging
        #    empty completions downstream).
        # 3) self._llm.temperature = temperature mutated the SHARED singleton
        #    ChatOpenAI / ChatAnthropic instance, causing concurrent requests
        #    to race on temperature. We now bind temperature per call via
        #    .bind(temperature=...) so each invocation gets its own value.
        # 4) self._llm.with_structured_output(schema) calls without temperature
        #    would use the (possibly mutated) singleton's temperature; the
        #    bind happens BEFORE with_structured_output so it cascades.
        lc_messages = []
        for m in messages:
            role = m.get("role", "")
            if role == "system":
                lc_messages.append(SystemMessage(content=m["content"]))
            elif role == "user":
                lc_messages.append(HumanMessage(content=m["content"]))
            elif role == "assistant":
                lc_messages.append(AIMessage(content=m["content"]))
            else:
                # Unknown role: refuse rather than silently drop.
                raise ValueError(
                    f"ModelAdapter: unsupported message role {role!r}; "
                    "expected one of system / user / assistant"
                )

        _, llm = await self._resolve(model_id)
        # Per-request temperature (avoids racing the cached singleton).
        bound = llm.bind(temperature=temperature)

        if schema is not None:
            structured_llm = bound.with_structured_output(schema)
            result = await structured_llm.ainvoke(lc_messages)
            return result
        response = await bound.ainvoke(lc_messages)
        return str(response.content)


_adapter: ModelAdapter | None = None


def get_model_adapter() -> ModelAdapter:
    global _adapter
    if _adapter is None:
        _adapter = ModelAdapter()
    return _adapter
