from typing import TypeVar, overload

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)
T = TypeVar("T", bound=BaseModel)


class ModelAdapter:
    """Unified LLM interface supporting Claude, OpenAI, and vLLM backends."""

    def __init__(self) -> None:
        settings = get_settings()
        self._provider = settings.llm_provider

        if self._provider == "claude":
            self._llm = ChatAnthropic(
                model="claude-sonnet-4-5",
                api_key=settings.anthropic_api_key,
                temperature=0.1,
                max_tokens=4096,
            )
        elif self._provider == "openai":
            kwargs = {
                "model": settings.openai_model,
                "api_key": settings.openai_api_key,
                "temperature": 0.1,
            }
            if settings.openai_base_url:
                kwargs["base_url"] = settings.openai_base_url
            self._llm = ChatOpenAI(**kwargs)
        else:  # vllm
            self._llm = ChatOpenAI(
                model=settings.vllm_model,
                base_url=settings.vllm_base_url,
                temperature=0.1,
            )

    @overload
    async def chat_completion(
        self, messages: list[dict[str, str]], schema: type[T], temperature: float = 0.1
    ) -> T: ...

    @overload
    async def chat_completion(
        self, messages: list[dict[str, str]], schema: None = None, temperature: float = 0.1
    ) -> str: ...

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        schema: type[T] | None = None,
        temperature: float = 0.1,
    ) -> T | str:
        # 保留 system / user / assistant 各类消息
        lc_messages = []
        for m in messages:
            if m["role"] == "system":
                lc_messages.append(SystemMessage(content=m["content"]))
            elif m["role"] in ("user", "assistant"):
                lc_messages.append(HumanMessage(content=m["content"]))

        # 透传 temperature
        self._llm.temperature = temperature

        if schema is not None:
            structured_llm = self._llm.with_structured_output(schema)
            result = await structured_llm.ainvoke(lc_messages)
            return result  # type: ignore[return-value]
        response = await self._llm.ainvoke(lc_messages)
        return str(response.content)


_adapter: ModelAdapter | None = None


def get_model_adapter() -> ModelAdapter:
    global _adapter
    if _adapter is None:
        _adapter = ModelAdapter()
    return _adapter
