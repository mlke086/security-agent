from typing import Any, TypeVar

from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_community.chat_models import ChatOpenAI as VLLMChat
from langchain_core.messages import HumanMessage
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
            self._llm = ChatOpenAI(
                model="gpt-4o",
                api_key=settings.openai_api_key,
                temperature=0.1,
            )
        else:  # vllm
            self._llm = VLLMChat(
                model=settings.vllm_model,
                base_url=settings.vllm_base_url,
                temperature=0.1,
            )

    async def chat_completion(
        self,
        messages: list[dict[str, str]],
        schema: type[T] | None = None,
        temperature: float = 0.1,
    ) -> T | str:
        lc_messages = [HumanMessage(content=m["content"]) for m in messages if m["role"] == "user"]

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
