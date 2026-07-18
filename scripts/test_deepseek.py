"""Quick test: DeepSeek API via our adapter."""
import sys
from src.common.logging.logger import configure_logging
configure_logging()

from src.knowledge.models.adapter import get_model_adapter
from pydantic import BaseModel, Field


class TestResult(BaseModel):
    answer: str = Field(description="A short response")
    confidence: float = Field(ge=0.0, le=1.0)


async def test():
    adapter = get_model_adapter()
    
    # Test 1: Simple chat
    result = await adapter.chat_completion(
        messages=[{"role": "user", "content": "Say hello in one word."}],
    )
    print(f"  [Chat] {result}")
    
    # Test 2: Structured output
    result = await adapter.chat_completion(
        messages=[{"role": "user", "content": "Say hello and give confidence 0.95."}],
        schema=TestResult,
    )
    print(f"  [Structured] answer={result.answer}, confidence={result.confidence}")
    
    print("\nDeepSeek integration: OK!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test())
