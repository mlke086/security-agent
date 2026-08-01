from langchain_core.messages import AIMessage

from src.agents.models import ScanIntent
from src.knowledge.models.adapter import ModelAdapter


def test_scan_intent_preserves_engine():
    intent = ScanIntent.model_validate(
        {"targets": ["Rocky001"], "modules": ["baseline"], "engine": "nuclei"}
    )
    assert intent.engine == "nuclei"


def test_parse_structured_content_skips_reasoning_prefix():
    raw = (
        "<think>reasoning with {braces}</think>\n"
        '{"targets":["Rocky001"],"modules":["baseline"],"engine":"nuclei"}'
    )
    intent = ModelAdapter._parse_structured_content(raw, ScanIntent)
    assert intent.targets == ["Rocky001"]
    assert intent.engine == "nuclei"


async def test_json_mode_fallback_parses_prefixed_json():
    class FakeBound:
        def bind(self, **_kwargs):
            return self

        async def ainvoke(self, _messages):
            return AIMessage(
                content='<think>analysis</think>\n{"targets":["Rocky001"],"engine":"nuclei","resource_limit":{}}'
            )

    intent = await ModelAdapter()._json_mode_fallback(FakeBound(), [], ScanIntent)
    assert intent.targets == ["Rocky001"]
    assert intent.engine == "nuclei"
