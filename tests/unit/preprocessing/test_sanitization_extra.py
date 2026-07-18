"""Additional sanitization tests — Span resolution and engine edge cases."""
from src.preprocessing.sanitization.engine import SanitizationEngine
from src.preprocessing.sanitization.mask import Rule, Span, apply_mask, resolve_spans

engine = SanitizationEngine()
import re

_rule = Rule(name="test", pattern=re.compile("."), type="pii", priority=1, mask="***")


class TestSpanResolution:
    def test_non_overlapping_spans(self):
        spans = [Span(start=0, end=3, rule=_rule), Span(start=10, end=15, rule=_rule)]
        result = resolve_spans(spans)
        assert len(result) == 2

    def test_same_priority_first_wins(self):
        spans = [Span(start=0, end=8, rule=_rule), Span(start=5, end=12, rule=_rule)]
        result = resolve_spans(spans)
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 8

    def test_nested_same_priority_outer_wins(self):
        spans = [Span(start=0, end=10, rule=_rule), Span(start=2, end=5, rule=_rule)]
        result = resolve_spans(spans)
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 10


class TestApplyMask:
    def test_basic_masking(self):
        result = apply_mask("password=s3cr3t", Span(start=0, end=16, rule=_rule))
        assert "s3cr3t" not in result
        assert "***" in result


class TestSanitizationEngine:
    def test_empty_text(self):
        assert engine.sanitize("") == ""

    def test_clean_text_no_change(self):
        t = "This is a normal security alert"
        assert engine.sanitize(t) == t

    def test_password_masking(self):
        result = engine.sanitize("password=s3cr3t123")
        assert "s3cr3t123" not in result
        assert "password=***" in result

    def test_phone_masking(self):
        result = engine.sanitize("Phone: 13812345678")
        assert "13812345678" not in result
        assert "138" in result

    def test_api_key_masking(self):
        result = engine.sanitize("api_key=sk-ant-abc1234567890")
        assert "sk-ant" not in result
