import re
from dataclasses import dataclass
from typing import Literal


MaskType = Literal["credential", "pii", "hash"]


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    type: MaskType
    priority: int
    mask: str | None  # None means preserve (hash rules)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    rule: Rule


def apply_mask(text: str, span: Span) -> str:
    """Return the replacement string for a matched span."""
    rule = span.rule
    matched = text[span.start : span.end]

    if rule.mask is None:
        return matched  # hash: preserve as-is

    if rule.mask == "***":
        # For key=value patterns keep the key name
        if "=" in matched:
            key, _ = matched.split("=", 1)
            return f"{key}=***"
        if ":" in matched:
            key, _ = matched.split(":", 1)
            return f"{key}:***"
        return "***"

    if "{prefix3}" in rule.mask:
        return matched[:3] + "****" + matched[-4:]

    if "{prefix6}" in rule.mask:
        return matched[:6] + "********" + matched[-4:]

    if "{user_first}" in rule.mask:
        at_idx = matched.index("@")
        domain = matched[at_idx + 1 :]
        return matched[0] + "***@" + domain

    return rule.mask


def resolve_spans(spans: list[Span]) -> list[Span]:
    """Remove overlapping spans: higher priority wins; same priority → longer span wins."""
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda s: (-s.rule.priority, s.start))
    resolved: list[Span] = []
    last_end = -1

    for span in sorted(sorted_spans, key=lambda s: s.start):
        if span.start >= last_end:
            resolved.append(span)
            last_end = span.end

    return resolved
