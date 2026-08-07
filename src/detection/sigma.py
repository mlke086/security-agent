"""Minimal Sigma rule parser (Phase 3 of monitoring plan).

Scope: title, id, description, author, level, logsource, detection, fields, tags.
Detection: single selection block + condition: selection.
Operators: gte / lte / gt / lt / eq / neq / contains / startswith.
Field paths: dotted notation (data.srcip).
"""

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class RuleLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse(cls, raw):
        if not raw:
            return cls.MEDIUM
        try:
            return cls(raw.lower())
        except ValueError:
            return cls.MEDIUM


class Operator(StrEnum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    EXISTS = "exists"

    @classmethod
    def parse(cls, raw):
        if not raw:
            return cls.EQ
        try:
            return cls(raw.lower())
        except ValueError:
            return cls.EQ


@dataclass(frozen=True)
class FieldPredicate:
    field: str
    op: Operator
    value: Any

    @classmethod
    def from_yaml(cls, raw, value):
        if "|" in raw:
            field, op = raw.split("|", 1)
            op = Operator.parse(op)
        else:
            field, op = raw, Operator.EQ
        return cls(field=field, op=op, value=value)


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str = ""
    level: RuleLevel = RuleLevel.MEDIUM
    product: str = ""
    service: str = ""
    category: str = ""
    detection_fields: list = field(default_factory=list)
    selection: list = field(default_factory=list)
    # V13 P1-3: keep every selection block, not just the first one. The
    # Sigma ``1 of selection_*`` condition is OR-of-blocks -- dropping the
    # other blocks silently turned it into AND-of-first-block and missed
    # detections whose behaviour only matched a later block.
    pred_lists: list = field(default_factory=list)
    condition_mode: str = "selection"  # "selection" | "1of" | "all"
    tags: list = field(default_factory=list)
    source_path: str | None = field(default=None)

    def __repr__(self):
        return "SigmaRule(id=" + repr(self.rule_id) + ", level=" + repr(self.level) + ")"


def _coerce(v):
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        try:
            if "." in v:
                return float(v)
            return int(v)
        except ValueError:
            return v
    return v


def _event_get(event, path, default=None):
    node = event
    for part in path.split("."):
        if not isinstance(node, dict):
            return default
        node = node.get(part)
        if node is None:
            return default
    return node


def _compare(actual, op, expected):
    if actual is None:
        return False
    if op is Operator.EQ:
        return actual == expected
    if op is Operator.NEQ:
        return actual != expected
    if op in (Operator.GT, Operator.GTE, Operator.LT, Operator.LTE):
        a, b = _coerce(actual), _coerce(expected)
        try:
            if op is Operator.GT:
                return a > b
            if op is Operator.GTE:
                return a >= b
            if op is Operator.LT:
                return a < b
            if op is Operator.LTE:
                return a <= b
        except TypeError:
            return False
    # Sigma spec: contains/startswith are case-insensitive string matchers.
    if op is Operator.CONTAINS:
        try:
            return str(expected).lower() in str(actual).lower()
        except (TypeError, ValueError):
            return False
    if op is Operator.STARTSWITH:
        try:
            return str(actual).lower().startswith(str(expected).lower())
        except (TypeError, ValueError):
            return False
    if op is Operator.EXISTS:
        return actual is not None
    return False


def _block_matches(rule, event, block) -> dict | None:
    """Match one selection block (all predicates AND). Returns the matched
    field values, or None if any predicate fails."""
    matched_fields = {}
    for pred in block:
        actual = _event_get(event, pred.field)
        if not _compare(actual, pred.op, pred.value):
            return None
        matched_fields[pred.field] = actual
    return matched_fields


def matches(rule, event):
    if not rule.selection:
        return False, {}
    # Logsource filter only applies when the event declares logsource.
    # Many upstream sources (raw syslog, EDR forwarders) do not stamp
    # logsource on the event itself; the routing layer / EDR normalizer
    # is expected to have already filtered by source. Matching without
    # the metadata would otherwise reject every event that lacks it.
    event_logsource = _event_get(event, "logsource") or {}
    if rule.product:
        ep = event_logsource.get("product") if isinstance(event_logsource, dict) else None
        if ep and rule.product != ep:
            return False, {}
    if rule.service:
        es = event_logsource.get("service") if isinstance(event_logsource, dict) else None
        if es and rule.service != es:
            return False, {}
    # V13 P1-3: honour the full condition semantics.
    #   "selection"      -> single block, all predicates AND
    #   "1 of selection_*" / "1 of them" -> any block matching is a hit
    #   "all of them"    -> every block must match
    blocks = rule.pred_lists or ([rule.selection] if rule.selection else [])
    if rule.condition_mode == "1of":
        for block in blocks:
            matched = _block_matches(rule, event, block)
            if matched is not None:
                return _finish_match(rule, event, matched)
        return False, {}
    if rule.condition_mode == "all":
        merged: dict = {}
        for block in blocks:
            matched = _block_matches(rule, event, block)
            if matched is None:
                return False, {}
            merged.update(matched)
        return _finish_match(rule, event, merged)
    # "selection" (default): single AND block
    matched = _block_matches(rule, event, blocks[0] if blocks else rule.selection)
    if matched is None:
        return False, {}
    return _finish_match(rule, event, matched)


def _finish_match(rule, event, matched_fields) -> tuple:
    for path in rule.detection_fields:
        val = _event_get(event, path)
        if val is not None and path not in matched_fields:
            matched_fields[path] = val
    return True, matched_fields


def parse_sigma_yaml(path):
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return parse_sigma_dict(data, source_path=str(p))


def _selection_blocks(selection: dict) -> list[list[FieldPredicate]]:
    """A Sigma selection is either a flat map of field predicates
    (``selection: {field: value}``) or a map of named blocks
    (``selection: {selection_a: {field: value}}``). Return one
    predicate list per block."""
    if not selection:
        return []
    if all(isinstance(v, dict) for v in selection.values()):
        # Named blocks form.
        return [
            [FieldPredicate.from_yaml(k2, v2) for k2, v2 in block.items()]
            for block in selection.values()
        ]
    # Flat form: the selection itself is a single block.
    return [[FieldPredicate.from_yaml(k, v) for k, v in selection.items()]]


def parse_sigma_dict(data, source_path=None):
    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping")
    detection = data.get("detection") or {}
    selection = detection.get("selection") or {}
    condition = detection.get("condition") or "selection"
    if condition != "selection" and not condition.startswith("1 of ") and condition != "all of them":
        raise ValueError(
            "unsupported Sigma condition: "
            + repr(condition)
            + " (MVP supports only selection / 1 of selection_* / 1 of them / all of them)"
        )
    # V13 P1-3: resolve every selection block. ``1 of selection_*`` /
    # ``1 of them`` are OR-of-blocks; ``all of them`` is AND-across-blocks.
    if condition == "all of them":
        pred_lists = _selection_blocks(selection)
        if not pred_lists:
            raise ValueError("all of them requires named selection blocks")
        mode = "all"
    elif condition.startswith("1 of "):
        prefix = condition[len("1 of ") :].strip()
        if not all(isinstance(v, dict) for v in selection.values()):
            raise ValueError(
                "1-of condition " + repr(condition) + " requires named selection blocks"
            )
        keys = list(selection.keys()) if prefix == "them" else [
            # Sigma prefixes are globs: ``1 of selection_*``.
            k for k in selection.keys() if k.startswith(prefix.rstrip("*"))
        ]
        if not keys:
            raise ValueError("1-of condition " + repr(condition) + " matches no selections")
        pred_lists = [
            [FieldPredicate.from_yaml(k2, v2) for k2, v2 in selection[k].items()] for k in keys
        ]
        mode = "1of"
    else:
        pred_lists = _selection_blocks(selection)
        mode = "selection"
    fields = data.get("fields") or []
    if isinstance(fields, str):
        fields = [fields]
    logsource = data.get("logsource") or {}
    return SigmaRule(
        rule_id=str(data.get("id") or data.get("title") or "unknown"),
        title=str(data.get("title") or "untitled"),
        description=str(data.get("description") or ""),
        level=RuleLevel.parse(data.get("level")),
        product=str(logsource.get("product") or ""),
        service=str(logsource.get("service") or ""),
        category=str(logsource.get("category") or ""),
        detection_fields=[str(f) for f in fields],
        selection=pred_lists[0] if pred_lists else [],
        pred_lists=pred_lists,
        condition_mode=mode,
        tags=[str(t) for t in (data.get("tags") or [])],
        source_path=source_path,
    )
