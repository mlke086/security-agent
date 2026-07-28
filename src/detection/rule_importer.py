"""Sigma rule importer (Phase 6 of monitoring plan).

Walks a directory of Sigma YAML files, parses each, and produces an
``ImportResult`` summarising what was accepted / rejected / skipped.
The MVP scope is deliberately small:

  - We do NOT clone the SigmaHQ repo here. The operator runs
    ``scripts/import_sigma_rules.py <path>`` against either a
    hand-cloned checkout, a downloaded tarball, or a curated subset.
    Git-clone is platform-specific (ssh keys, submodules) and is
    trivial to wrap around this entry point.
  - We accept any rule that ``parse_sigma_yaml`` can handle (which
    covers the two main ``condition`` shapes: ``selection`` and
    ``1 of selection_*``). Rules using ``aggregation``, ``near``,
    time windows, etc. are reported as "skipped" so the operator can
    decide whether to extend the parser or drop them.
  - Each accepted rule is enriched with ``applicable_os`` (a list
    inferred from ``logsource.product``) and ``category`` (from
    ``logsource.category``) so the console can filter without
    re-parsing every rule on every page load.

The importer does NOT write to the detector. Wiring the imported
rules into the live ``Detector`` is the operator's next step (either
copy the .yml into ``src/detection/rules/`` and restart, or call
``Detector.add_rule`` for each). Keeping the write step explicit
makes the import dry-run-able and avoids surprise rule activations.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import yaml

from src.detection.sigma import SigmaRule, parse_sigma_yaml

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


#: Rules whose logsource.product maps to one of these OS labels. Sigma
#: logsource.product is loosely typed so this list is intentionally
#: small; anything we cannot map is reported as "other" so the
#: operator can still see the rule and decide.
OS_BY_PRODUCT: dict[str, str] = {
    "linux": "linux",
    "macos": "macos",
    "windows": "windows",
}

#: Categories the MVP detector can actually match against. Categories
#: outside this set are still imported (so the operator can see them)
#: but tagged with ``detector_supported=False`` so the console can
#: grey them out.
SUPPORTED_CATEGORIES: set[str] = {
    "process_creation",
    "file_event",
    "network_connection",
    "image_load",
    "dns_query",
    "process_access",
    "registry_event",
}


@dataclass
class ImportedRule:
    """A successfully parsed rule, with the enrichment the console needs."""

    path: str
    rule: SigmaRule
    applicable_os: list[str]
    category: str
    detector_supported: bool
    level: str
    mitre_techniques: list[str]
    title: str


@dataclass
class SkippedRule:
    """A rule we could not use, with a reason string for the operator."""

    path: str
    reason: str


@dataclass
class ImportResult:
    accepted: list[ImportedRule] = field(default_factory=list)
    skipped: list[SkippedRule] = field(default_factory=list)
    source_dir: str = ""
    imported_at: str = ""

    @property
    def total_seen(self) -> int:
        return len(self.accepted) + len(self.skipped)

    def by_category(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for r in self.accepted:
            c[r.category or "uncategorized"] += 1
        return dict(c)

    def by_os(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for r in self.accepted:
            for os_name in r.applicable_os:
                c[os_name] += 1
        return dict(c)

    def by_level(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for r in self.accepted:
            c[r.level] += 1
        return dict(c)

    def to_manifest(self) -> dict[str, Any]:
        """JSON-friendly summary for the manifest file / API response."""
        return {
            "source_dir": self.source_dir,
            "imported_at": self.imported_at,
            "total_seen": self.total_seen,
            "accepted": len(self.accepted),
            "skipped": len(self.skipped),
            "by_category": self.by_category(),
            "by_os": self.by_os(),
            "by_level": self.by_level(),
            "skipped_reasons": [
                {"path": s.path, "reason": s.reason} for s in self.skipped
            ],
        }


def import_from_directory(path: str | Path) -> ImportResult:
    """Walk ``path`` recursively and import every ``*.yml`` / ``*.yaml``.

    Non-recursive lookup is also supported by passing a single file
    path -- useful for the operator who wants to test one rule at a
    time before committing a batch.
    """
    p = Path(path)
    result = ImportResult(source_dir=str(p), imported_at=datetime.now(UTC).isoformat())
    if not p.exists():
        result.skipped.append(SkippedRule(path=str(p), reason="path does not exist"))
        return result

    files: Iterable[Path]
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.rglob("*.yml"))
        files = list(files) + sorted(p.rglob("*.yaml"))

    for f in files:
        try:
            rule = parse_sigma_yaml(f)
        except Exception as exc:  # noqa: BLE001
            result.skipped.append(SkippedRule(path=str(f), reason=f"parse: {exc}"))
            continue
        enriched = _enrich(rule, f)
        result.accepted.append(enriched)

    logger.info(
        "sigma_import_done",
        extra={
            "source": str(p),
            "accepted": len(result.accepted),
            "skipped": len(result.skipped),
        },
    )
    return result


def _enrich(rule: SigmaRule, path: Path) -> ImportedRule:
    """Decorate a parsed rule with the metadata the console / detector need."""
    applicable_os: list[str] = []
    if rule.product:
        mapped = OS_BY_PRODUCT.get(rule.product.lower())
        if mapped:
            applicable_os.append(mapped)
    category = (rule.category or "").lower() or "uncategorized"
    detector_supported = category in SUPPORTED_CATEGORIES
    level = rule.level.value if hasattr(rule.level, "value") else str(rule.level)
    return ImportedRule(
        path=str(path),
        rule=rule,
        applicable_os=applicable_os,
        category=category,
        detector_supported=detector_supported,
        level=level,
        mitre_techniques=_mitre_from_tags(rule.tags),
        title=rule.title,
    )


def _mitre_from_tags(tags: list[str]) -> list[str]:
    """Normalise Sigma MITRE tags to canonical Txxxx / Txxxx.xxx form.

    Sigma tags look like ``attack.t1059`` or ``attack.t1059.004``. We
    only keep the ones that look like techniques (T + digits) and
    de-dupe while preserving order. Tactics (``attack.execution`` etc.)
    are dropped here; the console can show them in a separate column.
    """
    out: list[str] = []
    seen: set[str] = set()
    for t in tags or []:
        if not isinstance(t, str):
            continue
        if not t.lower().startswith("attack."):
            continue
        parts = t.split(".")
        # attack.t1059        -> ["attack", "t1059"]
        # attack.t1059.004    -> ["attack", "t1059", "004"]
        # attack.execution    -> ["attack", "execution"]   (tactic; drop)
        if len(parts) < 2 or not parts[1].lower().startswith("t"):
            continue
        rest = parts[1:]
        if len(rest) == 2 and rest[1].isdigit():
            canonical = rest[0].upper() + "." + rest[1]
        else:
            canonical = rest[0].upper()
        # Final sanity: "T" + digits (+ optional .digits)
        head = canonical.split(".")[0]
        if not (head.startswith("T") and head[1:].isdigit()):
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


def write_manifest(result: ImportResult, dest: Path) -> Path:
    """Write the import summary as JSON next to the imported rules.

    The manifest is what the API endpoint serves, so the console does
    not need to re-walk the imported directory on every page load.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_manifest()
    payload["rules"] = [
        {
            "path": r.path,
            "rule_id": r.rule.rule_id,
            "title": r.title,
            "level": r.level,
            "category": r.category,
            "applicable_os": r.applicable_os,
            "detector_supported": r.detector_supported,
            "mitre_techniques": r.mitre_techniques,
        }
        for r in result.accepted
    ]
    dest.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return dest


# ---------- convenience: read a manifest back -----------------------------

def read_manifest(path: str | Path) -> dict[str, Any] | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("manifest_read_failed", extra={"path": str(p), "error": str(exc)})
        return None
