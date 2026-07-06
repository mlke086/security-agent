import re
import threading
from pathlib import Path

import yaml
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.common.logging.logger import get_logger
from src.preprocessing.sanitization.mask import Rule, Span, apply_mask, resolve_spans

logger = get_logger(__name__)

_RULES_FILE = Path(__file__).parent.parent / "rules" / "default_rules.yaml"


class _RulesReloader(FileSystemEventHandler):
    def __init__(self, engine: "SanitizationEngine") -> None:
        self._engine = engine

    def on_modified(self, event: FileSystemEvent) -> None:
        if Path(str(event.src_path)).name == _RULES_FILE.name:
            logger.info("rules_file_changed", path=str(event.src_path))
            self._engine.reload_rules()


class SanitizationEngine:
    """Thread-safe PII masking engine with hot-reload support."""

    def __init__(self, rules_path: Path = _RULES_FILE) -> None:
        self._rules_path = rules_path
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self.reload_rules()
        self._start_watcher()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize(self, text: str) -> str:
        """Return the text with all PII/credential fields masked."""
        spans = self._find_spans(text)
        resolved = resolve_spans(spans)
        return self._apply_spans(text, resolved)

    def reload_rules(self) -> None:
        try:
            raw = yaml.safe_load(self._rules_path.read_text(encoding="utf-8"))
            rules = []
            for r in raw.get("rules", []):
                rules.append(
                    Rule(
                        name=r["name"],
                        pattern=re.compile(r["pattern"]),
                        type=r["type"],
                        priority=r.get("priority", 1),
                        mask=r.get("mask"),
                    )
                )
            with self._lock:
                self._rules = rules
            logger.info("rules_loaded", count=len(rules))
        except Exception as exc:
            logger.error("rules_load_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _find_spans(self, text: str) -> list[Span]:
        spans: list[Span] = []
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            for m in rule.pattern.finditer(text):
                spans.append(Span(start=m.start(), end=m.end(), rule=rule))
        return spans

    def _apply_spans(self, text: str, spans: list[Span]) -> str:
        if not spans:
            return text
        parts: list[str] = []
        cursor = 0
        for span in sorted(spans, key=lambda s: s.start):
            parts.append(text[cursor : span.start])
            parts.append(apply_mask(text, span))
            cursor = span.end
        parts.append(text[cursor:])
        return "".join(parts)

    def _start_watcher(self) -> None:
        observer = Observer()
        observer.schedule(_RulesReloader(self), str(self._rules_path.parent), recursive=False)
        observer.daemon = True
        observer.start()
