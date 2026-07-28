"""Detection orchestrator (Phase 3 of monitoring plan).

Loads a set of Sigma rules (built-in + user-uploaded) and runs them
against an event. The MVP scope is one-shot detection (run_rules)
called by the background detector loop or via the on-demand API.

The background loop is a separate concern (background_tasks.py). This
module is just the rule-fan-out + alert-build glue.
"""
from pathlib import Path
from typing import Iterable

from src.agents.alert_store import get_alert_store
from src.common.logging.logger import get_logger
from src.detection.builder import build_alert
from src.detection.sigma import SigmaRule, parse_sigma_yaml

logger = get_logger(__name__)


class Detector:
    """In-memory registry of enabled Sigma rules.

    Rules are loaded from:
      - built-in .yml files under src/detection/rules/
      - user-uploaded .yml via the API (Phase 3+ ships a /rules/upload
        endpoint that calls detector.add_rule)
    """

    def __init__(self):
        self._rules: dict[str, SigmaRule] = {}

    def add_rule(self, rule: SigmaRule) -> None:
        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def list_rules(self) -> list:
        return list(self._rules.values())

    def get_rule(self, rule_id: str):
        return self._rules.get(rule_id)

    def load_builtin_rules(self, dir_path=None) -> int:
        """Load all .yml files from src/detection/rules/. Returns count loaded."""
        d = Path(dir_path) if dir_path else (Path(__file__).parent / "rules")
        if not d.exists():
            return 0
        loaded = 0
        # Recurse so ``src/detection/rules/imported/`` (CLI output)
        # is also picked up. We dedup by rule_id via add_rule, so a
        # rule that exists in both the root and a subdir just wins
        # the first-load race.
        for p in sorted(list(d.glob("*.yml")) + list(d.rglob("*.yml"))):
            try:
                rule = parse_sigma_yaml(p)
                self.add_rule(rule)
                loaded += 1
            except Exception as exc:
                logger.warning("rule_load_failed", path=str(p), error=str(exc))
        return loaded

    async def run_rules(self, event: dict, event_id: str) -> list:
        """Run all rules against one event. Return a list of Alert objects that hit.

        Persists hits to AlertStore (PG + ES) for the AlertInboxPage to
        surface. Failures to persist are logged but do not raise, so a
        bad rule never takes down the detector loop.
        """
        alerts = []
        for rule in self._rules.values():
            try:
                alert = build_alert(rule, event, event_id)
            except Exception as exc:
                logger.warning(
                    "rule_evaluation_failed",
                    rule_id=rule.rule_id,
                    error=str(exc),
                )
                continue
            if alert is None:
                continue
            try:
                await get_alert_store().save_alert(alert)
                alerts.append(alert)
                logger.info(
                    "alert_detected",
                    rule_id=rule.rule_id,
                    alert_id=alert.alert_id,
                    severity=str(alert.severity),
                )
            except Exception as exc:
                logger.error(
                    "alert_persist_failed",
                    rule_id=rule.rule_id,
                    alert_id=alert.alert_id,
                    error=str(exc),
                )
        return alerts


# Module-level singleton. The lifespan or background_tasks init populates
# the builtin rules once at startup; the API mutates it for user uploads.
_detector: Detector | None = None


def get_detector() -> Detector:
    global _detector
    if _detector is None:
        _detector = Detector()
    return _detector


def init_builtin_rules() -> int:
    """Load the bundled Sigma rules into the singleton detector.

    Called once during FastAPI lifespan startup. Safe to call multiple
    times (each call resets the rule registry to the bundled set, so
    tests get a clean state). Returns the number of rules loaded.
    """
    detector = get_detector()
    # Reset to a clean registry so a previous run's user-uploaded rules
    # do not leak across reloads / tests.
    detector._rules.clear()
    return detector.load_builtin_rules()
