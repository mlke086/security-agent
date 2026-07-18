import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

from src.common.config.settings import get_settings

_PII_PATTERN = re.compile(
    r"(?:password|passwd|pwd|secret|token|key)\s*[=:]\s*\S+",
    re.IGNORECASE,
)


def _mask_pii(event: str) -> str:
    return _PII_PATTERN.sub(lambda m: m.group(0).split("=")[0] + "=***", event)


def _pii_censor(logger: Any, method: str, event_dict: MutableMapping[str, Any]) -> Mapping[str, Any]:  # noqa: ARG001
    if isinstance(event_dict.get("event"), str):
        event_dict["event"] = _mask_pii(event_dict["event"])
    return event_dict


def configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _pii_censor,
            structlog.dev.ConsoleRenderer() if settings.log_level == "DEBUG"
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    )
    logging.basicConfig(level=level, stream=sys.stdout, format="%(message)s", force=True)


def get_logger(name: str) -> Any:
    # structlog's runtime API accepts arbitrary kwargs (event_dict keys); typing
    # it as BoundLogger makes mypy treat .warning/.error as stdlib Logger methods
    # and reject those kwargs. Return Any to reflect the dynamic API.
    return structlog.get_logger(name)
