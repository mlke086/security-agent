"""Generic syslog / RFC5424 line + structured fields."""

import hashlib
import re

from src.agents.models import AlertIOC, AlertSeverity, AlertSource
from src.preprocessing.edr_adapter.base import EDRAdapter

_SYSLOG_PRI_RE = re.compile(r"\<(\d+)\>")


class SyslogAdapter(EDRAdapter):
    source = AlertSource.SYSLOG

    def _id(self):
        canonical = repr(sorted(self.raw.items())).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()[:32]
        return self.source.value + chr(58) + "sha256" + chr(58) + digest

    def _title(self):
        return str(self.raw.get("msg") or self.raw.get("message") or "Syslog alert")

    def _severity(self):
        sev = self.raw.get("severity")
        try:
            sev_int = int(sev)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            pri = self.raw.get("priority") or self.raw.get("PRI") or 134
            m = _SYSLOG_PRI_RE.search(str(pri))
            sev_int = int(m.group(1)) % 8 if m else 5
        sev = sev_int
        if sev <= 1:
            return AlertSeverity.CRITICAL
        if sev <= 3:
            return AlertSeverity.HIGH
        if sev <= 4:
            return AlertSeverity.MEDIUM
        if sev <= 5:
            return AlertSeverity.LOW
        return AlertSeverity.INFO

    def _hostname(self):
        return str(self.raw.get("hostname") or str(self.raw.get("host") or ""))

    def _rule_name(self):
        return str(self.raw.get("program") or str(self.raw.get("app_name") or ""))

    def _iocs(self):
        msg = str(self.raw.get("msg") or self.raw.get("message") or "")
        # V13 P1-2: raw string -- a plain "\b" in a regular string literal is
        # the backspace character (U+0008), which made this regex demand a
        # backspace around every IP and silently never match.
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", msg)
        return AlertIOC(ips=list(set(ips)))
