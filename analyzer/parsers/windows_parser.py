"""Windows authentication event parser (synthetic EVENT_ID format)."""

from __future__ import annotations

import re
from datetime import datetime

from analyzer.models import LogEntry
from analyzer.parsers.base_parser import BaseParser, normalize_line

WINDOWS_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)
    \s+
    EVENT_ID=(?P<event>\d+)
    \s+
    USER=(?P<user>\S+)
    \s+
    IP=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})
    """,
    re.VERBOSE,
)

_WINDOWS_HINT = re.compile(r"EVENT_ID=\d+")

_EVENT_MAP = {
    "4624": ("SUCCESS", "LOGIN_SUCCESS"),
    "4625": ("FAILED", "LOGIN_FAILED"),
}


class WindowsParser(BaseParser):
    """Parse synthetic Windows security events 4624 / 4625."""

    source = "windows"

    def can_parse(self, line: str) -> bool:
        text = normalize_line(line)
        if not text:
            return False
        return bool(_WINDOWS_HINT.search(text))

    def parse_line(self, line: str) -> LogEntry | None:
        raw = normalize_line(line)
        if not raw:
            return None

        match = WINDOWS_PATTERN.search(raw)
        if not match:
            return None

        mapped = _EVENT_MAP.get(match.group("event"))
        if mapped is None:
            return None

        status, event_type = mapped

        try:
            timestamp = datetime.fromisoformat(match.group("timestamp"))
        except ValueError:
            return None

        return LogEntry(
            timestamp=timestamp,
            username=match.group("user"),
            ip_address=match.group("ip"),
            status=status,
            source=self.source,
            event_type=event_type,
            raw_message=raw,
        )


def parse_windows_line(line: str) -> LogEntry | None:
    """Parse a single Windows event line (module-level convenience API)."""
    return WindowsParser().parse_line(line)
