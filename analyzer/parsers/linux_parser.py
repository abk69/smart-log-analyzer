"""Linux SSH / syslog authentication log parser."""

from __future__ import annotations

import re
from datetime import datetime

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG
from analyzer.models import LogEntry
from analyzer.parsers.base_parser import BaseParser, normalize_line

# Accepted / Failed password (optional "invalid user" prefix before username).
AUTH_PASSWORD_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)
    \s+
    \S+
    \s+
    sshd\[\d+\]:
    \s+
    (?P<status>Accepted|Failed)
    \s+password\s+for\s+
    (?:invalid\s+user\s+)?
    (?P<username>\S+)
    \s+from\s+
    (?P<ip>\d{1,3}(?:\.\d{1,3}){3})
    \s+port\s+
    (?P<port>\d+)
    """,
    re.VERBOSE,
)

# Standalone "Invalid user" authentication rejection.
INVALID_USER_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)
    \s+
    \S+
    \s+
    sshd\[\d+\]:
    \s+
    Invalid\s+user\s+
    (?P<username>\S+)
    \s+from\s+
    (?P<ip>\d{1,3}(?:\.\d{1,3}){3})
    (?:\s+port\s+(?P<port>\d+))?
    """,
    re.VERBOSE,
)

_SSH_HINT = re.compile(r"sshd\[\d+\]:")


def _build_timestamp(timestamp_text: str, year: int) -> datetime:
    """Build a datetime from a syslog stamp that omits the year."""
    return datetime.strptime(
        f"{year} {timestamp_text}",
        "%Y %b %d %H:%M:%S",
    )


class LinuxParser(BaseParser):
    """Parse common Linux SSH authentication events.

    The syslog timestamp has no year. Supply ``year`` explicitly, or pass
    an ``AnalyzerConfig`` / rely on ``DEFAULT_CONFIG.default_log_year``.
    """

    source = "linux"

    def __init__(
        self,
        year: int | None = None,
        *,
        config: AnalyzerConfig | None = None,
    ) -> None:
        if year is not None:
            self.year = year
        elif config is not None:
            self.year = config.default_log_year
        else:
            self.year = DEFAULT_CONFIG.default_log_year

    def can_parse(self, line: str) -> bool:
        text = normalize_line(line)
        if not text:
            return False
        return bool(_SSH_HINT.search(text))

    def parse_line(self, line: str) -> LogEntry | None:
        raw = normalize_line(line)
        if not raw:
            return None

        match = AUTH_PASSWORD_PATTERN.search(raw)
        if match:
            try:
                timestamp = _build_timestamp(match.group("timestamp"), self.year)
            except ValueError:
                return None

            status = "SUCCESS" if match.group("status") == "Accepted" else "FAILED"
            event_type = "LOGIN_SUCCESS" if status == "SUCCESS" else "LOGIN_FAILED"
            return LogEntry(
                timestamp=timestamp,
                username=match.group("username"),
                ip_address=match.group("ip"),
                status=status,
                source=self.source,
                event_type=event_type,
                raw_message=raw,
            )

        match = INVALID_USER_PATTERN.search(raw)
        if match:
            try:
                timestamp = _build_timestamp(match.group("timestamp"), self.year)
            except ValueError:
                return None

            return LogEntry(
                timestamp=timestamp,
                username=match.group("username"),
                ip_address=match.group("ip"),
                status="FAILED",
                source=self.source,
                event_type="LOGIN_FAILED",
                raw_message=raw,
            )

        return None


def parse_linux_line(line: str, *, year: int | None = None) -> LogEntry | None:
    """Parse a single Linux auth line (module-level convenience API)."""
    return LinuxParser(year=year).parse_line(line)
