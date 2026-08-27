"""Apache combined / common access log parser."""

from __future__ import annotations

import re
from datetime import datetime

from analyzer.models import LogEntry
from analyzer.parsers.base_parser import BaseParser, normalize_line

APACHE_PATTERN = re.compile(
    r"""
    ^
    (?P<ip>\d{1,3}(?:\.\d{1,3}){3})
    \s+
    \S+
    \s+
    \S+
    \s+
    \[
    (?P<timestamp>[^\]]+)
    \]
    \s+
    "
    (?P<method>[A-Z]+)
    \s+
    (?P<path>.+?)
    \s+
    (?P<protocol>HTTP/\d(?:\.\d)?)
    "
    \s+
    (?P<status>\d{3})
    (?:\s+(?P<size>\d+|-))?
    """,
    re.VERBOSE,
)

_APACHE_HINT = re.compile(
    r'^\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\[[^\]]+\]\s+"'
)


class ApacheParser(BaseParser):
    """Parse Apache-style access log lines into normalized entries."""

    source = "apache"

    def can_parse(self, line: str) -> bool:
        text = normalize_line(line)
        if not text:
            return False
        return bool(_APACHE_HINT.match(text))

    def parse_line(self, line: str) -> LogEntry | None:
        raw = normalize_line(line)
        if not raw:
            return None

        match = APACHE_PATTERN.search(raw)
        if not match:
            return None

        try:
            timestamp = datetime.strptime(
                match.group("timestamp"),
                "%d/%b/%Y:%H:%M:%S %z",
            ).replace(tzinfo=None)
        except ValueError:
            try:
                timestamp = datetime.strptime(
                    match.group("timestamp"),
                    "%d/%b/%Y:%H:%M:%S +0000",
                )
            except ValueError:
                return None

        try:
            status_code = int(match.group("status"))
        except ValueError:
            return None

        path = match.group("path") or "/"
        method = match.group("method")
        outcome = "SUCCESS" if status_code < 400 else "FAILED"

        return LogEntry(
            timestamp=timestamp,
            username="-",
            ip_address=match.group("ip"),
            status=outcome,
            source=self.source,
            event_type="HTTP_REQUEST",
            request=path,
            method=method,
            path=path,
            status_code=status_code,
            raw_message=raw,
        )


def parse_apache_line(line: str) -> LogEntry | None:
    """Parse a single Apache access line (module-level convenience API)."""
    return ApacheParser().parse_line(line)
