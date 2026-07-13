import re
from datetime import datetime

from analyzer.models import LogEntry


LOG_PATTERN = re.compile(
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
    (?P<username>\w+)
    \s+from\s+
    (?P<ip>\d+\.\d+\.\d+\.\d+)
    \s+port\s+
    (?P<port>\d+)
    """,
    re.VERBOSE,
)


def parse_linux_line(line: str):

    match = LOG_PATTERN.search(line)

    if not match:
        return None

    timestamp = datetime.strptime(
        f"2026 {match.group('timestamp')}",
        "%Y %b %d %H:%M:%S",
    )

    status = (
        "SUCCESS"
        if match.group("status") == "Accepted"
        else "FAILED"
    )

    event_type = (
        "LOGIN_SUCCESS"
        if status == "SUCCESS"
        else "LOGIN_FAILED"
    )

    return LogEntry(
        timestamp=timestamp,
        username=match.group("username"),
        ip_address=match.group("ip"),
        status=status,
        source="linux",
        event_type=event_type,
    )