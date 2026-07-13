import re
from datetime import datetime

from analyzer.models import LogEntry


WINDOWS_PATTERN = re.compile(
    r"""
    ^
    (?P<timestamp>[\d\-T:]+)
    \s+
    EVENT_ID=(?P<event>\d+)
    \s+
    USER=(?P<user>\w+)
    \s+
    IP=(?P<ip>\d+\.\d+\.\d+\.\d+)
    """,
    re.VERBOSE,
)


def parse_windows_line(line: str):

    match = WINDOWS_PATTERN.search(line)

    if not match:
        return None

    event_id = match.group("event")

    status = (
        "SUCCESS"
        if event_id == "4624"
        else "FAILED"
    )

    event_type = (
        "LOGIN_SUCCESS"
        if status == "SUCCESS"
        else "LOGIN_FAILED"
    )

    return LogEntry(
        timestamp=datetime.fromisoformat(
            match.group("timestamp")
        ),
        username=match.group("user"),
        ip_address=match.group("ip"),
        status=status,
        source="windows",
        event_type=event_type,
    )