import re
from datetime import datetime

from analyzer.models import LogEntry


APACHE_PATTERN = re.compile(
    r"""
    ^
    (?P<ip>\d+\.\d+\.\d+\.\d+)
    \s+-\s+-\s+
    \[
        (?P<timestamp>.+?)
    \]
    \s+
    "
    (?P<method>GET|POST)
    \s+
    (?P<path>.+?)
    \s+
    HTTP/1\.1
    "
    \s+
    (?P<status>\d+)
    """,
    re.VERBOSE,
)


def parse_apache_line(line: str):

    match = APACHE_PATTERN.search(line)

    if not match:
        return None

    timestamp = datetime.strptime(
        match.group("timestamp"),
        "%d/%b/%Y:%H:%M:%S +0000",
    )

    status = (
        "SUCCESS"
        if int(match.group("status")) < 400
        else "FAILED"
    )

    return LogEntry(
        timestamp=timestamp,
        username="-",
        ip_address=match.group("ip"),
        status=status,
        source="apache",
        event_type="HTTP_REQUEST",
    )