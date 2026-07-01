import re
from pathlib import Path
from datetime import datetime

from analyzer.models import LogEntry


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?"
    r"(?P<status>Accepted|Failed) password for "
    r"(?P<username>\w+) from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def read_log_file(file_path: str) -> list[str]:

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"{file_path} not found")

    with path.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def parse_logs(log_lines: list[str]) -> list[LogEntry]:

    parsed_logs = []

    for line in log_lines:

        match = LOG_PATTERN.search(line)

        if not match:
            continue

        status = (
            "SUCCESS"
            if match.group("status") == "Accepted"
            else "FAILED"
        )

        parsed_logs.append(
            LogEntry(
                timestamp=datetime.strptime(
                    f"2026 {match.group('timestamp')}",
                    "%Y %b %d %H:%M:%S"
                ),
                username=match.group("username"),
                ip_address=match.group("ip"),
                status=status,
            )
        )

    return parsed_logs