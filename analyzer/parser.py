"""Log file I/O helpers."""

from __future__ import annotations

from pathlib import Path

from analyzer.exceptions import LogFileError


def read_log_file(path: str | Path) -> list[str]:
    """Read a log file and return non-empty stripped lines.

    Raises:
        LogFileError: If the path does not exist, is not a file, or cannot
            be read as text.
    """
    file_path = Path(path)

    if not file_path.exists():
        raise LogFileError(f"Log file not found: {file_path}")

    if not file_path.is_file():
        raise LogFileError(f"Path is not a file: {file_path}")

    try:
        with file_path.open(encoding="utf-8", errors="replace") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        raise LogFileError(f"Unable to read log file: {file_path}") from exc
