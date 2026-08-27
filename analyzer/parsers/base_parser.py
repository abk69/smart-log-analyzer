"""Base parser abstraction for format-specific log parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from analyzer.models import LogEntry


def normalize_line(line: str | None) -> str:
    """Strip whitespace and a leading UTF-8 BOM if present."""
    if not line:
        return ""
    return str(line).strip().lstrip("\ufeff")


class BaseParser(ABC):
    """Contract every format parser must implement.

    ``can_parse`` decides whether a line belongs to this format.
    ``parse_line`` extracts a ``LogEntry`` or returns ``None`` when the
    line looks related but is malformed.
    """

    source: str = "unknown"

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser recognizes the line's format."""

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry | None:
        """Parse a recognized line into a ``LogEntry``, or ``None`` if malformed."""
