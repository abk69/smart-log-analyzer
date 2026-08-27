"""Multi-format parser dispatcher with parse statistics."""

from __future__ import annotations

from dataclasses import dataclass

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG
from analyzer.models import LogEntry
from analyzer.parsers.apache_parser import ApacheParser
from analyzer.parsers.base_parser import BaseParser, normalize_line
from analyzer.parsers.linux_parser import LinuxParser
from analyzer.parsers.windows_parser import WindowsParser
from analyzer.utils import get_logger

logger = get_logger("parsers.dispatcher")


@dataclass
class ParseStats:
    """Counters describing a multi-format parse run."""

    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    unsupported_lines: int = 0
    linux_lines: int = 0
    windows_lines: int = 0
    apache_lines: int = 0

    def as_dict(self) -> dict:
        """Return a JSON-serializable summary."""
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "malformed_lines": self.malformed_lines,
            "unsupported_lines": self.unsupported_lines,
            "linux_lines": self.linux_lines,
            "windows_lines": self.windows_lines,
            "apache_lines": self.apache_lines,
        }


def _default_parsers(config: AnalyzerConfig | None = None) -> list[BaseParser]:
    cfg = config if config is not None else DEFAULT_CONFIG
    return [
        LinuxParser(year=cfg.default_log_year),
        WindowsParser(),
        ApacheParser(),
    ]


def _parse_lines(
    log_lines: list[str],
    *,
    parsers: list[BaseParser] | None = None,
    config: AnalyzerConfig | None = None,
) -> tuple[list[LogEntry], ParseStats]:
    """Core dispatch loop shared by public APIs."""
    active_parsers = parsers if parsers is not None else _default_parsers(config)
    entries: list[LogEntry] = []
    stats = ParseStats(total_lines=len(log_lines))

    for line in log_lines:
        text = normalize_line(line if line is not None else "")
        if not text:
            stats.unsupported_lines += 1
            continue

        claimed = False

        for parser in active_parsers:
            if not parser.can_parse(text):
                continue

            claimed = True
            entry = parser.parse_line(text)
            if entry is None:
                stats.malformed_lines += 1
                logger.debug(
                    "Malformed %s line skipped: %s",
                    parser.source,
                    text[:120],
                )
                break

            entries.append(entry)
            stats.parsed_lines += 1
            if entry.source == "linux":
                stats.linux_lines += 1
            elif entry.source == "windows":
                stats.windows_lines += 1
            elif entry.source == "apache":
                stats.apache_lines += 1
            break

        if not claimed:
            stats.unsupported_lines += 1
            logger.debug("Unsupported log line skipped: %s", text[:120])

    return entries, stats


def parse_logs(
    log_lines: list[str],
    *,
    parsers: list[BaseParser] | None = None,
    config: AnalyzerConfig | None = None,
) -> list[LogEntry]:
    """Parse mixed-format log lines into normalized ``LogEntry`` objects.

    Malformed and unsupported lines are skipped. This is the stable simple
    API expected by existing callers.
    """
    entries, _stats = _parse_lines(log_lines, parsers=parsers, config=config)
    return entries


def parse_logs_with_stats(
    log_lines: list[str],
    *,
    parsers: list[BaseParser] | None = None,
    config: AnalyzerConfig | None = None,
) -> tuple[list[LogEntry], ParseStats]:
    """Parse log lines and return ``(entries, parse_stats)``."""
    return _parse_lines(log_lines, parsers=parsers, config=config)
