"""Tests for multi-format parser dispatcher."""

from analyzer.config import AnalyzerConfig
from analyzer.parsers.linux_parser import LinuxParser
from analyzer.parsers.parser_dispatcher import parse_logs, parse_logs_with_stats


def test_parse_logs_returns_list_api():
    lines = [
        "Jun 26 09:01:20 server sshd[1014]: Accepted password for alice from 192.168.1.18 port 46945 ssh2",
        '2026-06-26T09:00:25 EVENT_ID=4624 USER=bob IP=10.0.0.16 MESSAGE="ok"',
        '172.16.1.73 - - [26/Jun/2026:09:01:14 +0000] "GET /products HTTP/1.1" 200 342',
    ]
    entries = parse_logs(lines, config=AnalyzerConfig(default_log_year=2026))

    assert isinstance(entries, list)
    assert len(entries) == 3
    assert {e.source for e in entries} == {"linux", "windows", "apache"}


def test_parse_logs_with_stats_mixed_dataset():
    lines = [
        "Jun 26 09:01:20 server sshd[1014]: Accepted password for alice from 192.168.1.18 port 46945 ssh2",
        '2026-06-26T09:00:25 EVENT_ID=4624 USER=bob IP=10.0.0.16 MESSAGE="ok"',
        '172.16.1.73 - - [26/Jun/2026:09:01:14 +0000] "GET /products HTTP/1.1" 200 342',
        "Jun 26 09:01:20 server sshd[1014]: something broken",
        "this is not a log line",
    ]
    entries, stats = parse_logs_with_stats(
        lines,
        config=AnalyzerConfig(default_log_year=2026),
    )

    assert len(entries) == 3
    assert stats.total_lines == 5
    assert stats.parsed_lines == 3
    assert stats.malformed_lines == 1
    assert stats.unsupported_lines == 1
    assert stats.linux_lines == 1
    assert stats.windows_lines == 1
    assert stats.apache_lines == 1


def test_dispatcher_handles_empty_input():
    entries, stats = parse_logs_with_stats([])

    assert entries == []
    assert stats.total_lines == 0
    assert stats.parsed_lines == 0


def test_dispatcher_uses_injected_linux_year():
    lines = [
        "Jan 02 03:04:05 server sshd[9]: Accepted password for root from 1.2.3.4 port 22 ssh2",
    ]
    entries = parse_logs(lines, parsers=[LinuxParser(year=2099)])

    assert len(entries) == 1
    assert entries[0].timestamp.year == 2099


def test_parse_stats_as_dict():
    _entries, stats = parse_logs_with_stats(["not parseable"])
    payload = stats.as_dict()

    assert payload["total_lines"] == 1
    assert payload["unsupported_lines"] == 1
    assert payload["parsed_lines"] == 0
    assert payload["malformed_lines"] == 0
    assert "linux_lines" in payload
