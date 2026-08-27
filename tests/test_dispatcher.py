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


def test_ordered_mixed_and_malformed_counts():
    """Linux / Windows / Apache / malformed / unsupported / Linux / Apache."""
    lines = [
        "Jun 26 09:01:20 server sshd[1014]: Accepted password for alice from 192.168.1.18 port 46945 ssh2",
        '2026-06-26T09:00:25 EVENT_ID=4624 USER=bob IP=10.0.0.16 MESSAGE="ok"',
        '172.16.1.73 - - [26/Jun/2026:09:01:14 +0000] "GET /products HTTP/1.1" 200 342',
        "Jun 26 09:01:20 server sshd[1014]: something broken",
        "this is not a log line",
        "Jun 26 09:02:01 server sshd[1020]: Failed password for carol from 10.0.0.5 port 22 ssh2",
        '172.16.1.80 - - [26/Jun/2026:09:05:00 +0000] "GET /about HTTP/1.1" 200 100',
    ]
    entries, stats = parse_logs_with_stats(
        lines,
        config=AnalyzerConfig(default_log_year=2026),
    )

    assert len(entries) == 5
    assert stats.parsed_lines == 5
    assert stats.malformed_lines == 1
    assert stats.unsupported_lines == 1
    assert stats.linux_lines == 2
    assert stats.windows_lines == 1
    assert stats.apache_lines == 2
    assert {e.source for e in entries} == {"linux", "windows", "apache"}
    assert all(hasattr(e, "username") for e in entries)


def test_completely_unknown_file():
    lines = [
        "??? completely unknown format ???",
        "still not a log line",
        "random noise without structure",
    ]
    entries, stats = parse_logs_with_stats(lines)
    assert entries == []
    assert stats.parsed_lines == 0
    assert stats.unsupported_lines == 3
    assert stats.malformed_lines == 0


def test_whitespace_lines_do_not_crash_pipeline():
    lines = [
        "",
        "   ",
        "\t",
        "Jun 26 09:01:20 server sshd[1014]: Accepted password for alice from 192.168.1.18 port 46945 ssh2",
    ]
    entries, stats = parse_logs_with_stats(
        lines,
        config=AnalyzerConfig(default_log_year=2026),
    )
    assert len(entries) == 1
    assert stats.total_lines == 4
