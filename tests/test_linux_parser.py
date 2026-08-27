"""Tests for Linux SSH authentication log parsing."""

from datetime import datetime

from analyzer.config import AnalyzerConfig
from analyzer.parsers.linux_parser import LinuxParser, parse_linux_line


def test_parse_linux_accepted_password():
    line = (
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for abhishek from 192.168.1.18 port 46945 ssh2"
    )
    entry = parse_linux_line(line, year=2026)

    assert entry is not None
    assert entry.source == "linux"
    assert entry.username == "abhishek"
    assert entry.ip_address == "192.168.1.18"
    assert entry.status == "SUCCESS"
    assert entry.event_type == "LOGIN_SUCCESS"
    assert entry.timestamp == datetime(2026, 6, 26, 9, 1, 20)
    assert entry.raw_message == line


def test_parse_linux_failed_password():
    line = (
        "Jun 26 09:02:01 server sshd[1020]: "
        "Failed password for admin from 203.0.113.10 port 53769 ssh2"
    )
    entry = parse_linux_line(line, year=2026)

    assert entry is not None
    assert entry.status == "FAILED"
    assert entry.event_type == "LOGIN_FAILED"
    assert entry.username == "admin"
    assert entry.ip_address == "203.0.113.10"


def test_parse_linux_failed_invalid_user():
    line = (
        "Jun 26 10:00:00 server sshd[2000]: "
        "Failed password for invalid user bob from 10.0.0.5 port 22 ssh2"
    )
    entry = parse_linux_line(line, year=2026)

    assert entry is not None
    assert entry.username == "bob"
    assert entry.status == "FAILED"


def test_linux_year_from_explicit_argument():
    line = (
        "Jan 15 08:00:00 server sshd[1]: "
        "Accepted password for root from 1.2.3.4 port 22 ssh2"
    )
    entry = LinuxParser(year=2030).parse_line(line)

    assert entry is not None
    assert entry.timestamp.year == 2030


def test_linux_year_from_config_object():
    line = (
        "Mar 01 12:00:00 server sshd[2]: "
        "Failed password for alice from 5.6.7.8 port 22 ssh2"
    )
    config = AnalyzerConfig(default_log_year=2024)
    entry = LinuxParser(config=config).parse_line(line)

    assert entry is not None
    assert entry.timestamp.year == 2024


def test_linux_can_parse_and_malformed():
    parser = LinuxParser(year=2026)
    valid = (
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for alice from 192.168.1.18 port 46945 ssh2"
    )
    malformed = "Jun 26 09:01:20 server sshd[1014]: something unexpected happened"

    assert parser.can_parse(valid) is True
    assert parser.parse_line(valid) is not None
    assert parser.can_parse(malformed) is True
    assert parser.parse_line(malformed) is None
    assert parser.can_parse("not linux") is False


def test_linux_malformed_returns_none():
    assert parse_linux_line("not a linux auth line") is None
    assert parse_linux_line("") is None


def test_linux_whitespace_only_returns_none():
    assert parse_linux_line("   \t  ") is None


def test_linux_truncated_line_returns_none():
    assert parse_linux_line("Jun 26 09:01:20 server sshd[1014]: Failed password") is None


def test_linux_malformed_timestamp_returns_none():
    line = (
        "Xxx 99 99:99:99 server sshd[1014]: "
        "Failed password for admin from 10.0.0.1 port 22 ssh2"
    )
    assert parse_linux_line(line, year=2026) is None


def test_linux_very_long_line_does_not_crash():
    padding = "x" * 8000
    line = (
        f"Jun 26 09:01:20 server sshd[1014]: "
        f"Failed password for admin from 10.0.0.1 port 22 ssh2 {padding}"
    )
    # May parse or return None depending on trailing noise; must not raise.
    result = parse_linux_line(line, year=2026)
    assert result is None or result.username == "admin"


def test_linux_unicode_username():
    line = (
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for användare from 192.168.1.18 port 46945 ssh2"
    )
    entry = parse_linux_line(line, year=2026)
    assert entry is not None
    assert entry.username == "användare"


def test_linux_different_users_and_ips():
    for user, ip in (("root", "1.2.3.4"), ("guest", "198.51.100.1"), ("svc", "10.0.0.99")):
        line = (
            f"Jun 26 09:01:20 server sshd[1014]: "
            f"Accepted password for {user} from {ip} port 46945 ssh2"
        )
        entry = parse_linux_line(line, year=2026)
        assert entry is not None
        assert entry.username == user
        assert entry.ip_address == ip
