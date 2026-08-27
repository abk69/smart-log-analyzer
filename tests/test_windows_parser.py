"""Tests for Windows authentication event parsing."""

from datetime import datetime

from analyzer.parsers.windows_parser import WindowsParser, parse_windows_line


def test_parse_windows_success_4624():
    line = (
        '2026-06-26T09:00:25 EVENT_ID=4624 USER=abhishek IP=10.0.0.16 '
        'MESSAGE="An account was successfully logged on."'
    )
    entry = parse_windows_line(line)

    assert entry is not None
    assert entry.source == "windows"
    assert entry.username == "abhishek"
    assert entry.ip_address == "10.0.0.16"
    assert entry.status == "SUCCESS"
    assert entry.event_type == "LOGIN_SUCCESS"
    assert entry.timestamp == datetime(2026, 6, 26, 9, 0, 25)
    assert "EVENT_ID=4624" in entry.raw_message


def test_parse_windows_failed_4625():
    line = (
        '2026-06-26T09:00:52 EVENT_ID=4625 USER=abhishek IP=10.0.0.11 '
        'MESSAGE="An account failed to log on."'
    )
    entry = parse_windows_line(line)

    assert entry is not None
    assert entry.status == "FAILED"
    assert entry.event_type == "LOGIN_FAILED"


def test_windows_unknown_event_id_is_malformed_claim():
    parser = WindowsParser()
    line = "2026-06-26T09:00:25 EVENT_ID=9999 USER=admin IP=10.0.0.1"

    assert parser.can_parse(line) is True
    assert parser.parse_line(line) is None


def test_windows_malformed_returns_none():
    assert parse_windows_line("EVENT_ID=4624 USER=admin") is None
    assert parse_windows_line("") is None
    assert WindowsParser().can_parse("random text") is False


def test_windows_whitespace_only():
    assert parse_windows_line("   \n") is None


def test_windows_malformed_timestamp():
    line = 'not-a-date EVENT_ID=4624 USER=admin IP=10.0.0.1 MESSAGE="x"'
    assert parse_windows_line(line) is None


def test_windows_missing_username():
    line = '2026-06-26T09:00:25 EVENT_ID=4624 IP=10.0.0.1 MESSAGE="ok"'
    assert parse_windows_line(line) is None


def test_windows_invalid_event_id():
    line = '2026-06-26T09:00:25 EVENT_ID=1234 USER=admin IP=10.0.0.1 MESSAGE="x"'
    assert parse_windows_line(line) is None


def test_windows_unicode_username():
    line = (
        '2026-06-26T09:00:25 EVENT_ID=4624 USER=ユーザー IP=10.0.0.16 '
        'MESSAGE="An account was successfully logged on."'
    )
    entry = parse_windows_line(line)
    assert entry is not None
    assert entry.username == "ユーザー"


def test_windows_very_long_message_does_not_crash():
    msg = "x" * 5000
    line = (
        f'2026-06-26T09:00:25 EVENT_ID=4625 USER=admin IP=10.0.0.11 '
        f'MESSAGE="{msg}"'
    )
    entry = parse_windows_line(line)
    assert entry is not None
    assert entry.status == "FAILED"
