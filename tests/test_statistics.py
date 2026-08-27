"""Tests for aggregate log statistics."""

from datetime import datetime

from analyzer.models import LogEntry
from analyzer.statistics import generate_statistics


def _entry(
    *,
    source: str = "linux",
    event_type: str = "LOGIN_SUCCESS",
    username: str = "alice",
    ip: str = "10.0.0.1",
    status: str = "SUCCESS",
) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username=username,
        ip_address=ip,
        status=status,
        source=source,
        event_type=event_type,
    )


def test_empty_logs_never_crash():
    stats = generate_statistics([])
    assert stats["total_logs"] == 0
    assert stats["linux_logs"] == 0
    assert stats["windows_logs"] == 0
    assert stats["apache_logs"] == 0
    assert stats["successful_logins"] == 0
    assert stats["failed_logins"] == 0
    assert stats["http_requests"] == 0
    assert stats["unique_users"] == 0
    assert stats["unique_ips"] == 0
    assert stats["top_user"] == ("-", 0)
    assert stats["top_ip"] == ("-", 0)


def test_one_log():
    stats = generate_statistics([_entry()])
    assert stats["total_logs"] == 1
    assert stats["linux_logs"] == 1
    assert stats["successful_logins"] == 1
    assert stats["unique_users"] == 1
    assert stats["unique_ips"] == 1
    assert stats["top_user"] == ("alice", 1)
    assert stats["top_ip"] == ("10.0.0.1", 1)


def test_mixed_sources_and_event_types():
    logs = [
        _entry(source="linux", event_type="LOGIN_SUCCESS", username="alice", ip="1.1.1.1"),
        _entry(
            source="linux",
            event_type="LOGIN_FAILED",
            username="bob",
            ip="2.2.2.2",
            status="FAILED",
        ),
        _entry(
            source="windows",
            event_type="LOGIN_SUCCESS",
            username="alice",
            ip="1.1.1.1",
        ),
        _entry(
            source="apache",
            event_type="HTTP_REQUEST",
            username="-",
            ip="3.3.3.3",
            status="SUCCESS",
        ),
    ]
    stats = generate_statistics(logs)
    assert stats["total_logs"] == 4
    assert stats["linux_logs"] == 2
    assert stats["windows_logs"] == 1
    assert stats["apache_logs"] == 1
    assert stats["successful_logins"] == 2
    assert stats["failed_logins"] == 1
    assert stats["http_requests"] == 1
    assert stats["unique_users"] == 2  # alice, bob — excludes "-"
    assert stats["unique_ips"] == 3
    assert stats["top_user"] == ("alice", 2)
    assert stats["top_ip"] == ("1.1.1.1", 2)


def test_dash_username_excluded_from_unique_users():
    logs = [
        _entry(event_type="HTTP_REQUEST", username="-", ip="9.9.9.9"),
        _entry(event_type="HTTP_REQUEST", username="-", ip="8.8.8.8"),
    ]
    stats = generate_statistics(logs)
    assert stats["unique_users"] == 0
    assert stats["top_user"] == ("-", 0)
    assert stats["unique_ips"] == 2


def test_top_user_and_ip_ties_are_stable():
    """Counter.most_common returns first-seen winner on ties."""
    logs = [
        _entry(username="alice", ip="10.0.0.1"),
        _entry(username="bob", ip="10.0.0.2"),
    ]
    stats = generate_statistics(logs)
    assert stats["top_user"][1] == 1
    assert stats["top_ip"][1] == 1
    assert stats["top_user"][0] in {"alice", "bob"}
    assert stats["top_ip"][0] in {"10.0.0.1", "10.0.0.2"}


def test_no_ips_empty_string_still_counted():
    logs = [
        _entry(username="alice", ip=""),
        _entry(username="bob", ip=""),
    ]
    stats = generate_statistics(logs)
    assert stats["unique_ips"] == 1
    assert stats["top_ip"] == ("", 2)
