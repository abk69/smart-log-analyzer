"""Tests for password-spray authentication detection."""

from datetime import datetime, timedelta

from analyzer.config import AnalyzerConfig, PasswordSprayConfig
from analyzer.detectors.password_spray import detect_password_spray
from analyzer.models import LogEntry, SecurityAlert


def _failed(
    username: str,
    ip: str,
    when: datetime,
    *,
    source: str = "linux",
) -> LogEntry:
    return LogEntry(
        timestamp=when,
        username=username,
        ip_address=ip,
        status="FAILED",
        source=source,
        event_type="LOGIN_FAILED",
    )


def _success(username: str, ip: str, when: datetime) -> LogEntry:
    return LogEntry(
        timestamp=when,
        username=username,
        ip_address=ip,
        status="SUCCESS",
        source="linux",
        event_type="LOGIN_SUCCESS",
    )


def test_below_unique_user_threshold_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = ["admin", "john", "alice", "mike"]
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i * 10))
        for i, user in enumerate(users)
    ]
    assert detect_password_spray(logs) == []


def test_exact_threshold_one_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = ["admin", "john", "alice", "mike", "emma"]
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i * 10))
        for i, user in enumerate(users)
    ]
    alerts = detect_password_spray(logs)

    assert len(alerts) == 1
    assert isinstance(alerts[0], SecurityAlert)
    assert alerts[0].alert_type == "PASSWORD_SPRAY"
    assert alerts[0].ip_address == "198.51.100.20"
    assert alerts[0].evidence["unique_users"] == 5
    assert alerts[0].evidence["threshold"] == 5
    assert alerts[0].evidence["window_seconds"] == 120
    assert set(alerts[0].evidence["users"]) == set(users)
    assert alerts[0].risk_score >= 70
    assert alerts[0].alert_id


def test_ten_users_one_alert_no_duplicates():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = [f"user{i}" for i in range(10)]
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i * 5))
        for i, user in enumerate(users)
    ]
    alerts = detect_password_spray(logs)

    assert len(alerts) == 1
    assert alerts[0].evidence["unique_users"] == 10
    assert len(alerts[0].evidence["users"]) == 10


def test_outside_time_window_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = ["admin", "john", "alice", "mike", "emma"]
    # 40s spacing => span 160s > 120s
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i * 40))
        for i, user in enumerate(users)
    ]
    assert detect_password_spray(logs) == []


def test_same_user_many_failures_is_not_spray():
    """Same user + same IP is brute force territory, not spray."""
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "198.51.100.20", start + timedelta(seconds=i * 5))
        for i in range(10)
    ]
    assert detect_password_spray(logs) == []


def test_different_ips_are_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = ["admin", "john", "alice", "mike", "emma"]
    logs = []
    for i, user in enumerate(users):
        logs.append(_failed(user, "10.0.0.1", start + timedelta(seconds=i)))
        logs.append(_failed(user, "10.0.0.2", start + timedelta(seconds=i)))

    alerts = detect_password_spray(logs)
    assert len(alerts) == 2
    assert {a.ip_address for a in alerts} == {"10.0.0.1", "10.0.0.2"}


def test_successful_login_does_not_count():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = ["admin", "john", "alice", "mike"]
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i * 10))
        for i, user in enumerate(users)
    ]
    logs.append(_success("emma", "198.51.100.20", start + timedelta(seconds=50)))
    assert detect_password_spray(logs) == []


def test_empty_logs():
    assert detect_password_spray([]) == []


def test_disabled_returns_no_alerts():
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = [f"user{i}" for i in range(8)]
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i))
        for i, user in enumerate(users)
    ]
    cfg = AnalyzerConfig(password_spray=PasswordSprayConfig(enabled=False))
    assert detect_password_spray(logs, config=cfg) == []


def test_overlapping_windows_collapsed():
    """Regression: growing unique-user counts must not emit stacked alerts."""
    start = datetime(2026, 6, 26, 9, 0, 0)
    users = ["admin", "john", "alice", "mike", "emma", "david", "root", "guest"]
    logs = [
        _failed(user, "198.51.100.20", start + timedelta(seconds=i * 3))
        for i, user in enumerate(users)
    ]
    alerts = detect_password_spray(logs)
    assert len(alerts) == 1
    assert alerts[0].evidence["unique_users"] == 8
