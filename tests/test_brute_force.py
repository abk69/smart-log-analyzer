"""Tests for brute-force authentication detection."""

from datetime import datetime, timedelta

from analyzer.config import AnalyzerConfig, BruteForceConfig
from analyzer.detectors.brute_force import detect_brute_force
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


def test_below_threshold_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 10))
        for i in range(4)
    ]
    assert detect_brute_force(logs) == []


def test_exact_threshold_one_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 10))
        for i in range(5)
    ]
    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert isinstance(alerts[0], SecurityAlert)
    assert alerts[0].alert_type == "BRUTE_FORCE"
    assert alerts[0].username == "admin"
    assert alerts[0].ip_address == "10.0.0.1"
    assert alerts[0].evidence["attempts"] == 5
    assert alerts[0].evidence["threshold"] == 5
    assert alerts[0].evidence["window_seconds"] == 120
    assert alerts[0].risk_score >= 70
    assert alerts[0].confidence > 0
    assert alerts[0].alert_id


def test_above_threshold_one_logical_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 5))
        for i in range(10)
    ]
    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0].evidence["attempts"] == 10


def test_burst_of_20_does_not_duplicate_alerts():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "203.0.113.10", start + timedelta(seconds=i * 2))
        for i in range(20)
    ]
    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0].evidence["attempts"] == 20


def test_outside_time_window_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    # 5 failures spaced 40s apart => span 160s > 120s window
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 40))
        for i in range(5)
    ]
    assert detect_brute_force(logs) == []


def test_different_ips_are_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = []
    for i in range(5):
        logs.append(_failed("admin", "10.0.0.1", start + timedelta(seconds=i)))
    for i in range(5):
        logs.append(_failed("admin", "10.0.0.2", start + timedelta(seconds=i)))

    alerts = detect_brute_force(logs)
    assert len(alerts) == 2
    assert {a.ip_address for a in alerts} == {"10.0.0.1", "10.0.0.2"}


def test_successful_login_does_not_count():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 10))
        for i in range(4)
    ]
    logs.append(_success("admin", "10.0.0.1", start + timedelta(seconds=50)))
    assert detect_brute_force(logs) == []


def test_empty_logs():
    assert detect_brute_force([]) == []


def test_disabled_returns_no_alerts():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i))
        for i in range(10)
    ]
    cfg = AnalyzerConfig(brute_force=BruteForceConfig(enabled=False))
    assert detect_brute_force(logs, config=cfg) == []


def test_custom_threshold_from_config():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i))
        for i in range(3)
    ]
    cfg = BruteForceConfig(failed_attempt_threshold=3, window_seconds=120)
    alerts = detect_brute_force(logs, config=cfg)
    assert len(alerts) == 1
    assert alerts[0].evidence["threshold"] == 3


def test_threshold_plus_one_still_one_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 5))
        for i in range(6)
    ]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 1
    assert alerts[0].evidence["attempts"] == 6


def test_out_of_order_timestamps_still_detect():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=40)),
        _failed("admin", "10.0.0.1", start + timedelta(seconds=10)),
        _failed("admin", "10.0.0.1", start + timedelta(seconds=30)),
        _failed("admin", "10.0.0.1", start + timedelta(seconds=0)),
        _failed("admin", "10.0.0.1", start + timedelta(seconds=20)),
    ]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 1
    assert alerts[0].evidence["attempts"] == 5


def test_duplicate_timestamps_count_separately():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [_failed("admin", "10.0.0.1", start) for _ in range(5)]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 1
    assert alerts[0].evidence["attempts"] == 5


def test_two_independent_bursts_two_alerts():
    start = datetime(2026, 6, 26, 9, 0, 0)
    first = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i * 5))
        for i in range(5)
    ]
    # Gap > 120s window between bursts
    second_start = start + timedelta(seconds=200)
    second = [
        _failed("admin", "10.0.0.1", second_start + timedelta(seconds=i * 5))
        for i in range(5)
    ]
    alerts = detect_brute_force(first + second)
    assert len(alerts) == 2


def test_different_users_same_ip_are_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = []
    for i in range(5):
        logs.append(_failed("admin", "10.0.0.1", start + timedelta(seconds=i)))
    for i in range(5):
        logs.append(_failed("alice", "10.0.0.1", start + timedelta(seconds=i)))
    alerts = detect_brute_force(logs)
    assert len(alerts) == 2
    assert {a.username for a in alerts} == {"admin", "alice"}


def test_same_user_across_different_ips_already_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _failed("admin", "10.0.0.1", start + timedelta(seconds=i)) for i in range(5)
    ] + [
        _failed("admin", "10.0.0.9", start + timedelta(seconds=i)) for i in range(5)
    ]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 2
