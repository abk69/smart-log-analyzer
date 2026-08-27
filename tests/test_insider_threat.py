"""Tests for heuristic insider-threat detection."""

from datetime import datetime, timedelta

from analyzer.config import InsiderThreatConfig
from analyzer.detectors.insider_threat import detect_insider_threat
from analyzer.models import LogEntry, SecurityAlert


def _login(
    user: str,
    ip: str,
    when: datetime,
    *,
    success: bool = True,
    source: str = "linux",
) -> LogEntry:
    return LogEntry(
        timestamp=when,
        username=user,
        ip_address=ip,
        status="SUCCESS" if success else "FAILED",
        source=source,
        event_type="LOGIN_SUCCESS" if success else "LOGIN_FAILED",
    )


def _http(user: str, ip: str, path: str, when: datetime) -> LogEntry:
    return LogEntry(
        timestamp=when,
        username=user,
        ip_address=ip,
        status="SUCCESS",
        source="apache",
        event_type="HTTP_REQUEST",
        request=path,
        path=path,
        method="GET",
        status_code=200,
    )


def test_combined_signals_alert():
    """Privileged + unusual hour + sensitive path should cross threshold."""
    start = datetime(2026, 6, 26, 2, 0, 0)  # unusual hour (0-5)
    logs = [
        _login("admin", "10.0.0.5", start),
        _http("admin", "10.0.0.5", "/admin/users", start + timedelta(minutes=1)),
    ]
    alerts = detect_insider_threat(logs)

    assert len(alerts) == 1
    assert isinstance(alerts[0], SecurityAlert)
    assert alerts[0].alert_type == "INSIDER_THREAT"
    assert alerts[0].username == "admin"
    assert "privileged_account" in alerts[0].evidence["signals"]
    assert "unusual_hour" in alerts[0].evidence["signals"]
    assert "sensitive_resource_access" in alerts[0].evidence["signals"]
    assert alerts[0].evidence["score"] >= 50


def test_privileged_alone_no_alert():
    start = datetime(2026, 6, 26, 14, 0, 0)  # daytime
    logs = [_login("admin", "10.0.0.5", start)]
    assert detect_insider_threat(logs) == []


def test_unusual_hour_alone_no_alert():
    start = datetime(2026, 6, 26, 3, 0, 0)
    logs = [_login("alice", "10.0.0.8", start)]
    assert detect_insider_threat(logs) == []


def test_admin_at_2300_alone_no_alert():
    """23:00 is outside default unusual window [0, 5)."""
    start = datetime(2026, 6, 26, 23, 0, 0)
    logs = [_login("admin", "10.0.0.5", start)]
    assert detect_insider_threat(logs) == []


def test_high_activity_with_privileged_alerts():
    start = datetime(2026, 6, 26, 10, 0, 0)
    logs = [
        _login("admin", "10.0.0.5", start + timedelta(minutes=i))
        for i in range(20)
    ]
    alerts = detect_insider_threat(logs)
    assert len(alerts) == 1
    assert "high_activity_volume" in alerts[0].evidence["signals"]
    assert "privileged_account" in alerts[0].evidence["signals"]


def test_sensitive_request_with_privileged_alerts():
    start = datetime(2026, 6, 26, 11, 0, 0)
    logs = [
        _login("root", "10.0.0.5", start),
        _http("root", "10.0.0.5", "/backup/dump.sql", start + timedelta(minutes=2)),
    ]
    alerts = detect_insider_threat(logs)
    assert len(alerts) == 1
    assert "sensitive_resource_access" in alerts[0].evidence["signals"]


def test_unusual_ip_signal_with_privileged():
    start = datetime(2026, 6, 26, 12, 0, 0)
    logs = [
        _login("admin", "10.0.0.5", start),
        _login("admin", "10.0.0.5", start + timedelta(minutes=1)),
        _login("admin", "203.0.113.99", start + timedelta(minutes=2)),
    ]
    alerts = detect_insider_threat(logs)
    assert len(alerts) == 1
    assert "unusual_source_ip" in alerts[0].evidence["signals"]


def test_below_threshold_with_custom_scores():
    cfg = InsiderThreatConfig(
        alert_score_threshold=100,
        score_privileged=30,
        score_unusual_hour=20,
    )
    start = datetime(2026, 6, 26, 2, 0, 0)
    logs = [_login("admin", "10.0.0.5", start)]
    assert detect_insider_threat(logs, config=cfg) == []


def test_disabled_config():
    start = datetime(2026, 6, 26, 2, 0, 0)
    logs = [
        _login("admin", "10.0.0.5", start),
        _http("admin", "10.0.0.5", "/secret/keys", start + timedelta(minutes=1)),
    ]
    assert detect_insider_threat(logs, config=InsiderThreatConfig(enabled=False)) == []


def test_empty_logs():
    assert detect_insider_threat([]) == []
