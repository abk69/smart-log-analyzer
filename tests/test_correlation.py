"""Tests for alert correlation."""

from datetime import datetime, timedelta

from analyzer.config import CorrelationConfig
from analyzer.correlation import correlate_alerts
from analyzer.models import SecurityAlert


def _alert(
    alert_type: str,
    when: datetime,
    *,
    ip: str = "203.0.113.10",
    user: str = "admin",
    severity: str = "HIGH",
) -> SecurityAlert:
    return SecurityAlert(
        alert_type=alert_type,
        severity=severity,
        timestamp=when,
        username=user,
        ip_address=ip,
        description=f"{alert_type} alert",
        confidence=0.9,
    )


def test_same_ip_close_timestamps_one_incident():
    start = datetime(2026, 6, 26, 9, 30, 0)
    alerts = [
        _alert("PASSWORD_SPRAY", start, user="admin, john, alice, mike, emma"),
        _alert("BRUTE_FORCE", start + timedelta(minutes=1)),
        _alert(
            "SQL_INJECTION",
            start + timedelta(minutes=4),
            user="-",
            severity="CRITICAL",
        ),
    ]
    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert len(incidents[0].alerts) == 3
    assert incidents[0].metadata["attack_chain"] == [
        "PASSWORD_SPRAY",
        "BRUTE_FORCE",
        "SQL_INJECTION",
    ]
    assert incidents[0].incident_type == "CORRELATED_ACTIVITY"
    assert "203.0.113.10" in incidents[0].source_ips


def test_same_user_close_timestamps_one_incident():
    start = datetime(2026, 6, 26, 9, 30, 0)
    alerts = [
        _alert("BRUTE_FORCE", start, ip="10.0.0.1", user="admin"),
        _alert(
            "IMPOSSIBLE_TRAVEL",
            start + timedelta(minutes=1),
            ip="198.51.100.50",
            user="admin",
        ),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert set(incidents[0].source_ips) == {"10.0.0.1", "198.51.100.50"}
    assert "admin" in incidents[0].usernames


def test_different_ip_user_far_apart_separate():
    start = datetime(2026, 6, 26, 9, 30, 0)
    alerts = [
        _alert("SQL_INJECTION", start, ip="10.0.0.1", user="-", severity="CRITICAL"),
        _alert(
            "XSS",
            start + timedelta(hours=6),
            ip="10.0.0.2",
            user="-",
            severity="HIGH",
        ),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


def test_same_ip_outside_window_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", start),
        _alert("SQL_INJECTION", start + timedelta(minutes=10), severity="CRITICAL"),
    ]
    # Default window 300s; 10 minutes apart with no intermediate alert.
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


def test_single_alert_incident():
    alerts = [_alert("XSS", datetime(2026, 6, 26, 9, 0, 0), ip="1.1.1.1", user="-")]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert incidents[0].incident_type == "XSS"
    assert len(incidents[0].alerts) == 1


def test_empty_alerts():
    assert correlate_alerts([]) == []


def test_missing_user_and_ip_still_forms_incident():
    alert = SecurityAlert(
        alert_type="XSS",
        severity="HIGH",
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="-",
        ip_address="",
        description="missing context",
    )
    incidents = correlate_alerts([alert])
    assert len(incidents) == 1
    assert incidents[0].source_ips == []
    assert incidents[0].usernames == []


def test_custom_window_merges_farther_alerts():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", start),
        _alert("SQL_INJECTION", start + timedelta(minutes=8), severity="CRITICAL"),
    ]
    cfg = CorrelationConfig(window_seconds=600)
    incidents = correlate_alerts(alerts, config=cfg)
    assert len(incidents) == 1


def test_disabled_correlation_keeps_alerts_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", start),
        _alert("SQL_INJECTION", start + timedelta(seconds=30), severity="CRITICAL"),
    ]
    incidents = correlate_alerts(alerts, config=CorrelationConfig(enabled=False))
    assert len(incidents) == 2


def test_exactly_window_boundary_merges():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", start),
        _alert("SQL_INJECTION", start + timedelta(seconds=300), severity="CRITICAL"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1


def test_just_inside_window_merges():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", start),
        _alert("SQL_INJECTION", start + timedelta(seconds=299), severity="CRITICAL"),
    ]
    assert len(correlate_alerts(alerts)) == 1


def test_just_outside_window_separate():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", start),
        _alert("SQL_INJECTION", start + timedelta(seconds=301), severity="CRITICAL"),
    ]
    assert len(correlate_alerts(alerts)) == 2


def test_missing_ip_only_handled_safely():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        SecurityAlert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            timestamp=start,
            username="admin",
            ip_address="",
            description="no ip",
        ),
        SecurityAlert(
            alert_type="IMPOSSIBLE_TRAVEL",
            severity="HIGH",
            timestamp=start + timedelta(seconds=30),
            username="admin",
            ip_address="",
            description="no ip 2",
        ),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert "admin" in incidents[0].usernames


def test_duplicate_alerts_do_not_inflate_incorrectly():
    start = datetime(2026, 6, 26, 9, 0, 0)
    a = _alert("XSS", start, ip="1.1.1.1", user="-")
    b = _alert("XSS", start, ip="1.1.1.1", user="-")
    incidents = correlate_alerts([a, b])
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 2


def test_attack_chain_deterministic():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("SQL_INJECTION", start + timedelta(minutes=2), severity="CRITICAL"),
        _alert("BRUTE_FORCE", start),
        _alert("XSS", start + timedelta(minutes=1)),
    ]
    first = correlate_alerts(alerts)[0].metadata["attack_chain"]
    second = correlate_alerts(alerts)[0].metadata["attack_chain"]
    assert first == second
    assert first == ["BRUTE_FORCE", "XSS", "SQL_INJECTION"]
