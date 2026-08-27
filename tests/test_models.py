"""Tests for core data models."""

from datetime import datetime

from analyzer.models import LogEntry, SecurityAlert


def test_log_entry_requires_core_fields():
    entry = LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="admin",
        ip_address="192.168.1.10",
        status="FAILED",
        source="linux",
        event_type="LOGIN_FAILED",
    )

    assert entry.username == "admin"
    assert entry.ip_address == "192.168.1.10"
    assert entry.source == "linux"
    assert entry.event_type == "LOGIN_FAILED"


def test_log_entry_optional_field_defaults():
    entry = LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="alice",
        ip_address="10.0.0.1",
        status="SUCCESS",
        source="windows",
        event_type="LOGIN_SUCCESS",
    )

    assert entry.request == ""
    assert entry.method == ""
    assert entry.path == ""
    assert entry.status_code is None
    assert entry.raw_message == ""


def test_security_alert_can_be_created_with_legacy_fields():
    alert = SecurityAlert(
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        timestamp=datetime(2026, 6, 26, 9, 2, 0),
        username="admin",
        ip_address="203.0.113.10",
        description="Repeated failed logins.",
    )

    assert alert.alert_type == "BRUTE_FORCE"
    assert alert.severity == "HIGH"
    assert alert.source == ""
    assert alert.evidence == []
    assert alert.confidence == 0.0
    assert alert.risk_score == 0
    assert alert.metadata == {}


def test_security_alert_id_auto_populated():
    alert = SecurityAlert(
        alert_type="XSS",
        severity="HIGH",
        timestamp=datetime(2026, 6, 26, 9, 5, 0),
        username="-",
        ip_address="172.16.1.1",
        description="XSS pattern detected.",
    )

    assert isinstance(alert.alert_id, str)
    assert len(alert.alert_id) > 0


def test_security_alert_ids_are_unique():
    kwargs = dict(
        alert_type="SQL_INJECTION",
        severity="CRITICAL",
        timestamp=datetime(2026, 6, 26, 9, 6, 0),
        username="-",
        ip_address="172.16.1.2",
        description="SQL Injection pattern detected.",
    )

    first = SecurityAlert(**kwargs)
    second = SecurityAlert(**kwargs)

    assert first.alert_id != second.alert_id
