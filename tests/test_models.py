"""Tests for core data models."""

from datetime import datetime

from analyzer.models import AnalysisResult, Incident, LogEntry, SecurityAlert
from analyzer.reporting.serialize import alert_to_dict, incident_to_dict


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


def test_log_entry_empty_optional_values_allowed():
    entry = LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="",
        ip_address="",
        status="FAILED",
        source="apache",
        event_type="HTTP_REQUEST",
        request="",
        path="",
    )
    assert entry.username == ""
    assert entry.ip_address == ""
    assert entry.request == ""


def test_log_entry_special_characters_and_unicode():
    entry = LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="ユーザー名_jøhn",
        ip_address="10.0.0.1",
        status="SUCCESS",
        source="linux",
        event_type="LOGIN_SUCCESS",
        request="/search?q=<script>&x=\"y\"",
        path="/files/résumé.pdf",
        raw_message="line with 'quotes' & <tags>",
    )
    assert "ユーザー" in entry.username
    assert "<script>" in entry.request
    assert "résumé" in entry.path


def test_log_entry_long_request_string():
    long_request = "/api?" + ("a" * 5000) + "=1"
    entry = LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="-",
        ip_address="1.1.1.1",
        status="SUCCESS",
        source="apache",
        event_type="HTTP_REQUEST",
        request=long_request,
        path=long_request,
    )
    assert len(entry.request) > 5000


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


def test_security_alert_structured_fields():
    evidence = {"pattern": "OR 1=1", "attempts": 5}
    metadata = {"detector": "sql_injection"}
    alert = SecurityAlert(
        alert_type="SQL_INJECTION",
        severity="CRITICAL",
        timestamp=datetime(2026, 6, 26, 9, 6, 0),
        username="-",
        ip_address="172.16.1.2",
        description="SQLi",
        evidence=evidence,
        confidence=0.95,
        risk_score=90,
        metadata=metadata,
        source="apache",
    )
    assert alert.evidence == evidence
    assert alert.confidence == 0.95
    assert alert.risk_score == 90
    assert alert.metadata == metadata

    payload = alert_to_dict(alert)
    assert payload["alert_id"] == alert.alert_id
    assert payload["evidence"]["pattern"] == "OR 1=1"
    assert payload["confidence"] == 0.95
    assert isinstance(payload["timestamp"], str)


def test_incident_auto_id_and_fields():
    ts = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        SecurityAlert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            timestamp=ts,
            username="admin",
            ip_address="10.0.0.1",
            description="bf",
        ),
        SecurityAlert(
            alert_type="SQL_INJECTION",
            severity="CRITICAL",
            timestamp=ts,
            username="alice",
            ip_address="10.0.0.2",
            description="sqli",
        ),
    ]
    incident = Incident(
        incident_type="CORRELATED_ACTIVITY",
        severity="CRITICAL",
        first_seen=ts,
        last_seen=ts,
        description="multi-alert",
        source_ips=["10.0.0.1", "10.0.0.2"],
        usernames=["admin", "alice"],
        alert_ids=[a.alert_id for a in alerts],
        alerts=alerts,
        evidence={"observed_alert_chain": ["BRUTE_FORCE", "SQL_INJECTION"]},
        metadata={"attack_chain": ["BRUTE_FORCE", "SQL_INJECTION"]},
        risk_score=95,
    )

    assert incident.incident_id
    assert len(incident.alerts) == 2
    assert len(incident.source_ips) == 2
    assert len(incident.usernames) == 2
    assert incident.severity == "CRITICAL"
    assert incident.evidence["observed_alert_chain"][0] == "BRUTE_FORCE"

    other = Incident(
        incident_type="XSS",
        severity="HIGH",
        first_seen=ts,
        last_seen=ts,
        description="solo",
    )
    assert other.incident_id != incident.incident_id

    payload = incident_to_dict(incident, include_alerts=True)
    assert payload["alert_count"] == 2
    assert len(payload["alerts"]) == 2


def test_analysis_result_normal_and_empty():
    ts = datetime(2026, 6, 26, 10, 0, 0)
    empty = AnalysisResult(
        input_file="empty.log",
        analyzed_at=ts,
        duration_seconds=0.0,
        log_count=0,
        parse_stats={"total_lines": 0, "parsed_lines": 0},
        statistics={"total_logs": 0},
    )
    assert empty.alerts == []
    assert empty.incidents == []
    assert empty.logs == []
    assert empty.log_count == 0

    alert = SecurityAlert(
        alert_type="XSS",
        severity="HIGH",
        timestamp=ts,
        username="-",
        ip_address="1.1.1.1",
        description="xss",
    )
    incident = Incident(
        incident_type="XSS",
        severity="HIGH",
        first_seen=ts,
        last_seen=ts,
        description="xss incident",
        alerts=[alert],
    )
    result = AnalysisResult(
        input_file="sample.log",
        analyzed_at=ts,
        duration_seconds=1.25,
        log_count=3,
        parse_stats={"total_lines": 4, "parsed_lines": 3},
        statistics={"total_logs": 3, "unique_users": 1},
        alerts=[alert],
        incidents=[incident],
    )
    assert result.duration_seconds == 1.25
    assert result.analyzed_at == ts
    assert len(result.alerts) == 1
    assert len(result.incidents) == 1
    assert result.statistics["unique_users"] == 1
