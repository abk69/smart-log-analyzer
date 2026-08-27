"""Tests for global incident risk scoring."""

from datetime import datetime, timedelta

from analyzer.config import RiskScoringConfig
from analyzer.correlation import correlate_alerts
from analyzer.models import Incident, SecurityAlert
from analyzer.risk import score_incident, score_incidents


def _alert(
    alert_type: str,
    severity: str,
    when: datetime,
    *,
    ip: str = "203.0.113.10",
    user: str = "john",
    confidence: float = 0.5,
) -> SecurityAlert:
    return SecurityAlert(
        alert_type=alert_type,
        severity=severity,
        timestamp=when,
        username=user,
        ip_address=ip,
        description=alert_type,
        confidence=confidence,
        risk_score=99,  # detector-local; must NOT be used as global score
    )


def _single_incident(severity: str) -> Incident:
    alert = _alert("TEST", severity, datetime(2026, 6, 26, 9, 0, 0))
    return correlate_alerts([alert])[0]


def test_low_severity_base_score():
    incident = score_incident(_single_incident("LOW"))
    assert incident.risk_score == 20
    assert incident.evidence["risk_breakdown"]["base_score"] == 20
    assert incident.evidence["risk_breakdown"]["final_score"] == 20


def test_medium_severity_base_score():
    assert score_incident(_single_incident("MEDIUM")).risk_score == 40


def test_high_severity_base_score():
    assert score_incident(_single_incident("HIGH")).risk_score == 70


def test_critical_severity_base_score():
    assert score_incident(_single_incident("CRITICAL")).risk_score == 90


def test_multiple_attack_types_increase_risk():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", "HIGH", start),
        _alert("SQL_INJECTION", "CRITICAL", start + timedelta(minutes=1), confidence=0.9),
    ]
    incident = score_incidents(correlate_alerts(alerts))[0]
    breakdown = incident.evidence["risk_breakdown"]

    assert breakdown["base_score"] == 90
    assert breakdown["multiple_alert_bonus"] == 10
    assert breakdown["multiple_attack_type_bonus"] == 10
    assert incident.risk_score == breakdown["final_score"]
    assert 0 <= incident.risk_score <= 100
    # Must not simply sum detector-local scores (99+99).
    assert incident.risk_score != 198


def test_repeated_activity_bonus():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("XSS", "HIGH", start, ip="1.1.1.1"),
        _alert("XSS", "HIGH", start + timedelta(minutes=1), ip="1.1.1.1"),
    ]
    incident = score_incidents(correlate_alerts(alerts))[0]
    assert "repeated_activity_bonus" in incident.evidence["risk_breakdown"]


def test_privileged_user_modifier():
    incident = score_incident(
        correlate_alerts(
            [_alert("BRUTE_FORCE", "HIGH", datetime(2026, 6, 26, 9, 0, 0), user="admin")]
        )[0]
    )
    assert incident.evidence["risk_breakdown"]["privileged_user_bonus"] == 5
    assert incident.risk_score == 75


def test_high_confidence_bonus():
    incident = score_incident(
        correlate_alerts(
            [
                _alert(
                    "SQL_INJECTION",
                    "CRITICAL",
                    datetime(2026, 6, 26, 9, 0, 0),
                    confidence=0.95,
                )
            ]
        )[0]
    )
    assert incident.evidence["risk_breakdown"]["confidence_bonus"] == 3
    assert incident.risk_score == 93


def test_score_clamped_to_100():
    cfg = RiskScoringConfig(
        multiple_alert_bonus=50,
        multiple_attack_type_bonus=50,
        repeated_activity_bonus=50,
        privileged_user_bonus=50,
        high_confidence_bonus=50,
    )
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("BRUTE_FORCE", "CRITICAL", start, user="admin", confidence=0.99),
        _alert(
            "SQL_INJECTION",
            "CRITICAL",
            start + timedelta(seconds=30),
            user="admin",
            confidence=0.99,
        ),
        _alert(
            "BRUTE_FORCE",
            "CRITICAL",
            start + timedelta(seconds=60),
            user="admin",
            confidence=0.99,
        ),
    ]
    incident = score_incidents(correlate_alerts(alerts), config=cfg)[0]
    assert incident.risk_score == 100


def test_deterministic_output():
    start = datetime(2026, 6, 26, 9, 0, 0)
    alerts = [
        _alert("PASSWORD_SPRAY", "HIGH", start, user="admin, john"),
        _alert("BRUTE_FORCE", "HIGH", start + timedelta(minutes=1), user="admin"),
    ]
    first = score_incidents(correlate_alerts(alerts))[0].risk_score
    second = score_incidents(correlate_alerts(alerts))[0].risk_score
    assert first == second


def test_breakdown_always_present():
    incident = score_incident(_single_incident("MEDIUM"))
    assert "risk_breakdown" in incident.evidence
    assert "final_score" in incident.evidence["risk_breakdown"]
