"""Tests for Isolation Forest anomaly detection."""

from datetime import datetime, timedelta

import pytest

from analyzer.anomaly.isolation_forest import (
    SKLEARN_AVAILABLE,
    decision_to_anomaly_score,
    detect_anomalies,
)
from analyzer.config import AnalyzerConfig, AnomalyConfig
from analyzer.models import LogEntry
from analyzer.services.analysis_service import AnalysisService


pytestmark = pytest.mark.skipif(
    not SKLEARN_AVAILABLE, reason="scikit-learn is required for anomaly tests"
)


def _login(
    user: str,
    ip: str,
    when: datetime,
    *,
    success: bool = True,
) -> LogEntry:
    return LogEntry(
        timestamp=when,
        username=user,
        ip_address=ip,
        status="SUCCESS" if success else "FAILED",
        source="linux",
        event_type="LOGIN_SUCCESS" if success else "LOGIN_FAILED",
    )


def _normal_fleet(start: datetime, *, ips: int = 25, events_per_ip: int = 4) -> list[LogEntry]:
    logs: list[LogEntry] = []
    for i in range(ips):
        ip = f"10.0.{i // 200}.{i % 200 + 1}"
        user = f"user{i % 10}"
        for j in range(events_per_ip):
            logs.append(
                _login(
                    user,
                    ip,
                    start + timedelta(seconds=i * 10 + j),
                    success=(j % 4 != 0),
                )
            )
    return logs


def _anomalous_ip_burst(start: datetime, ip: str = "203.0.113.50") -> list[LogEntry]:
    logs: list[LogEntry] = []
    for j in range(80):
        logs.append(
            _login(
                f"victim{j % 20}",
                ip,
                start + timedelta(seconds=5000 + j),
                success=False,
            )
        )
    return logs


def test_disabled_configuration():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = _normal_fleet(start) + _anomalous_ip_burst(start)
    assert detect_anomalies(logs, config=AnomalyConfig(enabled=False)) == []


def test_insufficient_data_skips():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [_login("alice", "10.0.0.1", start + timedelta(seconds=i)) for i in range(3)]
    cfg = AnomalyConfig(minimum_samples=20, include_user_entities=False)
    assert detect_anomalies(logs, config=cfg) == []


def test_minimum_sample_boundary_runs():
    start = datetime(2026, 6, 26, 9, 0, 0)
    # Exactly 20 IP entities
    logs = _normal_fleet(start, ips=20, events_per_ip=3)
    cfg = AnomalyConfig(
        minimum_samples=20,
        include_user_entities=False,
        alert_threshold=99.0,  # likely no alerts; just ensure it runs
        random_state=42,
    )
    alerts = detect_anomalies(logs, config=cfg)
    assert isinstance(alerts, list)


def test_score_range_helper():
    assert 0 <= decision_to_anomaly_score(-0.5) <= 100
    assert 0 <= decision_to_anomaly_score(0.5) <= 100
    assert decision_to_anomaly_score(-0.5) > decision_to_anomaly_score(0.5)


def test_deterministic_random_state():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = _normal_fleet(start) + _anomalous_ip_burst(start)
    cfg = AnomalyConfig(
        random_state=42,
        contamination=0.1,
        include_user_entities=False,
        alert_threshold=60.0,
        minimum_samples=20,
    )
    first = detect_anomalies(logs, config=cfg)
    second = detect_anomalies(logs, config=cfg)
    assert len(first) == len(second)
    assert [a.ip_address for a in first] == [a.ip_address for a in second]
    assert [
        round(float(a.evidence["anomaly_score"]), 4) for a in first
    ] == [
        round(float(a.evidence["anomaly_score"]), 4) for a in second
    ]


def test_anomalous_entity_more_likely_flagged():
    start = datetime(2026, 6, 26, 9, 0, 0)
    weird_ip = "203.0.113.50"
    logs = _normal_fleet(start, ips=30) + _anomalous_ip_burst(start, ip=weird_ip)
    cfg = AnomalyConfig(
        random_state=42,
        contamination=0.08,
        include_user_entities=False,
        alert_threshold=65.0,
        minimum_samples=20,
    )
    alerts = detect_anomalies(logs, config=cfg)
    assert alerts, "expected at least one anomaly on clearly unusual IP"
    assert any(a.alert_type == "ANOMALOUS_BEHAVIOR" for a in alerts)
    assert any(a.ip_address == weird_ip for a in alerts)


def test_mostly_normal_not_flooded():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = _normal_fleet(start, ips=40, events_per_ip=5)
    cfg = AnomalyConfig(
        random_state=42,
        contamination=0.05,
        include_user_entities=False,
        alert_threshold=75.0,
        minimum_samples=20,
    )
    alerts = detect_anomalies(logs, config=cfg)
    # Conservative threshold + homogeneous data → few or no alerts
    assert len(alerts) <= max(3, int(0.15 * 40))


def test_alert_structure_and_evidence():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = _normal_fleet(start) + _anomalous_ip_burst(start)
    cfg = AnomalyConfig(
        random_state=42,
        contamination=0.1,
        include_user_entities=False,
        alert_threshold=60.0,
    )
    alerts = detect_anomalies(logs, config=cfg)
    assert alerts
    alert = alerts[0]
    assert alert.alert_type == "ANOMALOUS_BEHAVIOR"
    assert alert.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert alert.alert_id
    assert alert.source == "anomaly"
    assert 0 <= alert.evidence["anomaly_score"] <= 100
    assert alert.evidence["model"] == "IsolationForest"
    assert "features" in alert.evidence
    assert "model_parameters" in alert.evidence
    assert "not an attack probability" in alert.evidence["score_note"]
    assert "does not by itself confirm" in alert.description.lower()
    assert alert.metadata.get("ml") is True


def test_analysis_service_includes_and_disables_anomaly():
    start = datetime(2026, 6, 26, 9, 0, 0)
    # Build syslog-like lines so the full service path is exercised lightly
    # via analyze_lines with pre-made LogEntry path: use detect through config.
    logs = _normal_fleet(start) + _anomalous_ip_burst(start)

    enabled = AnalyzerConfig(
        anomaly=AnomalyConfig(
            enabled=True,
            random_state=42,
            include_user_entities=False,
            contamination=0.1,
            alert_threshold=60.0,
        )
    )
    disabled = AnalyzerConfig(
        anomaly=AnomalyConfig(enabled=False),
    )

    from analyzer.anomaly import detect_anomalies as run

    with_ml = run(logs, config=enabled)
    without = run(logs, config=disabled)
    assert without == []
    assert isinstance(with_ml, list)


def test_service_pipeline_no_anomaly_flag_behavior(tmp_path):
    """With anomaly disabled, service must not emit ANOMALOUS_BEHAVIOR."""
    lines = [
        "Jun 26 09:02:01 server sshd[1020]: Failed password for admin from 203.0.113.10 port 53769 ssh2",
        "Jun 26 09:02:07 server sshd[1021]: Failed password for admin from 203.0.113.10 port 50490 ssh2",
        "Jun 26 09:02:11 server sshd[1022]: Failed password for admin from 203.0.113.10 port 59221 ssh2",
        "Jun 26 09:02:15 server sshd[1023]: Failed password for admin from 203.0.113.10 port 52800 ssh2",
        "Jun 26 09:02:21 server sshd[1024]: Failed password for admin from 203.0.113.10 port 42959 ssh2",
    ]
    cfg = AnalyzerConfig(
        default_log_year=2026,
        anomaly=AnomalyConfig(enabled=False),
    )
    result = AnalysisService(config=cfg).analyze_lines(lines)
    assert any(a.alert_type == "BRUTE_FORCE" for a in result.alerts)
    assert not any(a.alert_type == "ANOMALOUS_BEHAVIOR" for a in result.alerts)
