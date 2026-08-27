"""Tests for anomaly feature extraction."""

from datetime import datetime, timedelta

from analyzer.anomaly.features import (
    FEATURE_NAMES,
    extract_feature_vectors,
)
from analyzer.config import AnomalyConfig
from analyzer.models import LogEntry


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


def _http(ip: str, path: str, when: datetime, *, status: int = 200) -> LogEntry:
    return LogEntry(
        timestamp=when,
        username="-",
        ip_address=ip,
        status="SUCCESS" if status < 400 else "FAILED",
        source="apache",
        event_type="HTTP_REQUEST",
        request=path,
        path=path,
        method="GET",
        status_code=status,
    )


def test_empty_input():
    assert extract_feature_vectors([]) == []


def test_single_entity_ip():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [_login("alice", "10.0.0.1", start)]
    vectors = extract_feature_vectors(logs, AnomalyConfig(include_user_entities=False))
    assert len(vectors) == 1
    assert vectors[0].entity_id == "10.0.0.1"
    assert vectors[0].entity_type == "ip"
    assert vectors[0].feature_names == FEATURE_NAMES
    assert vectors[0].as_dict()["total_events"] == 1
    assert vectors[0].as_dict()["successful_logins"] == 1


def test_multiple_ips_and_users():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _login("alice", "10.0.0.1", start),
        _login("bob", "10.0.0.2", start + timedelta(seconds=1), success=False),
        _http("10.0.0.1", "/products", start + timedelta(seconds=2)),
    ]
    vectors = extract_feature_vectors(logs)
    ips = {v.entity_id for v in vectors if v.entity_type == "ip"}
    users = {v.entity_id for v in vectors if v.entity_type == "user"}
    assert ips == {"10.0.0.1", "10.0.0.2"}
    assert users == {"alice", "bob"}


def test_failed_success_ratios_and_uniques():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _login("alice", "203.0.113.10", start, success=False),
        _login("bob", "203.0.113.10", start + timedelta(seconds=1), success=False),
        _login("alice", "203.0.113.10", start + timedelta(seconds=2), success=True),
        _http("203.0.113.10", "/a", start + timedelta(seconds=3), status=500),
        _http("203.0.113.10", "/b", start + timedelta(seconds=4), status=200),
    ]
    vectors = extract_feature_vectors(
        logs, AnomalyConfig(include_user_entities=False)
    )
    feats = vectors[0].as_dict()
    assert feats["total_events"] == 5
    assert feats["failed_logins"] == 2
    assert feats["successful_logins"] == 1
    assert abs(feats["failed_ratio"] - 2 / 5) < 1e-9
    assert feats["unique_users"] == 2
    assert feats["unique_paths"] == 2
    assert feats["http_requests"] == 2
    assert feats["http_errors"] == 1
    assert feats["auth_attempts"] == 3
    assert feats["source_diversity"] == 2


def test_unusual_hours_counted():
    day = datetime(2026, 6, 26, 14, 0, 0)
    night = datetime(2026, 6, 26, 2, 0, 0)
    logs = [
        _login("alice", "10.0.0.1", day),
        _login("alice", "10.0.0.1", night),
    ]
    feats = extract_feature_vectors(
        logs, AnomalyConfig(include_user_entities=False)
    )[0].as_dict()
    assert feats["unusual_hour_events"] == 1


def test_feature_extraction_deterministic():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _login("alice", "10.0.0.1", start, success=False),
        _login("bob", "10.0.0.2", start + timedelta(seconds=1)),
        _http("10.0.0.1", "/x", start + timedelta(seconds=2), status=404),
    ]
    first = [v.as_dict() for v in extract_feature_vectors(logs)]
    second = [v.as_dict() for v in extract_feature_vectors(logs)]
    assert first == second
