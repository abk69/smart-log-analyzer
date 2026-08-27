"""Tests for impossible-travel detection and geolocation helpers."""

from datetime import datetime, timedelta

from analyzer.config import ImpossibleTravelConfig
from analyzer.detectors.impossible_travel import detect_impossible_travel
from analyzer.models import LogEntry, SecurityAlert
from analyzer.services.geolocation import (
    GeoLocation,
    StaticGeoLocationService,
    haversine_km,
)


def _success(user: str, ip: str, when: datetime, *, source: str = "linux") -> LogEntry:
    return LogEntry(
        timestamp=when,
        username=user,
        ip_address=ip,
        status="SUCCESS",
        source=source,
        event_type="LOGIN_SUCCESS",
    )


def test_mumbai_to_new_york_in_five_minutes_alerts():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("alice", "203.0.113.10", start),  # Mumbai
        _success("alice", "198.51.100.50", start + timedelta(minutes=5)),  # New York
    ]
    alerts = detect_impossible_travel(logs)

    assert len(alerts) == 1
    assert isinstance(alerts[0], SecurityAlert)
    assert alerts[0].alert_type == "IMPOSSIBLE_TRAVEL"
    assert alerts[0].username == "alice"
    assert alerts[0].evidence["previous_location"] == "Mumbai"
    assert alerts[0].evidence["current_location"] == "New York"
    assert alerts[0].evidence["distance_km"] > 10000
    assert alerts[0].evidence["required_speed_kmh"] > 900
    assert alerts[0].evidence["configured_speed_threshold"] == 900.0
    assert alerts[0].confidence > 0
    assert alerts[0].risk_score > 0


def test_mumbai_to_pune_over_hours_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("bob", "203.0.113.10", start),  # Mumbai
        _success("bob", "203.0.113.20", start + timedelta(hours=4)),  # Pune
    ]
    assert detect_impossible_travel(logs) == []


def test_same_ip_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("carol", "203.0.113.10", start),
        _success("carol", "203.0.113.10", start + timedelta(minutes=1)),
    ]
    assert detect_impossible_travel(logs) == []


def test_unknown_ip_no_alert():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("dave", "203.0.113.10", start),
        _success("dave", "8.8.8.8", start + timedelta(minutes=2)),
    ]
    assert detect_impossible_travel(logs) == []


def test_insufficient_events_no_alert():
    logs = [_success("erin", "203.0.113.10", datetime(2026, 6, 26, 9, 0, 0))]
    assert detect_impossible_travel(logs) == []


def test_failed_logins_ignored():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        LogEntry(
            timestamp=start,
            username="frank",
            ip_address="203.0.113.10",
            status="FAILED",
            source="linux",
            event_type="LOGIN_FAILED",
        ),
        _success("frank", "198.51.100.50", start + timedelta(minutes=1)),
    ]
    assert detect_impossible_travel(logs) == []


def test_disabled_config():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("gina", "203.0.113.10", start),
        _success("gina", "198.51.100.50", start + timedelta(minutes=5)),
    ]
    cfg = ImpossibleTravelConfig(enabled=False)
    assert detect_impossible_travel(logs, config=cfg) == []


def test_custom_geo_map_and_haversine():
    mumbai = GeoLocation("Mumbai", 19.0760, 72.8777, "IN")
    ny = GeoLocation("New York", 40.7128, -74.0060, "US")
    distance = haversine_km(mumbai, ny)
    assert 11000 < distance < 14000

    service = StaticGeoLocationService(
        {"1.1.1.1": mumbai, "2.2.2.2": ny}
    )
    start = datetime(2026, 6, 26, 12, 0, 0)
    logs = [
        _success("hank", "1.1.1.1", start),
        _success("hank", "2.2.2.2", start + timedelta(minutes=3)),
    ]
    alerts = detect_impossible_travel(logs, geo_service=service)
    assert len(alerts) == 1


def test_identical_timestamps_impossible():
    """Zero elapsed time between distant cities is treated as impossible."""
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("iris", "203.0.113.10", start),  # Mumbai
        _success("iris", "198.51.100.50", start),  # New York, same timestamp
    ]
    alerts = detect_impossible_travel(logs)
    assert len(alerts) == 1
    # Infinite speed is serialized as None for JSON friendliness.
    assert alerts[0].evidence["elapsed_seconds"] == 0
    assert alerts[0].evidence["required_speed_kmh"] is None
    assert alerts[0].evidence["distance_km"] > 10000

def test_out_of_order_events_are_sorted():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("jade", "198.51.100.50", start + timedelta(minutes=5)),
        _success("jade", "203.0.113.10", start),
    ]
    alerts = detect_impossible_travel(logs)
    assert len(alerts) == 1
    assert alerts[0].evidence["previous_location"] == "Mumbai"
    assert alerts[0].evidence["current_location"] == "New York"


def test_multiple_users_independent_sequences():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("alice", "203.0.113.10", start),
        _success("alice", "198.51.100.50", start + timedelta(minutes=5)),
        _success("bob", "203.0.113.10", start),
        _success("bob", "203.0.113.20", start + timedelta(hours=4)),  # realistic
    ]
    alerts = detect_impossible_travel(logs)
    assert len(alerts) == 1
    assert alerts[0].username == "alice"


def test_same_location_different_ip_no_alert():
    mumbai_a = GeoLocation("Mumbai", 19.0760, 72.8777, "IN")
    mumbai_b = GeoLocation("Mumbai", 19.0800, 72.8800, "IN")
    service = StaticGeoLocationService({"1.1.1.1": mumbai_a, "1.1.1.2": mumbai_b})
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("kate", "1.1.1.1", start),
        _success("kate", "1.1.1.2", start + timedelta(minutes=1)),
    ]
    assert detect_impossible_travel(logs, geo_service=service) == []


def test_deterministic_speed_calculation():
    start = datetime(2026, 6, 26, 9, 0, 0)
    logs = [
        _success("leo", "203.0.113.10", start),
        _success("leo", "198.51.100.50", start + timedelta(minutes=5)),
    ]
    first = detect_impossible_travel(logs)[0].evidence["required_speed_kmh"]
    second = detect_impossible_travel(logs)[0].evidence["required_speed_kmh"]
    assert first == second
