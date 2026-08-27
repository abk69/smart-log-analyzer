"""Tests for SQL injection detection."""

from datetime import datetime

from analyzer.config import SqlInjectionConfig
from analyzer.detectors.sql_injection import detect_sql_injection
from analyzer.models import LogEntry, SecurityAlert


def _http(path: str, *, ip: str = "172.16.1.10") -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="-",
        ip_address=ip,
        status="FAILED",
        source="apache",
        event_type="HTTP_REQUEST",
        request=path,
        method="GET",
        path=path,
        status_code=500,
    )


def test_url_encoded_or_tautology():
    alerts = detect_sql_injection(
        [_http("/login?id=1%27%20OR%201=1--")]
    )
    assert len(alerts) == 1
    assert isinstance(alerts[0], SecurityAlert)
    assert alerts[0].alert_type == "SQL_INJECTION"
    assert alerts[0].evidence["pattern"] == "OR 1=1"
    assert "or 1=1" in alerts[0].evidence["normalized_request"]
    assert alerts[0].confidence >= 0.9


def test_union_select():
    alerts = detect_sql_injection(
        [_http("/login?id=1 UNION SELECT username,password FROM users")]
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "UNION SELECT"


def test_union_all_select_mixed_case_whitespace():
    alerts = detect_sql_injection(
        [_http("/q?id=1  UnIoN   aLl   SeLeCt  null")]
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "UNION SELECT"


def test_information_schema():
    alerts = detect_sql_injection(
        [_http("/x?q=select+table_name+from+information_schema.tables")]
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "information_schema"


def test_drop_table():
    alerts = detect_sql_injection(
        [_http("/product?id=5;DROP TABLE users")]
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "DROP TABLE"


def test_sleep_time_based():
    alerts = detect_sql_injection([_http("/x?id=1;SELECT SLEEP(5)")])
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "SLEEP("


def test_one_alert_per_request_even_with_multiple_patterns():
    alerts = detect_sql_injection(
        [_http("/x?id=1 OR 1=1 UNION SELECT * FROM information_schema.tables")]
    )
    assert len(alerts) == 1
    assert "matched_indicators" in alerts[0].evidence
    assert len(alerts[0].evidence["matched_indicators"]) >= 2


def test_negative_normal_product_id():
    assert detect_sql_injection([_http("/products?id=10")]) == []


def test_negative_normal_search():
    assert detect_sql_injection([_http("/search?q=shoes")]) == []


def test_negative_bare_union_word():
    assert detect_sql_injection([_http("/search?q=union")]) == []


def test_negative_bare_select_word():
    assert detect_sql_injection([_http("/article?id=1&note=select")]) == []


def test_negative_standalone_sql_comment():
    assert detect_sql_injection([_http("/item?id=1--")]) == []


def test_disabled_config():
    logs = [_http("/login?id=1 OR 1=1")]
    assert detect_sql_injection(logs, config=SqlInjectionConfig(enabled=False)) == []


def test_evidence_keeps_original_and_normalized():
    original = "/login?id=1%20OR%201=1"
    alert = detect_sql_injection([_http(original)])[0]
    assert alert.evidence["request"] == original
    assert "or 1=1" in alert.evidence["normalized_request"]
    assert alert.source == "apache"
    assert alert.risk_score > 0
