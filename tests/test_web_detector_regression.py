"""Regression: Apache parsing must keep SQLi/XSS detectors working."""

from analyzer.detectors.sql_injection import detect_sql_injection
from analyzer.detectors.xss import detect_xss
from analyzer.parsers.parser_dispatcher import parse_logs


def test_apache_request_fields_feed_web_detectors():
    lines = [
        '172.16.1.10 - - [26/Jun/2026:09:00:00 +0000] "GET /products HTTP/1.1" 200 100',
        (
            '172.16.1.11 - - [26/Jun/2026:09:00:01 +0000] '
            '"GET /login?id=1 UNION SELECT username,password FROM users HTTP/1.1" '
            "500 777"
        ),
        (
            '172.16.1.16 - - [26/Jun/2026:09:00:02 +0000] '
            '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 266'
        ),
    ]

    entries = parse_logs(lines)
    assert len(entries) == 3

    normal, sqli, xss = entries
    assert normal.request == "/products"
    assert normal.path == "/products"
    assert normal.status_code == 200
    assert "UNION SELECT" in sqli.request
    assert sqli.path == sqli.request
    assert "<script>" in xss.request

    sql_alerts = detect_sql_injection(entries)
    xss_alerts = detect_xss(entries)

    assert any(a.alert_type == "SQL_INJECTION" for a in sql_alerts)
    assert any(a.alert_type == "XSS" for a in xss_alerts)
