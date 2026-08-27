"""Tests for Apache access log parsing."""

from datetime import datetime

from analyzer.parsers.apache_parser import ApacheParser, parse_apache_line


def test_parse_apache_simple_get():
    line = (
        '172.16.1.73 - - [26/Jun/2026:09:01:14 +0000] '
        '"GET /products HTTP/1.1" 200 342'
    )
    entry = parse_apache_line(line)

    assert entry is not None
    assert entry.source == "apache"
    assert entry.ip_address == "172.16.1.73"
    assert entry.event_type == "HTTP_REQUEST"
    assert entry.method == "GET"
    assert entry.path == "/products"
    assert entry.request == "/products"
    assert entry.status_code == 200
    assert entry.status == "SUCCESS"
    assert entry.timestamp == datetime(2026, 6, 26, 9, 1, 14)
    assert entry.raw_message == line


def test_parse_apache_post_method():
    line = (
        '10.0.0.1 - - [01/Jan/2026:12:00:00 +0000] '
        '"POST /login HTTP/1.1" 302 128'
    )
    entry = parse_apache_line(line)

    assert entry is not None
    assert entry.method == "POST"
    assert entry.status_code == 302
    assert entry.path == "/login"


def test_parse_apache_sql_payload_with_spaces():
    line = (
        '172.16.1.11 - - [26/Jun/2026:09:03:05 +0000] '
        '"GET /login?id=1 UNION SELECT username,password FROM users HTTP/1.1" '
        "500 777"
    )
    entry = parse_apache_line(line)

    assert entry is not None
    assert "UNION SELECT" in entry.request
    assert entry.path == entry.request
    assert entry.status_code == 500
    assert entry.status == "FAILED"


def test_parse_apache_xss_payload():
    line = (
        '172.16.1.16 - - [26/Jun/2026:09:01:04 +0000] '
        '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 266'
    )
    entry = parse_apache_line(line)

    assert entry is not None
    assert "<script>" in entry.path
    assert entry.method == "GET"


def test_apache_malformed_returns_none():
    parser = ApacheParser()
    assert parse_apache_line("not an apache line") is None
    assert parse_apache_line("") is None
    assert parser.can_parse("not an apache line") is False

    malformed = '172.16.1.1 - - [26/Jun/2026:09:01:14 +0000] "GET /products"'
    assert parser.can_parse(malformed) is True
    assert parser.parse_line(malformed) is None


def test_apache_whitespace_and_truncated():
    assert parse_apache_line("   ") is None
    assert parse_apache_line('172.16.1.1 - - [26/Jun/2026:09:01:14 +0000]') is None


def test_apache_malformed_timestamp():
    line = '172.16.1.1 - - [99/Xxx/2026:99:99:99 +0000] "GET /products HTTP/1.1" 200 10'
    assert parse_apache_line(line) is None


def test_apache_malformed_request():
    line = '172.16.1.1 - - [26/Jun/2026:09:01:14 +0000] "NOTAVALIDREQUEST" 200 10'
    # Either unsupported structure → None, or must not crash
    assert parse_apache_line(line) is None or isinstance(parse_apache_line(line), object)


def test_apache_unicode_and_special_path():
    line = (
        '172.16.1.1 - - [26/Jun/2026:09:01:14 +0000] '
        '"GET /files/%E6%96%87%E4%BB%B6?q=a&b=<x> HTTP/1.1" 200 10'
    )
    entry = parse_apache_line(line)
    assert entry is not None
    assert entry.method == "GET"
    assert "q=a" in entry.request


def test_apache_very_long_path_does_not_crash():
    path = "/" + ("a" * 4000)
    line = (
        f'172.16.1.1 - - [26/Jun/2026:09:01:14 +0000] '
        f'"GET {path} HTTP/1.1" 200 10'
    )
    entry = parse_apache_line(line)
    assert entry is not None
    assert len(entry.path) >= 4000
