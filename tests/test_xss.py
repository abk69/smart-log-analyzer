"""Tests for XSS detection."""

from datetime import datetime

from analyzer.config import XssConfig
from analyzer.detectors.xss import detect_xss
from analyzer.models import LogEntry, SecurityAlert


def _http(path: str, *, ip: str = "172.16.1.16") -> LogEntry:
    return LogEntry(
        timestamp=datetime(2026, 6, 26, 9, 0, 0),
        username="-",
        ip_address=ip,
        status="SUCCESS",
        source="apache",
        event_type="HTTP_REQUEST",
        request=path,
        method="GET",
        path=path,
        status_code=200,
    )


def test_script_tag_payload():
    alerts = detect_xss([_http("/search?q=<script>alert(1)</script>")])
    assert len(alerts) == 1
    assert isinstance(alerts[0], SecurityAlert)
    assert alerts[0].alert_type == "XSS"
    assert alerts[0].evidence["pattern"] == "<script"
    assert alerts[0].confidence >= 0.9


def test_url_encoded_script_payload():
    alerts = detect_xss(
        [_http("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")]
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "<script"
    assert "<script" in alerts[0].evidence["normalized_request"]


def test_html_encoded_script_payload():
    alerts = detect_xss([_http("/search?q=&lt;script&gt;alert(1)&lt;/script&gt;")])
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "<script"


def test_javascript_uri():
    alerts = detect_xss([_http("/redir?url=javascript:alert(1)")])
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "javascript:"


def test_onerror_handler():
    alerts = detect_xss([_http("/x?q=<img src=x onerror=alert(1)>")])
    assert len(alerts) == 1
    # Strongest among <img and onerror= is onerror=
    assert alerts[0].evidence["pattern"] == "onerror="
    assert "onerror=" in alerts[0].evidence["matched_indicators"]
    assert "<img" in alerts[0].evidence["matched_indicators"]


def test_onload_and_svg():
    alerts = detect_xss([_http("/profile?name=<svg/onload=alert(1)>")])
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] in {"onload=", "<svg"}
    assert len(alerts[0].evidence["matched_indicators"]) >= 2


def test_onclick_handler():
    alerts = detect_xss([_http("/x?q=<div onclick=alert(1)>")])
    assert len(alerts) == 1
    assert alerts[0].evidence["pattern"] == "onclick="


def test_one_alert_per_request():
    alerts = detect_xss(
        [_http("/x?q=<script>alert(1)</script><svg/onload=alert(1)>")]
    )
    assert len(alerts) == 1


def test_negative_normal_search():
    assert detect_xss([_http("/search?q=shoes")]) == []


def test_negative_ordinary_script_word():
    assert detect_xss([_http("/docs?topic=script")]) == []


def test_negative_harmless_image_url():
    assert detect_xss([_http("/static/images/logo.png")]) == []


def test_negative_normal_html_path():
    assert detect_xss([_http("/about.html")]) == []


def test_disabled_config():
    logs = [_http("/search?q=<script>alert(1)</script>")]
    assert detect_xss(logs, config=XssConfig(enabled=False)) == []


def test_evidence_structure():
    original = "/search?q=%3Cscript%3E"
    alert = detect_xss([_http(original)])[0]
    assert alert.evidence["request"] == original
    assert "normalized_request" in alert.evidence
    assert alert.source == "apache"
    assert alert.risk_score > 0
    assert alert.alert_id
