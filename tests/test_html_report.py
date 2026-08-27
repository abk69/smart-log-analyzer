"""Tests for HTML reporting and output escaping."""

from datetime import datetime
from pathlib import Path

from analyzer.models import AnalysisResult, Incident, SecurityAlert
from analyzer.reporting.html_report import write_html_report
from tests.report_fixtures import sample_result


def _empty_result(**kwargs) -> AnalysisResult:
    base = dict(
        input_file="x.log",
        analyzed_at=datetime(2026, 1, 1, 0, 0, 0),
        duration_seconds=0.1,
        log_count=0,
        parse_stats={
            "total_lines": 0,
            "parsed_lines": 0,
            "malformed_lines": 0,
            "unsupported_lines": 0,
        },
        statistics={"total_logs": 0, "top_ip": ("-", 0), "top_user": ("-", 0)},
        alerts=[],
        incidents=[],
    )
    base.update(kwargs)
    return AnalysisResult(**base)


def test_html_report_standalone(tmp_path: Path):
    result = sample_result()
    path = write_html_report(result, tmp_path)
    content = path.read_text(encoding="utf-8")

    assert path.exists()
    assert "<!DOCTYPE html>" in content
    assert "Smart Log Analyzer" in content
    assert "Security Analysis Report" in content
    assert "cdn." not in content.lower()
    assert "BRUTE_FORCE" in content or "SQL_INJECTION" in content
    assert "Security Incidents" in content
    assert "View Evidence" in content
    assert "Log Overview" in content


def test_html_escaping_script_tag(tmp_path: Path):
    result = _empty_result(
        log_count=1,
        parse_stats={
            "total_lines": 1,
            "parsed_lines": 1,
            "malformed_lines": 0,
            "unsupported_lines": 0,
        },
        statistics={"total_logs": 1, "top_ip": ("1.1.1.1", 1), "top_user": ("admin", 1)},
        alerts=[
            SecurityAlert(
                alert_type="XSS",
                severity="HIGH",
                timestamp=datetime(2026, 1, 1, 0, 0, 0),
                username="-",
                ip_address="1.1.1.1",
                description='<script>alert("test")</script>',
                evidence={"pattern": "<script", "raw": '<script>alert("test")</script>'},
            )
        ],
    )
    content = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    assert '<script>alert("test")</script>' not in content
    assert "&lt;script&gt;" in content


def test_html_escaping_ampersand_quotes_unicode(tmp_path: Path):
    result = _empty_result(
        alerts=[
            SecurityAlert(
                alert_type="XSS",
                severity="HIGH",
                timestamp=datetime(2026, 1, 1, 0, 0, 0),
                username='ops&qa"ユーザー',
                ip_address="1.1.1.1",
                description='A & B < C > D "quoted"',
                evidence={"note": "x & y < z > \"q\""},
            )
        ],
        incidents=[
            Incident(
                incident_type="XSS",
                severity="HIGH",
                first_seen=datetime(2026, 1, 1, 0, 0, 0),
                last_seen=datetime(2026, 1, 1, 0, 0, 0),
                description="inc & <tag>",
                usernames=['ops&qa"ユーザー'],
                evidence={"x": "<y>"},
            )
        ],
    )
    content = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    assert "&amp;" in content
    assert "&lt;" in content
    assert "&gt;" in content
    assert "ユーザー" in content
    # Raw unescaped control characters must not appear as injectable markup
    assert "inc & <tag>" not in content


def test_html_empty_result(tmp_path: Path):
    content = write_html_report(_empty_result(), tmp_path).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Total Events" in content or "total" in content.lower()


def test_html_includes_statistics_and_evidence(tmp_path: Path):
    result = sample_result()
    content = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    assert "evidence" in content.lower() or "View Evidence" in content
    assert str(result.statistics.get("total_logs", "")) in content or "Log Overview" in content
