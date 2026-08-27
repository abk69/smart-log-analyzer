"""Tests for HTML reporting."""

from pathlib import Path

from analyzer.models import AnalysisResult, SecurityAlert
from analyzer.reporting.html_report import write_html_report
from datetime import datetime
from tests.report_fixtures import sample_result


def test_html_report_standalone(tmp_path: Path):
    result = sample_result()
    path = write_html_report(result, tmp_path)
    content = path.read_text(encoding="utf-8")

    assert path.exists()
    assert "<!DOCTYPE html>" in content
    assert "Smart Log Analyzer" in content
    assert "Security Analysis Report" in content
    assert "http://" not in content.lower() or "http-equiv" in content.lower()
    assert "cdn." not in content.lower()
    assert "BRUTE_FORCE" in content or "SQL_INJECTION" in content
    assert "Security Incidents" in content
    assert "View Evidence" in content


def test_html_escaping(tmp_path: Path):
    result = AnalysisResult(
        input_file="x.log",
        analyzed_at=datetime(2026, 1, 1, 0, 0, 0),
        duration_seconds=0.1,
        log_count=1,
        parse_stats={"total_lines": 1, "parsed_lines": 1, "malformed_lines": 0, "unsupported_lines": 0},
        statistics={"total_logs": 1, "top_ip": ("1.1.1.1", 1), "top_user": ("admin", 1)},
        alerts=[
            SecurityAlert(
                alert_type="XSS",
                severity="HIGH",
                timestamp=datetime(2026, 1, 1, 0, 0, 0),
                username="-",
                ip_address="1.1.1.1",
                description="<script>alert(1)</script>",
                evidence={"pattern": "<script"},
            )
        ],
        incidents=[],
    )
    content = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
