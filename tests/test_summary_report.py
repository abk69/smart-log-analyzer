"""Tests for text summary reporting."""

from pathlib import Path

from analyzer.reporting.summary_report import write_summary_report
from tests.report_fixtures import sample_result


def test_summary_report_metrics(tmp_path: Path):
    result = sample_result()
    path = write_summary_report(result, tmp_path)
    text = path.read_text(encoding="utf-8")

    assert path.exists()
    assert "SECURITY SUMMARY" in text
    assert "TOTAL EVENTS" in text
    assert "TOTAL ALERTS" in text
    assert "TOTAL INCIDENTS" in text
    assert "HIGHEST RISK INCIDENT" in text


def test_summary_empty_result(tmp_path: Path):
    from datetime import datetime

    from analyzer.models import AnalysisResult

    result = AnalysisResult(
        input_file="empty.log",
        analyzed_at=datetime(2026, 1, 1, 0, 0, 0),
        duration_seconds=0.0,
        log_count=0,
        parse_stats={},
        statistics={"total_logs": 0},
    )
    text = write_summary_report(result, tmp_path).read_text(encoding="utf-8")
    assert "TOTAL EVENTS" in text
    assert "0" in text
