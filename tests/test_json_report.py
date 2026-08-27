"""Tests for JSON reporting."""

import json
from datetime import datetime
from pathlib import Path

from analyzer.models import AnalysisResult
from analyzer.reporting import generate_reports
from analyzer.reporting.json_report import write_json_report
from analyzer.reporting.serialize import build_report_document
from tests.report_fixtures import sample_result


def test_json_report_structure(tmp_path: Path):
    result = sample_result()
    path = write_json_report(result, tmp_path)
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert set(payload.keys()) >= {"metadata", "analysis", "statistics", "alerts", "incidents"}
    assert payload["metadata"]["application"] == "Smart Log Analyzer"
    assert payload["metadata"]["input_file"] == "fixture.log"
    assert "analyzed_at" in payload["analysis"]
    assert isinstance(payload["alerts"], list)
    assert isinstance(payload["incidents"], list)
    assert any(a["alert_type"] == "BRUTE_FORCE" for a in payload["alerts"])
    if payload["alerts"]:
        assert "evidence" in payload["alerts"][0]
        assert isinstance(payload["alerts"][0]["timestamp"], str)


def test_json_datetime_serialization():
    doc = build_report_document(sample_result())
    assert isinstance(doc["analysis"]["analyzed_at"], str)
    if doc["alerts"]:
        assert isinstance(doc["alerts"][0]["timestamp"], str)


def test_json_empty_result(tmp_path: Path):
    result = AnalysisResult(
        input_file="empty.log",
        analyzed_at=datetime(2026, 1, 1, 0, 0, 0),
        duration_seconds=0.0,
        log_count=0,
        parse_stats={"total_lines": 0, "parsed_lines": 0},
        statistics={"total_logs": 0},
        alerts=[],
        incidents=[],
    )
    path = write_json_report(result, tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["analysis"]["log_count"] == 0
    assert payload["alerts"] == []
    assert payload["incidents"] == []
    assert "statistics" in payload


def test_generate_reports_all_kinds(tmp_path: Path):
    written = generate_reports(sample_result(), tmp_path, kinds=["all"])
    assert "json" in written
    assert "html" in written
    assert "summary" in written
    assert "alerts_csv" in written
    assert "incidents_csv" in written
