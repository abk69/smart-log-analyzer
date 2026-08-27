"""Tests for CSV reporting."""

import csv
import json
from datetime import datetime
from pathlib import Path

from analyzer.models import AnalysisResult, SecurityAlert
from analyzer.reporting.csv_report import write_csv_reports
from tests.report_fixtures import sample_result


def test_csv_reports_created(tmp_path: Path):
    result = sample_result()
    paths = write_csv_reports(result, tmp_path)
    assert paths["alerts_csv"].exists()
    assert paths["incidents_csv"].exists()

    with paths["alerts_csv"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert "alert_id" in rows[0]
    assert "evidence" in rows[0]
    assert any(row["alert_type"] == "BRUTE_FORCE" for row in rows)

    with paths["incidents_csv"].open(encoding="utf-8", newline="") as handle:
        incidents = list(csv.DictReader(handle))
    assert incidents
    assert "incident_id" in incidents[0]
    assert "alert_count" in incidents[0]


def test_csv_special_characters_and_nested_evidence(tmp_path: Path):
    result = AnalysisResult(
        input_file="x.log",
        analyzed_at=datetime(2026, 1, 1, 0, 0, 0),
        duration_seconds=0.1,
        log_count=1,
        parse_stats={"total_lines": 1, "parsed_lines": 1},
        statistics={"total_logs": 1},
        alerts=[
            SecurityAlert(
                alert_type="XSS",
                severity="HIGH",
                timestamp=datetime(2026, 1, 1, 0, 0, 0),
                username='user, "quoted"',
                ip_address="1.1.1.1",
                description='desc with, commas and "quotes"',
                evidence={"pattern": "<script>", "note": "a,b"},
            )
        ],
        incidents=[],
    )
    paths = write_csv_reports(result, tmp_path)
    with paths["alerts_csv"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert 'quoted' in rows[0]["username"]
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["pattern"] == "<script>"


def test_csv_empty_result_headers_only(tmp_path: Path):
    result = AnalysisResult(
        input_file="empty.log",
        analyzed_at=datetime(2026, 1, 1, 0, 0, 0),
        duration_seconds=0.0,
        log_count=0,
        parse_stats={},
        statistics={},
        alerts=[],
        incidents=[],
    )
    paths = write_csv_reports(result, tmp_path)
    with paths["alerts_csv"].open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames is not None
        assert "alert_id" in reader.fieldnames
        assert list(reader) == []
