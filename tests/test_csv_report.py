"""Tests for CSV reporting."""

import csv
from pathlib import Path

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
