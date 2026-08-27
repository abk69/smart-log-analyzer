"""Tests for JSON reporting."""

import json
from pathlib import Path

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


def test_json_datetime_serialization():
    doc = build_report_document(sample_result())
    assert isinstance(doc["analysis"]["analyzed_at"], str)
    if doc["alerts"]:
        assert isinstance(doc["alerts"][0]["timestamp"], str)
