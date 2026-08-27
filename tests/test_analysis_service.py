"""Tests for AnalysisService orchestration."""

from datetime import datetime
from pathlib import Path

from analyzer.config import (
    AnalyzerConfig,
    BruteForceConfig,
    SqlInjectionConfig,
    XssConfig,
)
from analyzer.models import AnalysisResult, SecurityAlert
from analyzer.services.analysis_service import AnalysisService, deduplicate_alerts


FIXTURE_LINES = [
    "Jun 26 09:02:01 server sshd[1020]: Failed password for admin from 203.0.113.10 port 53769 ssh2",
    "Jun 26 09:02:07 server sshd[1021]: Failed password for admin from 203.0.113.10 port 50490 ssh2",
    "Jun 26 09:02:11 server sshd[1022]: Failed password for admin from 203.0.113.10 port 59221 ssh2",
    "Jun 26 09:02:15 server sshd[1023]: Failed password for admin from 203.0.113.10 port 52800 ssh2",
    "Jun 26 09:02:21 server sshd[1024]: Failed password for admin from 203.0.113.10 port 42959 ssh2",
    '172.16.1.11 - - [26/Jun/2026:09:03:05 +0000] "GET /login?id=1 UNION SELECT username,password FROM users HTTP/1.1" 500 777',
    '172.16.1.16 - - [26/Jun/2026:09:01:04 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 266',
    "this is not a valid log line",
    '2026-06-26T09:00:25 EVENT_ID=4624 USER=alice IP=10.0.0.16 MESSAGE="ok"',
]


def test_successful_analysis_mixed_logs():
    service = AnalysisService(config=AnalyzerConfig(default_log_year=2026))
    result = service.analyze_lines(FIXTURE_LINES, input_file="fixture.log")

    assert isinstance(result, AnalysisResult)
    assert result.input_file == "fixture.log"
    assert result.log_count >= 7
    assert result.parse_stats["parsed_lines"] == result.log_count
    assert result.parse_stats["unsupported_lines"] >= 1
    assert result.statistics["total_logs"] == result.log_count
    assert any(a.alert_type == "BRUTE_FORCE" for a in result.alerts)
    assert any(a.alert_type == "SQL_INJECTION" for a in result.alerts)
    assert any(a.alert_type == "XSS" for a in result.alerts)
    assert len(result.incidents) >= 1
    assert result.duration_seconds >= 0
    assert result.analyzed_at is not None


def test_empty_file_analysis(tmp_path: Path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    result = AnalysisService().analyze_file(empty)

    assert result.log_count == 0
    assert result.alerts == []
    assert result.statistics["total_logs"] == 0
    assert result.parse_stats["total_lines"] == 0


def test_malformed_logs_do_not_crash():
    lines = ["??? garbage ???", "still not a log", ""]
    result = AnalysisService().analyze_lines(lines)
    assert result.log_count == 0
    assert result.parse_stats["unsupported_lines"] >= 2
    assert result.alerts == []


def test_disabling_detector_skips_it():
    cfg = AnalyzerConfig(
        default_log_year=2026,
        sql_injection=SqlInjectionConfig(enabled=False),
        xss=XssConfig(enabled=False),
        brute_force=BruteForceConfig(enabled=True),
    )
    result = AnalysisService(config=cfg).analyze_lines(FIXTURE_LINES)
    types = {a.alert_type for a in result.alerts}
    assert "SQL_INJECTION" not in types
    assert "XSS" not in types
    assert "BRUTE_FORCE" in types


def test_analyze_file_missing_raises(tmp_path: Path):
    from analyzer.exceptions import LogFileError

    missing = tmp_path / "nope.log"
    try:
        AnalysisService().analyze_file(missing)
        assert False, "expected LogFileError"
    except LogFileError:
        pass


def test_deduplicate_exact_alerts_only():
    ts = datetime(2026, 6, 26, 9, 0, 0)
    evidence = {"pattern": "OR 1=1"}
    a = SecurityAlert(
        alert_type="SQL_INJECTION",
        severity="CRITICAL",
        timestamp=ts,
        username="-",
        ip_address="1.1.1.1",
        description="a",
        evidence=evidence,
    )
    b = SecurityAlert(
        alert_type="SQL_INJECTION",
        severity="CRITICAL",
        timestamp=ts,
        username="-",
        ip_address="1.1.1.1",
        description="b",
        evidence=evidence,
    )
    c = SecurityAlert(
        alert_type="XSS",
        severity="HIGH",
        timestamp=ts,
        username="-",
        ip_address="1.1.1.1",
        description="c",
        evidence={"pattern": "<script"},
    )
    unique = deduplicate_alerts([a, b, c])
    assert len(unique) == 2


def test_result_contains_statistics_keys():
    result = AnalysisService(config=AnalyzerConfig(default_log_year=2026)).analyze_lines(
        FIXTURE_LINES
    )
    for key in (
        "total_logs",
        "linux_logs",
        "windows_logs",
        "apache_logs",
        "successful_logins",
        "failed_logins",
        "http_requests",
    ):
        assert key in result.statistics


def test_fixture_file_pipeline(tmp_path: Path):
    fixture = Path(__file__).parent / "fixtures" / "mixed_malformed.log"
    result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_file(fixture)

    assert result.log_count >= 4
    assert result.parse_stats["malformed_lines"] >= 2
    assert result.parse_stats["unsupported_lines"] >= 1
    assert result.statistics["total_logs"] == result.log_count
    assert any(a.alert_type == "SQL_INJECTION" for a in result.alerts)
    assert len(result.incidents) >= 1
    assert all(0 <= i.risk_score <= 100 for i in result.incidents)


def test_empty_result_reports_valid(tmp_path: Path):
    from analyzer.reporting import generate_reports

    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    result = AnalysisService().analyze_file(empty)
    written = generate_reports(result, tmp_path / "out", kinds=["all"])
    assert result.log_count == 0
    assert result.alerts == []
    assert result.incidents == []
    assert written["json"].exists()
    assert written["html"].exists()
    assert written["summary"].exists()


def test_unknown_fixture_file():
    fixture = Path(__file__).parent / "fixtures" / "unknown_only.log"
    result = AnalysisService().analyze_file(fixture)
    assert result.log_count == 0
    assert result.parse_stats["unsupported_lines"] >= 3
    assert result.alerts == []
