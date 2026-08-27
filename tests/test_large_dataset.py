"""Large synthetic dataset stress test (normal suite, ~10k events)."""

from datetime import datetime, timedelta

from analyzer.config import AnalyzerConfig
from analyzer.models import LogEntry
from analyzer.services.analysis_service import AnalysisService
from analyzer.statistics import generate_statistics


def _build_entries(n: int = 10_000) -> list[LogEntry]:
    start = datetime(2026, 6, 26, 9, 0, 0)
    entries: list[LogEntry] = []
    for i in range(n):
        source = ("linux", "windows", "apache")[i % 3]
        if source == "apache":
            entries.append(
                LogEntry(
                    timestamp=start + timedelta(seconds=i),
                    username="-",
                    ip_address=f"10.0.{(i // 256) % 256}.{i % 256}",
                    status="SUCCESS",
                    source="apache",
                    event_type="HTTP_REQUEST",
                    request=f"/item/{i}",
                    path=f"/item/{i}",
                    method="GET",
                    status_code=200,
                )
            )
        else:
            failed = i % 7 == 0
            entries.append(
                LogEntry(
                    timestamp=start + timedelta(seconds=i),
                    username=f"user{i % 50}",
                    ip_address=f"203.0.113.{i % 50}",
                    status="FAILED" if failed else "SUCCESS",
                    source=source,
                    event_type="LOGIN_FAILED" if failed else "LOGIN_SUCCESS",
                )
            )
    return entries


def test_ten_thousand_events_complete_without_crash():
    entries = _build_entries(10_000)
    assert len(entries) == 10_000

    stats = generate_statistics(entries)
    assert stats["total_logs"] == 10_000
    assert stats["linux_logs"] + stats["windows_logs"] + stats["apache_logs"] == 10_000
    assert stats["unique_users"] > 0
    assert stats["unique_ips"] > 0

    # Drive detectors via AnalysisService with pre-parsed path: analyze_lines
    # on synthetic syslog-like lines would be slower; use analyze_lines with
    # a compact representative mix for service path coverage.
    lines = []
    start = datetime(2026, 6, 26, 9, 0, 0)
    for i in range(200):
        ts = start + timedelta(seconds=i)
        month = ts.strftime("%b")
        day = f"{ts.day:2d}"
        hms = ts.strftime("%H:%M:%S")
        lines.append(
            f"{month} {day} {hms} server sshd[{1000 + i}]: "
            f"Failed password for admin from 203.0.113.10 port {50000 + i} ssh2"
        )
    for i in range(100):
        lines.append(
            f'172.16.1.{i % 50} - - [26/Jun/2026:09:10:{i % 60:02d} +0000] '
            f'"GET /item/{i} HTTP/1.1" 200 100'
        )

    result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_lines(lines, input_file="large_synth.log")

    assert result.log_count == len(lines)
    assert result.statistics["total_logs"] == result.log_count
    assert result.duration_seconds >= 0
    assert isinstance(result.alerts, list)
    assert isinstance(result.incidents, list)


def test_ten_thousand_logentry_statistics_only():
    """Pure statistics path on 10k LogEntry objects (no parse overhead)."""
    stats = generate_statistics(_build_entries(10_000))
    assert stats["total_logs"] == 10_000
    assert stats["http_requests"] > 0
    assert stats["failed_logins"] > 0
    assert stats["successful_logins"] > 0
