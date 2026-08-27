"""Optional local performance benchmark for Smart Log Analyzer.

Not part of the default pytest suite. Run manually:

    python tools/benchmark.py

Results are approximate and machine-dependent. Do not treat timings as
absolute product claims.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer.config import AnalyzerConfig
from analyzer.correlation import correlate_alerts
from analyzer.detectors.brute_force import detect_brute_force
from analyzer.detectors.password_spray import detect_password_spray
from analyzer.detectors.sql_injection import detect_sql_injection
from analyzer.detectors.xss import detect_xss
from analyzer.parsers.parser_dispatcher import parse_logs
from analyzer.reporting import generate_reports
from analyzer.risk import score_incidents
from analyzer.services.analysis_service import AnalysisService


def _synthetic_lines(n: int = 5000) -> list[str]:
    start = datetime(2026, 6, 26, 9, 0, 0)
    lines: list[str] = []
    for i in range(n):
        ts = start + timedelta(seconds=i)
        month = ts.strftime("%b")
        day = f"{ts.day:2d}"
        hms = ts.strftime("%H:%M:%S")
        kind = i % 5
        if kind == 0:
            lines.append(
                f"{month} {day} {hms} server sshd[{1000 + i}]: "
                f"Failed password for user{i % 20} from 203.0.113.{i % 40} "
                f"port {50000 + (i % 1000)} ssh2"
            )
        elif kind == 1:
            lines.append(
                f'2026-06-26T{hms} EVENT_ID=4624 USER=user{i % 20} '
                f'IP=10.0.0.{i % 50} MESSAGE="ok"'
            )
        elif kind == 2:
            lines.append(
                f'172.16.1.{i % 50} - - [26/Jun/2026:{hms} +0000] '
                f'"GET /item/{i} HTTP/1.1" 200 100'
            )
        elif kind == 3:
            lines.append(
                f'172.16.1.{i % 50} - - [26/Jun/2026:{hms} +0000] '
                f'"GET /login?id=1 UNION SELECT 1 HTTP/1.1" 500 10'
            )
        else:
            lines.append(
                f'172.16.1.{i % 50} - - [26/Jun/2026:{hms} +0000] '
                f'"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 10'
            )
    return lines


def _timeit(label: str, fn) -> tuple[float, object]:
    started = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - started
    print(f"{label:<28} {elapsed * 1000:8.1f} ms")
    return elapsed, result


def main() -> None:
    lines = _synthetic_lines(5000)
    cfg = AnalyzerConfig(default_log_year=2026)

    print("Smart Log Analyzer — local benchmark (approx.)")
    print(f"Events: {len(lines)}")
    print("-" * 40)

    parse_time, entries = _timeit("parsing", lambda: parse_logs(lines, config=cfg))

    def _detect():
        alerts = []
        alerts.extend(detect_brute_force(entries, config=cfg))
        alerts.extend(detect_password_spray(entries, config=cfg))
        alerts.extend(detect_sql_injection(entries, config=cfg))
        alerts.extend(detect_xss(entries, config=cfg))
        return alerts

    detect_time, alerts = _timeit("detection", _detect)
    corr_time, incidents = _timeit("correlation", lambda: correlate_alerts(alerts, config=cfg))
    _timeit("risk scoring", lambda: score_incidents(incidents, config=cfg))

    service = AnalysisService(config=cfg)
    total_time, result = _timeit(
        "total analysis (service)",
        lambda: service.analyze_lines(lines, input_file="benchmark.log"),
    )

    out_dir = Path("reports") / "_benchmark"
    report_time, _ = _timeit(
        "report generation",
        lambda: generate_reports(result, out_dir, kinds=["all"]),
    )

    print("-" * 40)
    print(f"Parsed entries: {len(entries)}")
    print(f"Alerts: {len(result.alerts)}  Incidents: {len(result.incidents)}")
    print(
        "Note: timings are local and approximate; "
        f"parse={parse_time:.3f}s detect={detect_time:.3f}s "
        f"corr={corr_time:.3f}s reports={report_time:.3f}s "
        f"total={total_time:.3f}s"
    )


if __name__ == "__main__":
    main()
