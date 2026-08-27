"""Human-readable text summary report."""

from __future__ import annotations

from pathlib import Path

from analyzer.exceptions import ReportGenerationError
from analyzer.models import AnalysisResult
from analyzer.reporting.serialize import (
    APP_NAME,
    attack_type_counts,
    build_report_document,
    to_iso,
)


def write_summary_report(result: AnalysisResult, output_dir: Path) -> Path:
    """Write ``summary.txt`` and return the path."""
    output_dir = Path(output_dir)
    path = output_dir / "summary.txt"
    doc = build_report_document(result)
    summary = doc["summary"]
    alert_sev = summary["alert_severity"]
    threats = list(attack_type_counts(result.alerts).keys())[:5]
    highest = None
    if result.incidents:
        highest = max(result.incidents, key=lambda i: i.risk_score)

    lines = [
        "=" * 60,
        APP_NAME,
        "SECURITY SUMMARY",
        "=" * 60,
        "",
        f"Input File       : {result.input_file}",
        f"Analysis Time    : {to_iso(result.analyzed_at)}",
        f"Duration         : {result.duration_seconds:.2f} seconds",
        "",
        f"TOTAL EVENTS     : {summary['total_events']}",
        f"TOTAL ALERTS     : {summary['total_alerts']}",
        f"TOTAL INCIDENTS  : {summary['total_incidents']}",
        "",
        "SEVERITY",
        f"Critical         : {alert_sev['CRITICAL']}",
        f"High             : {alert_sev['HIGH']}",
        f"Medium           : {alert_sev['MEDIUM']}",
        f"Low              : {alert_sev['LOW']}",
        "",
        "TOP THREATS",
    ]
    if threats:
        lines.extend(threats)
    else:
        lines.append("(none)")

    lines.append("")
    lines.append("HIGHEST RISK INCIDENT")
    if highest is None:
        lines.append("Incident ID      : N/A")
        lines.append("Risk Score       : 0")
        lines.append("Severity         : N/A")
    else:
        lines.append(f"Incident ID      : {highest.incident_id}")
        lines.append(f"Risk Score       : {highest.risk_score}")
        lines.append(f"Severity         : {highest.severity}")

    lines.extend(["", "=" * 60, ""])

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
    except OSError as exc:
        raise ReportGenerationError(f"Unable to write summary report: {exc}") from exc
