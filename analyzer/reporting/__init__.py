"""Reporting package: transform AnalysisResult into exportable artifacts."""

from __future__ import annotations

from pathlib import Path

from analyzer.models import AnalysisResult
from analyzer.reporting.csv_report import write_csv_reports
from analyzer.reporting.html_report import write_html_report
from analyzer.reporting.json_report import write_json_report
from analyzer.reporting.summary_report import write_summary_report

REPORT_KINDS = ("json", "csv", "html", "summary")


def generate_reports(
    result: AnalysisResult,
    output_dir: str | Path = "reports",
    *,
    kinds: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Path]:
    """Generate requested report artifacts from one ``AnalysisResult``.

    Args:
        result: Completed analysis payload.
        output_dir: Destination directory (created if missing).
        kinds: Subset of ``json``, ``csv``, ``html``, ``summary``.
            ``None`` or including ``all`` generates every report.

    Returns:
        Mapping of report label → written path.
    """
    destination = Path(output_dir)
    requested = set(kinds or ("all",))
    if "all" in requested:
        requested = set(REPORT_KINDS)

    written: dict[str, Path] = {}
    if "json" in requested:
        written["json"] = write_json_report(result, destination)
    if "csv" in requested:
        written.update(write_csv_reports(result, destination))
    if "html" in requested:
        written["html"] = write_html_report(result, destination)
    if "summary" in requested:
        written["summary"] = write_summary_report(result, destination)
    return written


__all__ = [
    "REPORT_KINDS",
    "generate_reports",
    "write_csv_reports",
    "write_html_report",
    "write_json_report",
    "write_summary_report",
]
