"""Smart Log Analyzer CLI entry point.

Orchestration lives in ``AnalysisService``. This module handles argparse,
presentation, reporting invocation, and exit codes only.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

from analyzer import __version__
from analyzer.anomaly import SKLEARN_AVAILABLE
from analyzer.config import AnalyzerConfig
from analyzer.exceptions import (
    ConfigurationError,
    LogAnalyzerError,
    LogFileError,
    ReportGenerationError,
)
from analyzer.models import AnalysisResult, Incident, SecurityAlert
from analyzer.reporting import generate_reports
from analyzer.services.analysis_service import AnalysisService
from analyzer.utils import setup_logging


EXIT_OK = 0
EXIT_APP_ERROR = 1
EXIT_USAGE = 2


class _Style:
    """Minimal optional ANSI styling."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def bold(self, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[1m{text}\033[0m"


def _count_by_severity(items: list[SecurityAlert] | list[Incident]) -> dict[str, int]:
    counts = Counter((item.severity or "").upper() for item in items)
    return {
        "CRITICAL": counts.get("CRITICAL", 0),
        "HIGH": counts.get("HIGH", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "LOW": counts.get("LOW", 0),
    }


def _print_attack_chain(chain: list[str]) -> None:
    if not chain:
        print("Attack Chain  : (none)")
        return
    print("Attack Chain  :")
    for index, alert_type in enumerate(chain):
        print(f"    {alert_type}")
        if index < len(chain) - 1:
            print("         |")
            print("         v")


def _print_banner(style: _Style) -> None:
    print("=" * 60)
    print(style.bold("SMART LOG ANALYZER"))
    print("=" * 60)


def _print_summary(result: AnalysisResult, *, quiet: bool, style: _Style) -> None:
    stats = result.statistics
    parse_stats = result.parse_stats
    alert_sev = _count_by_severity(result.alerts)
    incident_sev = _count_by_severity(result.incidents)

    print()
    print(f"Input       : {result.input_file}")
    print(f"Analysis    : {result.duration_seconds:.2f} seconds")

    print()
    print(style.bold("PARSING"))
    print("-" * 60)
    print(f"Total Lines       : {parse_stats.get('total_lines', 0)}")
    print(f"Parsed            : {parse_stats.get('parsed_lines', 0)}")
    print(f"Malformed         : {parse_stats.get('malformed_lines', 0)}")
    print(f"Unsupported       : {parse_stats.get('unsupported_lines', 0)}")

    print()
    print(style.bold("LOG SUMMARY"))
    print("-" * 60)
    print(f"Total Events      : {stats.get('total_logs', 0)}")
    print(f"Linux             : {stats.get('linux_logs', 0)}")
    print(f"Windows           : {stats.get('windows_logs', 0)}")
    print(f"Apache            : {stats.get('apache_logs', 0)}")
    print()
    print(f"Successful Logins : {stats.get('successful_logins', 0)}")
    print(f"Failed Logins     : {stats.get('failed_logins', 0)}")
    print(f"HTTP Requests     : {stats.get('http_requests', 0)}")
    print()
    print(f"Unique Users      : {stats.get('unique_users', 0)}")
    print(f"Unique IPs        : {stats.get('unique_ips', 0)}")

    print()
    print(style.bold("SECURITY ALERTS"))
    print("-" * 60)
    print(f"Total Alerts      : {len(result.alerts)}")
    print()
    print(f"Critical          : {alert_sev['CRITICAL']}")
    print(f"High              : {alert_sev['HIGH']}")
    print(f"Medium            : {alert_sev['MEDIUM']}")
    print(f"Low               : {alert_sev['LOW']}")

    print()
    print(style.bold("INCIDENTS"))
    print("-" * 60)
    print(f"Total Incidents   : {len(result.incidents)}")
    print()
    print(f"Critical          : {incident_sev['CRITICAL']}")
    print(f"High              : {incident_sev['HIGH']}")
    print(f"Medium            : {incident_sev['MEDIUM']}")
    print(f"Low               : {incident_sev['LOW']}")

    if quiet:
        return

    print()
    print(style.bold("ALERT DETAILS"))
    print("-" * 60)
    if not result.alerts:
        print("No security alerts found.")
    else:
        for i, alert in enumerate(result.alerts, start=1):
            print(f"\nAlert #{i}")
            print("-" * 40)
            print(f"Type        : {alert.alert_type}")
            print(f"Severity    : {alert.severity}")
            print(f"Time        : {alert.timestamp}")
            print(f"User        : {alert.username}")
            print(f"IP Address  : {alert.ip_address}")
            print(f"Description : {alert.description}")

    print()
    print(style.bold("INCIDENT DETAILS"))
    print("-" * 60)
    if not result.incidents:
        print("No security incidents found.")
        return

    for i, incident in enumerate(result.incidents, start=1):
        chain = incident.metadata.get("attack_chain") or incident.evidence.get(
            "observed_alert_chain", []
        )
        print(f"\nIncident #{i}")
        print("-" * 60)
        print(f"Type          : {incident.incident_type}")
        print(f"Severity      : {incident.severity}")
        print(f"Risk Score    : {incident.risk_score}")
        print()
        print(
            "Source IPs    : "
            + (", ".join(incident.source_ips) if incident.source_ips else "-")
        )
        print(
            "Users         : "
            + (", ".join(incident.usernames) if incident.usernames else "-")
        )
        print()
        _print_attack_chain(list(chain))
        print()
        print(f"Related Alerts : {len(incident.alerts)}")
        print(f"First Seen     : {incident.first_seen}")
        print(f"Last Seen      : {incident.last_seen}")
        print()
        print("Description:")
        print(f"  {incident.description}")


def _print_report_paths(paths: dict[str, Path], style: _Style) -> None:
    if not paths:
        return
    labels = {
        "json": "JSON",
        "alerts_csv": "CSV",
        "incidents_csv": "CSV",
        "html": "HTML",
        "summary": "SUMMARY",
    }
    print()
    print(style.bold("REPORTS"))
    print("-" * 60)
    for key, path in paths.items():
        label = labels.get(key, key.upper())
        print(f"{label:<10}: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Smart Log Analyzer - parse heterogeneous security logs, detect "
            "known attacks, optionally flag behavioral anomalies, correlate "
            "alerts, score risk, and write local reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py logs/security.log\n"
            "  python main.py logs/security.log --verbose\n"
            "  python main.py logs/security.log --no-anomaly\n"
            "  python main.py logs/security.log --report all\n"
            "  python main.py logs/security.log --report all --output reports/\n"
            "\n"
            "Log lines are treated as data only (never executed). Analysis is\n"
            "local/offline - no external APIs or automated blocking."
        ),
    )
    parser.add_argument("logfile", help="Path to the security log file to analyze")
    parser.add_argument(
        "--version",
        action="version",
        version=f"Smart Log Analyzer {__version__}",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed application diagnostics",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Show summary only (hide alert/incident details)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in console output",
    )
    parser.add_argument(
        "--report",
        choices=["json", "csv", "html", "summary", "all"],
        action="append",
        default=None,
        metavar="KIND",
        help=(
            "Generate report artifact(s): json, csv, html, summary, or all. "
            "Repeatable. Writes under --output."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "csv", "html", "summary", "all"],
        default="console",
        help=(
            "Console display mode (default: console). Non-console values are "
            "aliases for --report"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports"),
        metavar="DIR",
        help="Output directory for generated reports (default: reports/)",
    )
    parser.add_argument(
        "--no-anomaly",
        action="store_true",
        help=(
            "Disable Isolation Forest anomaly detection "
            "(deterministic detectors still run)"
        ),
    )
    return parser


def _resolve_report_kinds(args: argparse.Namespace) -> list[str]:
    kinds: list[str] = []
    if args.report:
        kinds.extend(args.report)
    if args.format and args.format != "console":
        kinds.append(args.format)
    # Preserve order while deduplicating.
    seen: set[str] = set()
    ordered: list[str] = []
    for kind in kinds:
        if kind not in seen:
            seen.add(kind)
            ordered.append(kind)
    return ordered


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        return EXIT_USAGE if code else EXIT_OK

    if args.verbose and args.quiet:
        print("Error: --verbose and --quiet cannot be used together.", file=sys.stderr)
        return EXIT_USAGE

    if args.verbose:
        setup_logging(level="DEBUG", verbose=True)
    elif args.quiet:
        setup_logging(level="ERROR")
    else:
        setup_logging(level="WARNING")

    use_color = (not args.no_color) and sys.stdout.isatty()
    style = _Style(enabled=use_color)

    config = AnalyzerConfig()
    if args.no_anomaly:
        config = replace(config, anomaly=replace(config.anomaly, enabled=False))

    if config.anomaly.enabled and not SKLEARN_AVAILABLE:
        print(
            "Note: anomaly detection unavailable (scikit-learn not installed). "
            "Continuing with deterministic detectors only.",
            file=sys.stderr,
        )

    service = AnalysisService(config=config)
    try:
        result = service.analyze_file(args.logfile)
    except LogFileError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_APP_ERROR
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_APP_ERROR
    except LogAnalyzerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_APP_ERROR

    _print_banner(style)
    _print_summary(result, quiet=args.quiet, style=style)

    report_kinds = _resolve_report_kinds(args)
    if report_kinds:
        try:
            written = generate_reports(
                result,
                args.output,
                kinds=report_kinds,
            )
        except ReportGenerationError as exc:
            print(f"Report error: {exc}", file=sys.stderr)
            return EXIT_APP_ERROR
        _print_report_paths(written, style)

    print()
    print("=" * 60)
    print("Analysis Complete")
    print("=" * 60)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
