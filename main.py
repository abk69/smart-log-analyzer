import argparse
import sys

from analyzer.exceptions import LogAnalyzerError
from analyzer.parser import read_log_file
from analyzer.parsers.parser_dispatcher import parse_logs_with_stats
from analyzer.detectors.sql_injection import detect_sql_injection
from analyzer.detectors.brute_force import detect_brute_force
from analyzer.detectors.password_spray import detect_password_spray
from analyzer.detectors.xss import detect_xss
from analyzer.detectors.impossible_travel import detect_impossible_travel
from analyzer.detectors.insider_threat import detect_insider_threat
from analyzer.correlation import correlate_alerts
from analyzer.risk import score_incidents
from analyzer.statistics import generate_statistics
from analyzer.utils import setup_logging


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


def _print_incidents(incidents) -> None:
    print("\n" + "=" * 60)
    print("SECURITY INCIDENTS")
    print("=" * 60)

    if not incidents:
        print("\nNo Security Incidents Found.\n")
        return

    for i, incident in enumerate(incidents, start=1):
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smart Log Analyzer"
    )

    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    args = parser.parse_args()
    setup_logging(level="INFO")

    print("=" * 60)
    print("SMART LOG ANALYZER")
    print("=" * 60)

    try:
        log_lines = read_log_file(args.logfile)
    except LogAnalyzerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Parse Logs
    parsed_logs, parse_stats = parse_logs_with_stats(log_lines)

    print(f"\nTotal Parsed Logs : {parse_stats.parsed_lines}")
    if parse_stats.malformed_lines:
        print(f"Malformed Lines   : {parse_stats.malformed_lines}")
    if parse_stats.unsupported_lines:
        print(f"Unsupported Lines : {parse_stats.unsupported_lines}")

    # -----------------------------
    # Detection Engine
    # -----------------------------
    alerts = []

    alerts.extend(detect_brute_force(parsed_logs))
    alerts.extend(detect_password_spray(parsed_logs))
    alerts.extend(detect_sql_injection(parsed_logs))
    alerts.extend(detect_xss(parsed_logs))
    alerts.extend(detect_impossible_travel(parsed_logs))
    alerts.extend(detect_insider_threat(parsed_logs))

    stats = generate_statistics(parsed_logs)

    print("\n" + "=" * 60)
    print("LOG SUMMARY")
    print("=" * 60)

    print(f"Total Logs         : {stats['total_logs']}")
    print(f"Linux Logs         : {stats['linux_logs']}")
    print(f"Windows Logs       : {stats['windows_logs']}")
    print(f"Apache Logs        : {stats['apache_logs']}")

    print()

    print(f"Successful Logins  : {stats['successful_logins']}")
    print(f"Failed Logins      : {stats['failed_logins']}")
    print(f"HTTP Requests      : {stats['http_requests']}")

    print()

    print(f"Unique Users       : {stats['unique_users']}")
    print(f"Unique IPs         : {stats['unique_ips']}")

    print()

    print(
        f"Most Active User   : "
        f"{stats['top_user'][0]} "
        f"({stats['top_user'][1]})"
    )

    print(
        f"Most Active IP     : "
        f"{stats['top_ip'][0]} "
        f"({stats['top_ip'][1]})"
    )

    # -----------------------------
    # Display Alerts
    # -----------------------------
    print("\n" + "=" * 60)
    print("SECURITY ALERTS")
    print("=" * 60)

    if not alerts:
        print("\nNo Security Alerts Found.\n")
        _print_incidents([])
        print("\n" + "=" * 60)
        print("Analysis Complete")
        print("=" * 60)
        return 0

    for i, alert in enumerate(alerts, start=1):

        print(f"\nAlert #{i}")
        print("-" * 40)

        print(f"Type        : {alert.alert_type}")
        print(f"Severity    : {alert.severity}")
        print(f"Time        : {alert.timestamp}")
        print(f"User        : {alert.username}")
        print(f"IP Address  : {alert.ip_address}")
        print(f"Description : {alert.description}")

    # -----------------------------
    # Correlation + Global Risk
    # -----------------------------
    incidents = score_incidents(correlate_alerts(alerts))
    _print_incidents(incidents)

    print("\n" + "=" * 60)
    print("Analysis Complete")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
