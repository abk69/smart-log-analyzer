import argparse
import sys

from analyzer.exceptions import LogAnalyzerError
from analyzer.parser import read_log_file
from analyzer.parsers.parser_dispatcher import parse_logs
from analyzer.detectors.sql_injection import detect_sql_injection
from analyzer.detectors.brute_force import detect_brute_force
from analyzer.detectors.password_spray import detect_password_spray
from analyzer.detectors.xss import detect_xss
from analyzer.statistics import generate_statistics
from analyzer.utils import setup_logging


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
    parsed_logs = parse_logs(log_lines)

    print(f"\nTotal Parsed Logs : {len(parsed_logs)}")

    # -----------------------------
    # Detection Engine
    # -----------------------------
    alerts = []

    alerts.extend(detect_brute_force(parsed_logs))
    alerts.extend(detect_password_spray(parsed_logs))
    alerts.extend(detect_sql_injection(parsed_logs))
    alerts.extend(detect_xss(parsed_logs))

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

    print("\n" + "=" * 60)
    print("Analysis Complete")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
