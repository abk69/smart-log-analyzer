import argparse

from analyzer.parser import read_log_file
from analyzer.parsers.parser_dispatcher import parse_logs

from analyzer.detectors.brute_force import detect_brute_force
from analyzer.detectors.password_spray import detect_password_spray


def main():

    parser = argparse.ArgumentParser(
        description="Smart Log Analyzer"
    )

    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SMART LOG ANALYZER")
    print("=" * 60)

    # Read Logs
    log_lines = read_log_file(args.logfile)

    # Parse Logs
    parsed_logs = parse_logs(log_lines)

    print(f"\nTotal Parsed Logs : {len(parsed_logs)}")

    # -----------------------------
    # Detection Engine
    # -----------------------------
    alerts = []

    alerts.extend(detect_brute_force(parsed_logs))
    alerts.extend(detect_password_spray(parsed_logs))

    # -----------------------------
    # Display Alerts
    # -----------------------------
    print("\n" + "=" * 60)
    print("SECURITY ALERTS")
    print("=" * 60)

    if not alerts:
        print("\nNo Security Alerts Found.\n")
        return

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


if __name__ == "__main__":
    main()