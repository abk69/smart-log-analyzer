import argparse

from analyzer.parser import read_log_file
from analyzer.parsers.parser_dispatcher import parse_logs


def main():

    parser = argparse.ArgumentParser(
        description="Smart Log Analyzer"
    )

    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    args = parser.parse_args()

    print("=" * 55)
    print("              SMART LOG ANALYZER")
    print("=" * 55)

    log_lines = read_log_file(args.logfile)

    parsed_logs = parse_logs(log_lines)

    print(f"\nTotal Parsed Logs : {len(parsed_logs)}\n")

    print("-" * 55)

    for log in parsed_logs:
        print(log)

    print("-" * 55)
    print("\nAnalysis Complete.\n")


if __name__ == "__main__":
    main()