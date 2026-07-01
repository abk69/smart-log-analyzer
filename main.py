from analyzer.parser import read_log_file, parse_logs


def main():

    print("=" * 50)
    print("SMART LOG ANALYZER")
    print("=" * 50)

    logs = read_log_file("logs/auth.log")

    parsed_logs = parse_logs(logs)

    print(f"\nParsed {len(parsed_logs)} log entries\n")

    for log in parsed_logs:
        print(log)


if __name__ == "__main__":
    main()