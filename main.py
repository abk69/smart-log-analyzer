from analyzer.parser import read_log_file


def main():
    print("=" * 50)
    print("        SMART LOG ANALYZER")
    print("=" * 50)

    try:
        logs = read_log_file("logs/auth.log")

        print("✅ Log file loaded successfully.\n")
        print(f"Total Log Entries: {len(logs)}\n")

        print("Sample Logs:\n")

        for log in logs:
            print(log)

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()