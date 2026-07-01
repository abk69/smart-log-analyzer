from analyzer.parser import read_log_file, parse_logs
from analyzer.statistics import generate_statistics
from analyzer.detector import detect_bruteforce


def main():

    print("=" * 50)
    print("SMART LOG ANALYZER")
    print("=" * 50)

    log_lines = read_log_file("logs/auth.log")

    parsed_logs = parse_logs(log_lines)

    stats = generate_statistics(parsed_logs)
    

    print("\n📊 LOG STATISTICS\n")

    print(f"Total Logs         : {stats['total_logs']}")
    print(f"Successful Logins  : {stats['successful_logins']}")
    print(f"Failed Logins      : {stats['failed_logins']}")
    print(f"Unique Users       : {stats['unique_users']}")
    print(f"Unique IPs         : {stats['unique_ips']}")

    print(
        f"Most Active User   : {stats['top_user'][0]} ({stats['top_user'][1]} logins)"
    )

    print(
        f"Most Active IP     : {stats['top_ip'][0]} ({stats['top_ip'][1]} requests)"
    )
    
    alerts = detect_bruteforce(parsed_logs)

    print("\n🔒 SECURITY REPORT\n")

    if alerts:

        for alert in alerts:

            print("=" * 40)
            print("🚨 BRUTE FORCE DETECTED")
            print("=" * 40)

            print(f"User      : {alert['username']}")
            print(f"IP        : {alert['ip_address']}")
            print(f"Attempts  : {alert['attempts']}")
            print(f"Window    : {alert['window']}")
            print()

    else:

        print("✅ No suspicious activity detected.")

if __name__ == "__main__":
    main()