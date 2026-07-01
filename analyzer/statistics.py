from collections import Counter
from analyzer.models import LogEntry


def generate_statistics(logs: list[LogEntry]) -> dict:

    total_logs = len(logs)

    successful_logins = sum(
        1 for log in logs if log.status == "SUCCESS"
    )

    failed_logins = sum(
        1 for log in logs if log.status == "FAILED"
    )

    unique_users = len({log.username for log in logs})

    unique_ips = len({log.ip_address for log in logs})

    user_counter = Counter(log.username for log in logs)

    ip_counter = Counter(log.ip_address for log in logs)

    return {
        "total_logs": total_logs,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unique_users": unique_users,
        "unique_ips": unique_ips,
        "top_user": user_counter.most_common(1)[0],
        "top_ip": ip_counter.most_common(1)[0],
    }