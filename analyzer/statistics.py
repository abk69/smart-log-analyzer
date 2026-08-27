from collections import Counter


def generate_statistics(logs):

    stats = {}

    stats["total_logs"] = len(logs)

    stats["linux_logs"] = sum(
        1 for log in logs if log.source == "linux"
    )

    stats["windows_logs"] = sum(
        1 for log in logs if log.source == "windows"
    )

    stats["apache_logs"] = sum(
        1 for log in logs if log.source == "apache"
    )

    stats["successful_logins"] = sum(
        1 for log in logs if log.event_type == "LOGIN_SUCCESS"
    )

    stats["failed_logins"] = sum(
        1 for log in logs if log.event_type == "LOGIN_FAILED"
    )

    stats["http_requests"] = sum(
        1 for log in logs if log.event_type == "HTTP_REQUEST"
    )

    users = [
        log.username
        for log in logs
        if log.username != "-"
    ]

    ips = [
        log.ip_address
        for log in logs
    ]

    stats["unique_users"] = len(set(users))
    stats["unique_ips"] = len(set(ips))

    user_counter = Counter(users)
    ip_counter = Counter(ips)

    stats["top_user"] = (
        user_counter.most_common(1)[0]
        if user_counter
        else ("-", 0)
    )

    stats["top_ip"] = (
        ip_counter.most_common(1)[0]
        if ip_counter
        else ("-", 0)
    )

    return stats
