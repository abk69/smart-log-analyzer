from collections import defaultdict
from analyzer.models import LogEntry


def detect_bruteforce(logs: list[LogEntry], threshold: int = 5):

    failed_attempts = defaultdict(int)

    alerts = []

    for log in logs:

        if log.status == "FAILED":

            key = (log.username, log.ip_address)

            failed_attempts[key] += 1

    for (user, ip), count in failed_attempts.items():

        if count >= threshold:

            alerts.append(
                {
                    "username": user,
                    "ip_address": ip,
                    "attempts": count,
                }
            )

    return alerts