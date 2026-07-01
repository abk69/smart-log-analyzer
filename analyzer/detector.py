from collections import defaultdict
from datetime import timedelta

from analyzer.models import LogEntry


def detect_bruteforce(
    logs: list[LogEntry],
    threshold: int = 5,
    window_minutes: int = 2,
):

    failed_logs = defaultdict(list)

    for log in logs:

        if log.status == "FAILED":

            key = (log.username, log.ip_address)

            failed_logs[key].append(log.timestamp)

    alerts = []

    for (user, ip), timestamps in failed_logs.items():

        timestamps.sort()

        for i in range(len(timestamps)):

            count = 1

            for j in range(i + 1, len(timestamps)):

                if timestamps[j] - timestamps[i] <= timedelta(
                    minutes=window_minutes
                ):
                    count += 1
                else:
                    break

            if count >= threshold:

                alerts.append(
                    {
                        "username": user,
                        "ip_address": ip,
                        "attempts": count,
                        "window": f"{window_minutes} minutes",
                    }
                )

                break

    return alerts