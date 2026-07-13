from collections import defaultdict
from datetime import timedelta
from analyzer.models import SecurityAlert


def detect_brute_force(logs):

    failed_attempts = defaultdict(list)
    alerts = []

    for log in logs:

        if log.event_type != "LOGIN_FAILED":
            continue

        key = (log.username, log.ip_address)

        failed_attempts[key].append(log.timestamp)

    for (username, ip), timestamps in failed_attempts.items():

        timestamps.sort()

        for i in range(len(timestamps) - 4):

            start = timestamps[i]
            end = timestamps[i + 4]

            if end - start <= timedelta(minutes=2):

                alerts.append(
                    SecurityAlert(
                        alert_type="BRUTE_FORCE",
                        severity="HIGH",
                        timestamp=start,
                        username=username,
                        ip_address=ip,
                        description="5 failed login attempts within 2 minutes.",
                    )
                )

                break

    return alerts