from collections import defaultdict
from datetime import timedelta
from analyzer.models import SecurityAlert


def detect_password_spray(logs):

    attempts = defaultdict(list)
    alerts = []

    for log in logs:

        if log.event_type != "LOGIN_FAILED":
            continue

        attempts[log.ip_address].append(log)

    for ip, entries in attempts.items():

        entries.sort(key=lambda x: x.timestamp)

        for i in range(len(entries)):

            users = set()
            start = entries[i].timestamp

            for j in range(i, len(entries)):

                if entries[j].timestamp - start > timedelta(minutes=2):
                    break

                users.add(entries[j].username)

                if len(users) >= 5:

                    alerts.append(
                        SecurityAlert(
                            alert_type="PASSWORD_SPRAY",
                            severity="HIGH",
                            timestamp=start,
                            username=", ".join(sorted(users)),
                            ip_address=ip,
                            description=f"Password spray against {len(users)} users.",
                        )
                    )

                    break

    return alerts