from analyzer.models import SecurityAlert
from urllib.parse import unquote


SQL_PATTERNS = [
    "union select",
    "information_schema",
    "drop table",
    "sleep(",
    "or 1=1",
    "' or '",
    "--",
]


def detect_sql_injection(logs):

    alerts = []

    for log in logs:

        if log.event_type != "HTTP_REQUEST":
            continue

        request = unquote(log.request).lower()

        for pattern in SQL_PATTERNS:

            if pattern in request:

                alerts.append(

                    SecurityAlert(

                        alert_type="SQL_INJECTION",

                        severity="CRITICAL",

                        timestamp=log.timestamp,

                        username="-",

                        ip_address=log.ip_address,

                        description=f"SQL Injection pattern detected: {pattern}",

                    )

                )

                break

    return alerts