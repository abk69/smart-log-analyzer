from urllib.parse import unquote

from analyzer.models import SecurityAlert


XSS_PATTERNS = [

    "<script",

    "javascript:",

    "onerror=",

    "onload=",

    "<svg",

    "<img",

    "alert(",

]


def detect_xss(logs):

    alerts = []

    for log in logs:

        if log.event_type != "HTTP_REQUEST":
            continue

        request = unquote(log.request).lower()

        for pattern in XSS_PATTERNS:

            if pattern in request:

                alerts.append(

                    SecurityAlert(

                        alert_type="XSS",

                        severity="HIGH",

                        timestamp=log.timestamp,

                        username="-",

                        ip_address=log.ip_address,

                        description=f"XSS pattern detected: {pattern}",

                    )

                )

                break

    return alerts