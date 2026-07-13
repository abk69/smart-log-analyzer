from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEntry:
    timestamp: datetime
    username: str
    ip_address: str
    status: str
    source: str
    event_type: str

    def __str__(self):
        return (
            f"[{self.source.upper()}] "
            f"{self.timestamp} | "
            f"{self.username} | "
            f"{self.ip_address} | "
            f"{self.status} | "
            f"{self.event_type}"
        )


@dataclass
class SecurityAlert:
    alert_type: str
    severity: str
    timestamp: datetime
    username: str
    ip_address: str
    description: str

    def __str__(self):
        return (
            f"[{self.severity}] "
            f"{self.alert_type} | "
            f"{self.username} | "
            f"{self.ip_address}"
        )