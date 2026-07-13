from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEntry:
    timestamp: datetime
    username: str
    ip_address: str
    status: str
    source: str

    def __str__(self):
        return (
            f"[{self.source.upper()}] "
            f"{self.timestamp} | "
            f"{self.username} | "
            f"{self.ip_address} | "
            f"{self.status}"
        )