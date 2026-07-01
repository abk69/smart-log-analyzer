from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: str
    username: str
    ip_address: str
    status: str