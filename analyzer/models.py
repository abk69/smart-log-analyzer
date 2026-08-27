"""Core data models for normalized log events and security alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass
class LogEntry:
    """Normalized representation of a single parsed log event.

    Parsers populate the fields they can extract. Optional web-oriented
    fields default to empty/None so existing auth parsers remain unchanged.
    """

    timestamp: datetime
    username: str
    ip_address: str
    status: str
    source: str
    event_type: str
    request: str = ""
    method: str = ""
    path: str = ""
    status_code: int | None = None
    raw_message: str = ""

    def __str__(self) -> str:
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
    """Structured security finding produced by a detector.

    Required constructor arguments match the existing detector call sites.
    Additional fields are optional and auto-populated where useful.
    ``alert_id`` is assigned once at construction and remains stable.
    """

    alert_type: str
    severity: str
    timestamp: datetime
    username: str
    ip_address: str
    description: str
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    source: str = ""
    evidence: Any = field(default_factory=list)
    confidence: float = 0.0
    risk_score: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
