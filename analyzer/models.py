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


@dataclass
class Incident:
    """Correlated group of related ``SecurityAlert`` findings.

    ``incident_id`` is assigned once at construction. ``alerts`` holds
    references to the contributing alert objects; ``alert_ids`` mirrors
    their identifiers for convenient serialization.
    """

    incident_type: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    description: str
    incident_id: str = field(default_factory=lambda: str(uuid4()))
    risk_score: int = 0
    source_ips: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    alerts: list[SecurityAlert] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Complete output of one analysis run.

    Designed for CLI display now and report serialization in a later
    milestone. ``parse_stats`` is a plain dict for easy serialization.
    """

    input_file: str
    analyzed_at: datetime
    duration_seconds: float
    log_count: int
    parse_stats: dict[str, Any]
    statistics: dict[str, Any]
    alerts: list[SecurityAlert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    logs: list[LogEntry] = field(default_factory=list)
