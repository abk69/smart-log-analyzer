"""Application configuration for detector thresholds and defaults.

Uses standard-library dataclasses only. Values are intended to be consumed
by detectors and parsers in later milestones; detection algorithms are not
wired to this module yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class BruteForceConfig:
    """Thresholds for same-user / same-IP failed login bursts."""

    enabled: bool = True
    failed_attempt_threshold: int = 5
    window_seconds: int = 120


@dataclass(frozen=True)
class PasswordSprayConfig:
    """Thresholds for multi-username failed login from one IP."""

    enabled: bool = True
    unique_user_threshold: int = 5
    window_seconds: int = 120


@dataclass(frozen=True)
class SqlInjectionConfig:
    """Toggle for SQL injection detection."""

    enabled: bool = True


@dataclass(frozen=True)
class XssConfig:
    """Toggle for XSS detection."""

    enabled: bool = True


@dataclass(frozen=True)
class InsiderThreatConfig:
    """Heuristic windows for unusual privileged activity hours (local)."""

    unusual_hour_start: int = 0
    unusual_hour_end: int = 5


@dataclass(frozen=True)
class AnalyzerConfig:
    """Top-level configuration container for the analyzer."""

    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    password_spray: PasswordSprayConfig = field(default_factory=PasswordSprayConfig)
    sql_injection: SqlInjectionConfig = field(default_factory=SqlInjectionConfig)
    xss: XssConfig = field(default_factory=XssConfig)
    insider_threat: InsiderThreatConfig = field(default_factory=InsiderThreatConfig)
    # Year used when a log format omits it (e.g. syslog). Not a fixed calendar
    # year; defaults to the current UTC year so deployments stay current.
    default_log_year: int = field(default_factory=lambda: datetime.now().year)
    # IANA-style label for documentation / future timezone-aware parsing.
    default_timezone: str = "UTC"


# Shared default configuration instance for the application.
DEFAULT_CONFIG = AnalyzerConfig()
