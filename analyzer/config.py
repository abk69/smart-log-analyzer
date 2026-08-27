"""Application configuration for detector thresholds and defaults.

Uses standard-library dataclasses only.
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
class ImpossibleTravelConfig:
    """Heuristic impossible-travel settings.

    ``max_plausible_speed_kmh`` is intentionally approximate (not a physics
    model). Commercial air travel with buffer is a common SIEM-style heuristic.
    """

    enabled: bool = True
    max_plausible_speed_kmh: float = 900.0


@dataclass(frozen=True)
class InsiderThreatConfig:
    """Multi-signal insider-threat heuristic settings.

    A single weak signal must not trigger an alert by itself. Scores are
    summed and compared to ``alert_score_threshold``.
    """

    enabled: bool = True
    unusual_hour_start: int = 0
    unusual_hour_end: int = 5
    activity_threshold: int = 20
    alert_score_threshold: int = 50
    privileged_users: tuple[str, ...] = ("admin", "root", "administrator")
    sensitive_path_prefixes: tuple[str, ...] = (
        "/admin",
        "/config",
        "/secret",
        "/backup",
        "/.env",
        "/etc",
    )
    score_privileged: int = 30
    score_unusual_hour: int = 20
    score_unusual_ip: int = 20
    score_high_activity: int = 20
    score_sensitive_resource: int = 20


@dataclass(frozen=True)
class AnalyzerConfig:
    """Top-level configuration container for the analyzer."""

    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    password_spray: PasswordSprayConfig = field(default_factory=PasswordSprayConfig)
    sql_injection: SqlInjectionConfig = field(default_factory=SqlInjectionConfig)
    xss: XssConfig = field(default_factory=XssConfig)
    impossible_travel: ImpossibleTravelConfig = field(
        default_factory=ImpossibleTravelConfig
    )
    insider_threat: InsiderThreatConfig = field(default_factory=InsiderThreatConfig)
    # Year used when a log format omits it (e.g. syslog).
    default_log_year: int = field(default_factory=lambda: datetime.now().year)
    default_timezone: str = "UTC"


# Shared default configuration instance for the application.
DEFAULT_CONFIG = AnalyzerConfig()
