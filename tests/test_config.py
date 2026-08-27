"""Tests for configuration and exception hierarchy."""

from datetime import datetime

from analyzer.config import DEFAULT_CONFIG, AnalyzerConfig
from analyzer.exceptions import (
    ConfigurationError,
    LogAnalyzerError,
    LogFileError,
    ParseError,
    ReportGenerationError,
)


def test_default_config_brute_force_thresholds():
    assert DEFAULT_CONFIG.brute_force.failed_attempt_threshold == 5
    assert DEFAULT_CONFIG.brute_force.window_seconds == 120


def test_default_config_password_spray_thresholds():
    assert DEFAULT_CONFIG.password_spray.unique_user_threshold == 5
    assert DEFAULT_CONFIG.password_spray.window_seconds == 120


def test_default_config_web_detectors_enabled():
    assert DEFAULT_CONFIG.sql_injection.enabled is True
    assert DEFAULT_CONFIG.xss.enabled is True


def test_default_config_insider_hours():
    assert DEFAULT_CONFIG.insider_threat.unusual_hour_start == 0
    assert DEFAULT_CONFIG.insider_threat.unusual_hour_end == 5


def test_default_log_year_is_current_not_hardcoded_2026():
    config = AnalyzerConfig()
    assert config.default_log_year == datetime.now().year
    assert config.default_timezone == "UTC"


def test_exception_hierarchy():
    assert issubclass(LogFileError, LogAnalyzerError)
    assert issubclass(ParseError, LogAnalyzerError)
    assert issubclass(ConfigurationError, LogAnalyzerError)
    assert issubclass(ReportGenerationError, LogAnalyzerError)
    assert issubclass(LogAnalyzerError, Exception)
