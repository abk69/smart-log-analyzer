"""Custom exceptions for Smart Log Analyzer."""


class LogAnalyzerError(Exception):
    """Base exception for all analyzer application errors."""


class LogFileError(LogAnalyzerError):
    """Raised when a log file cannot be read or is invalid for analysis."""


class ParseError(LogAnalyzerError):
    """Raised when log content cannot be parsed as expected."""


class ConfigurationError(LogAnalyzerError):
    """Raised when application configuration is missing or invalid."""


class ReportGenerationError(LogAnalyzerError):
    """Raised when a report cannot be written or serialized."""
