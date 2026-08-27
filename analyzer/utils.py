"""Shared application utilities (diagnostics, not security-log analysis)."""

from __future__ import annotations

import logging
from typing import Optional

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}


def setup_logging(
    level: str = "INFO",
    *,
    verbose: bool = False,
) -> logging.Logger:
    """Configure application diagnostic logging.

    This configures Python's ``logging`` module for the analyzer process.
    It is separate from parsing and analyzing security log files.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR).
        verbose: When True, forces DEBUG regardless of ``level``.

    Returns:
        The root ``smart_log_analyzer`` logger.
    """
    resolved = logging.DEBUG if verbose else _LEVEL_MAP.get(level.upper(), logging.INFO)

    root = logging.getLogger("smart_log_analyzer")
    root.setLevel(resolved)

    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root.addHandler(handler)

    # Avoid duplicate emission through the root logger.
    root.propagate = False
    return root


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a child logger under the application logging namespace."""
    if name:
        return logging.getLogger(f"smart_log_analyzer.{name}")
    return logging.getLogger("smart_log_analyzer")
