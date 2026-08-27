"""SQL injection detector for HTTP request logs.

Uses compiled high-signal patterns against a normalized request string.
Heuristic confidence values are pattern-local, not a calibrated score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG, SqlInjectionConfig
from analyzer.models import LogEntry, SecurityAlert
from analyzer.normalization import normalize_request

_SEVERITY = "CRITICAL"


@dataclass(frozen=True)
class _SqlPattern:
    """Compiled SQLi indicator with heuristic confidence."""

    name: str
    regex: re.Pattern[str]
    confidence: float
    risk_score: int


# Ordered roughly by signal strength; strongest match wins per request.
_SQL_PATTERNS: tuple[_SqlPattern, ...] = (
    _SqlPattern(
        "UNION SELECT",
        re.compile(r"\bunion(?:\s+all)?\s+select\b"),
        0.95,
        92,
    ),
    _SqlPattern(
        "OR 1=1",
        re.compile(r"\bor\s+1\s*=\s*1\b"),
        0.95,
        90,
    ),
    _SqlPattern(
        "OR '1'='1'",
        re.compile(r"\bor\s+'1'\s*=\s*'1'"),
        0.95,
        90,
    ),
    _SqlPattern(
        "AND 1=1",
        re.compile(r"\band\s+1\s*=\s*1\b"),
        0.90,
        88,
    ),
    _SqlPattern(
        "quote-OR tautology",
        re.compile(r"'\s*or\s+'[^']*'\s*=\s*'"),
        0.90,
        88,
    ),
    _SqlPattern(
        "information_schema",
        re.compile(r"\binformation_schema\b"),
        0.92,
        90,
    ),
    _SqlPattern(
        "DROP TABLE",
        re.compile(r"\bdrop\s+table\b"),
        0.93,
        95,
    ),
    _SqlPattern(
        "INSERT INTO",
        re.compile(r"\binsert\s+into\b"),
        0.85,
        85,
    ),
    _SqlPattern(
        "UPDATE SET",
        re.compile(r"\bupdate\b.+\bset\b"),
        0.85,
        85,
    ),
    _SqlPattern(
        "DELETE FROM",
        re.compile(r"\bdelete\s+from\b"),
        0.88,
        88,
    ),
    _SqlPattern(
        "SLEEP(",
        re.compile(r"\bsleep\s*\("),
        0.92,
        90,
    ),
    _SqlPattern(
        "WAITFOR DELAY",
        re.compile(r"\bwaitfor\s+delay\b"),
        0.92,
        90,
    ),
    _SqlPattern(
        "PG_SLEEP(",
        re.compile(r"\bpg_sleep\s*\("),
        0.92,
        90,
    ),
)


def _resolve_config(
    config: AnalyzerConfig | SqlInjectionConfig | None,
) -> SqlInjectionConfig:
    if config is None:
        return DEFAULT_CONFIG.sql_injection
    if isinstance(config, AnalyzerConfig):
        return config.sql_injection
    return config


def _request_text(log: LogEntry) -> str:
    return log.request or log.path or ""


def _find_best_match(normalized: str) -> tuple[_SqlPattern, list[str]] | None:
    """Return the highest-confidence matching pattern and all hit names."""
    best: _SqlPattern | None = None
    matched: list[str] = []
    for pattern in _SQL_PATTERNS:
        if pattern.regex.search(normalized):
            matched.append(pattern.name)
            if best is None or pattern.confidence > best.confidence:
                best = pattern
            elif (
                best is not None
                and pattern.confidence == best.confidence
                and pattern.risk_score > best.risk_score
            ):
                best = pattern
    if best is None:
        return None
    return best, matched


def detect_sql_injection(
    logs: list[LogEntry],
    config: AnalyzerConfig | SqlInjectionConfig | None = None,
) -> list[SecurityAlert]:
    """Detect high-signal SQL injection indicators in HTTP requests.

    Emits at most one alert per malicious request. Standalone SQL comment
    markers (``--``) and bare keywords like ``union`` / ``select`` alone
    are intentionally not flagged.
    """
    cfg = _resolve_config(config)
    if not cfg.enabled:
        return []

    alerts: list[SecurityAlert] = []

    for log in logs:
        if log.event_type != "HTTP_REQUEST":
            continue

        original = _request_text(log)
        if not original:
            continue

        normalized = normalize_request(original)
        found = _find_best_match(normalized.normalized)
        if found is None:
            continue

        best, matched = found
        evidence = {
            "pattern": best.name,
            "request": normalized.original,
            "normalized_request": normalized.normalized,
            "matched_indicators": matched,
        }
        alerts.append(
            SecurityAlert(
                alert_type="SQL_INJECTION",
                severity=_SEVERITY,
                timestamp=log.timestamp,
                username=log.username or "-",
                ip_address=log.ip_address,
                description=(
                    f"SQL injection indicator detected: {best.name}"
                ),
                source=log.source or "apache",
                evidence=evidence,
                confidence=best.confidence,
                risk_score=best.risk_score,
                metadata={
                    "detector": "sql_injection",
                    "heuristic_confidence": True,
                    "status_code": log.status_code,
                    "method": log.method,
                },
            )
        )

    return alerts
