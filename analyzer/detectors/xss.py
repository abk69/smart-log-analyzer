"""Cross-site scripting (XSS) detector for HTTP request logs.

Uses compiled context-aware patterns against a normalized request string.
Heuristic confidence values are pattern-local, not a calibrated score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG, XssConfig
from analyzer.models import LogEntry, SecurityAlert
from analyzer.normalization import normalize_request

_SEVERITY = "HIGH"


@dataclass(frozen=True)
class _XssPattern:
    """Compiled XSS indicator with heuristic confidence."""

    name: str
    regex: re.Pattern[str]
    confidence: float
    risk_score: int


_XSS_PATTERNS: tuple[_XssPattern, ...] = (
    _XssPattern(
        "<script",
        re.compile(r"<\s*script\b"),
        0.95,
        85,
    ),
    _XssPattern(
        "javascript:",
        re.compile(r"\bjavascript\s*:"),
        0.93,
        82,
    ),
    _XssPattern(
        "onerror=",
        re.compile(r"\bonerror\s*="),
        0.92,
        80,
    ),
    _XssPattern(
        "onload=",
        re.compile(r"\bonload\s*="),
        0.92,
        80,
    ),
    _XssPattern(
        "onclick=",
        re.compile(r"\bonclick\s*="),
        0.90,
        78,
    ),
    _XssPattern(
        "onmouseover=",
        re.compile(r"\bonmouseover\s*="),
        0.90,
        78,
    ),
    _XssPattern(
        "<svg",
        re.compile(r"<\s*svg\b"),
        0.88,
        75,
    ),
    _XssPattern(
        "<img",
        re.compile(r"<\s*img\b"),
        0.80,
        72,
    ),
)


def _resolve_config(
    config: AnalyzerConfig | XssConfig | None,
) -> XssConfig:
    if config is None:
        return DEFAULT_CONFIG.xss
    if isinstance(config, AnalyzerConfig):
        return config.xss
    return config


def _request_text(log: LogEntry) -> str:
    return log.request or log.path or ""


def _find_best_match(normalized: str) -> tuple[_XssPattern, list[str]] | None:
    """Return the highest-confidence matching pattern and all hit names."""
    best: _XssPattern | None = None
    matched: list[str] = []
    for pattern in _XSS_PATTERNS:
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


def detect_xss(
    logs: list[LogEntry],
    config: AnalyzerConfig | XssConfig | None = None,
) -> list[SecurityAlert]:
    """Detect high-signal XSS indicators in HTTP requests.

    Emits at most one alert per malicious request. Bare words like
    ``script`` without a tag/URI/handler context are not flagged.
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
                alert_type="XSS",
                severity=_SEVERITY,
                timestamp=log.timestamp,
                username=log.username or "-",
                ip_address=log.ip_address,
                description=f"XSS indicator detected: {best.name}",
                source=log.source or "apache",
                evidence=evidence,
                confidence=best.confidence,
                risk_score=best.risk_score,
                metadata={
                    "detector": "xss",
                    "heuristic_confidence": True,
                    "status_code": log.status_code,
                    "method": log.method,
                },
            )
        )

    return alerts
