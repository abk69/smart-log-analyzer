"""Brute-force authentication detector.

Detects repeated failed logins for the same username from the same IP
within a configured time window. Emits one logical alert per attack burst.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from analyzer.config import AnalyzerConfig, BruteForceConfig, DEFAULT_CONFIG
from analyzer.models import LogEntry, SecurityAlert

# Detector-local defaults (global risk engine arrives in a later milestone).
_SEVERITY = "HIGH"
_BASE_RISK = 70
_BASE_CONFIDENCE = 0.85


def _resolve_config(
    config: AnalyzerConfig | BruteForceConfig | None,
) -> BruteForceConfig:
    if config is None:
        return DEFAULT_CONFIG.brute_force
    if isinstance(config, AnalyzerConfig):
        return config.brute_force
    return config


def _local_risk_and_confidence(attempts: int, threshold: int) -> tuple[int, float]:
    """Explainable detector-local risk/confidence (not global scoring)."""
    overshoot = max(0, attempts - threshold)
    risk = min(95, _BASE_RISK + overshoot * 2)
    confidence = min(0.99, _BASE_CONFIDENCE + overshoot * 0.02)
    return risk, confidence


def _source_label(sources: Iterable[str]) -> str:
    unique = sorted({s for s in sources if s})
    if not unique:
        return ""
    if len(unique) == 1:
        return unique[0]
    return "mixed"


def detect_brute_force(
    logs: list[LogEntry],
    config: AnalyzerConfig | BruteForceConfig | None = None,
) -> list[SecurityAlert]:
    """Detect same-user / same-IP failed-login bursts.

    Only ``LOGIN_FAILED`` events count. Successful logins are ignored.
    For a continuous burst (including above-threshold floods), one alert is
    emitted and the detector advances past that burst.
    """
    cfg = _resolve_config(config)
    if not cfg.enabled:
        return []

    threshold = cfg.failed_attempt_threshold
    window = timedelta(seconds=cfg.window_seconds)

    failed: dict[tuple[str, str], list[LogEntry]] = defaultdict(list)
    for log in logs:
        if log.event_type != "LOGIN_FAILED":
            continue
        if not log.username or not log.ip_address:
            continue
        failed[(log.username, log.ip_address)].append(log)

    alerts: list[SecurityAlert] = []

    for (username, ip), events in failed.items():
        events.sort(key=lambda e: e.timestamp)
        timestamps = [e.timestamp for e in events]
        n = len(timestamps)
        left = 0

        while left <= n - threshold:
            right = left
            while (
                right + 1 < n
                and timestamps[right + 1] - timestamps[left] <= window
            ):
                right += 1

            attempts = right - left + 1
            if attempts >= threshold:
                burst = events[left : right + 1]
                start_time = timestamps[left]
                end_time = timestamps[right]
                risk_score, confidence = _local_risk_and_confidence(
                    attempts, threshold
                )
                evidence = {
                    "attempts": attempts,
                    "threshold": threshold,
                    "window_seconds": cfg.window_seconds,
                    "start_time": start_time.isoformat(sep=" "),
                    "end_time": end_time.isoformat(sep=" "),
                }
                alerts.append(
                    SecurityAlert(
                        alert_type="BRUTE_FORCE",
                        severity=_SEVERITY,
                        timestamp=start_time,
                        username=username,
                        ip_address=ip,
                        description=(
                            f"{attempts} failed login attempts for '{username}' "
                            f"from {ip} within {cfg.window_seconds} seconds."
                        ),
                        source=_source_label(e.source for e in burst),
                        evidence=evidence,
                        confidence=confidence,
                        risk_score=risk_score,
                        metadata={
                            "detector": "brute_force",
                            "burst_size": attempts,
                            "event_sources": sorted(
                                {e.source for e in burst if e.source}
                            ),
                        },
                    )
                )
                left = right + 1
            else:
                left += 1

    return alerts
