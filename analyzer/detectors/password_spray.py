"""Password-spray authentication detector.

Detects failed logins against many usernames from a single IP within a
configured time window. Emits one logical alert per spray burst.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG, PasswordSprayConfig
from analyzer.models import LogEntry, SecurityAlert

_SEVERITY = "HIGH"
_BASE_RISK = 70
_BASE_CONFIDENCE = 0.85


def _resolve_config(
    config: AnalyzerConfig | PasswordSprayConfig | None,
) -> PasswordSprayConfig:
    if config is None:
        return DEFAULT_CONFIG.password_spray
    if isinstance(config, AnalyzerConfig):
        return config.password_spray
    return config


def _local_risk_and_confidence(unique_users: int, threshold: int) -> tuple[int, float]:
    """Explainable detector-local risk/confidence (not global scoring)."""
    overshoot = max(0, unique_users - threshold)
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


def detect_password_spray(
    logs: list[LogEntry],
    config: AnalyzerConfig | PasswordSprayConfig | None = None,
) -> list[SecurityAlert]:
    """Detect multi-username failed logins from one IP.

    Only ``LOGIN_FAILED`` events count. When a window reaches the unique-user
    threshold, one alert is emitted for the full window and the detector
    advances past those events so overlapping sub-windows do not duplicate.
    """
    cfg = _resolve_config(config)
    if not cfg.enabled:
        return []

    threshold = cfg.unique_user_threshold
    window = timedelta(seconds=cfg.window_seconds)

    by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for log in logs:
        if log.event_type != "LOGIN_FAILED":
            continue
        if not log.ip_address:
            continue
        by_ip[log.ip_address].append(log)

    alerts: list[SecurityAlert] = []

    for ip, events in by_ip.items():
        events.sort(key=lambda e: e.timestamp)
        n = len(events)
        left = 0

        while left < n:
            right = left
            while (
                right + 1 < n
                and events[right + 1].timestamp - events[left].timestamp <= window
            ):
                right += 1

            burst = events[left : right + 1]
            users = sorted({e.username for e in burst if e.username})
            unique_users = len(users)

            if unique_users >= threshold:
                start_time = burst[0].timestamp
                end_time = burst[-1].timestamp
                risk_score, confidence = _local_risk_and_confidence(
                    unique_users, threshold
                )
                evidence = {
                    "unique_users": unique_users,
                    "threshold": threshold,
                    "window_seconds": cfg.window_seconds,
                    "start_time": start_time.isoformat(sep=" "),
                    "end_time": end_time.isoformat(sep=" "),
                    "users": users,
                }
                alerts.append(
                    SecurityAlert(
                        alert_type="PASSWORD_SPRAY",
                        severity=_SEVERITY,
                        timestamp=start_time,
                        username=", ".join(users),
                        ip_address=ip,
                        description=(
                            f"Password spray against {unique_users} users "
                            f"from {ip} within {cfg.window_seconds} seconds."
                        ),
                        source=_source_label(e.source for e in burst),
                        evidence=evidence,
                        confidence=confidence,
                        risk_score=risk_score,
                        metadata={
                            "detector": "password_spray",
                            "unique_users": unique_users,
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
