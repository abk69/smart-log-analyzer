"""Heuristic insider-threat detector.

Combines multiple weak signals into a score. A single signal (for example an
admin login at an odd hour alone, depending on weights) should not by itself
meet the alert threshold. This is intentionally a transparent heuristic — not
ML and not a definitive insider-threat determination.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG, InsiderThreatConfig
from analyzer.models import LogEntry, SecurityAlert

_SEVERITY = "MEDIUM"


def _resolve_config(
    config: AnalyzerConfig | InsiderThreatConfig | None,
) -> InsiderThreatConfig:
    if config is None:
        return DEFAULT_CONFIG.insider_threat
    if isinstance(config, AnalyzerConfig):
        return config.insider_threat
    return config


def _is_unusual_hour(hour: int, start: int, end: int) -> bool:
    """Return True if ``hour`` falls in the unusual range [start, end)."""
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    # Overnight wrap, e.g. 22 → 5
    return hour >= start or hour < end


def _is_sensitive_path(path: str, prefixes: tuple[str, ...]) -> bool:
    text = (path or "").lower()
    return any(text.startswith(prefix.lower()) for prefix in prefixes)


def _majority_ip(events: list[LogEntry]) -> str | None:
    ips = [e.ip_address for e in events if e.ip_address]
    if not ips:
        return None
    return Counter(ips).most_common(1)[0][0]


def detect_insider_threat(
    logs: list[LogEntry],
    config: AnalyzerConfig | InsiderThreatConfig | None = None,
) -> list[SecurityAlert]:
    """Score per-user activity and alert when the combined heuristic crosses threshold."""
    cfg = _resolve_config(config)
    if not cfg.enabled:
        return []

    privileged = {u.lower() for u in cfg.privileged_users}
    by_user: dict[str, list[LogEntry]] = defaultdict(list)

    for log in logs:
        if not log.username or log.username == "-":
            continue
        by_user[log.username].append(log)

    alerts: list[SecurityAlert] = []

    for username, events in by_user.items():
        events.sort(key=lambda e: e.timestamp)
        score = 0
        signals: list[str] = []

        is_privileged = username.lower() in privileged
        if is_privileged:
            score += cfg.score_privileged
            signals.append("privileged_account")

        unusual_hour_events = [
            e
            for e in events
            if _is_unusual_hour(
                e.timestamp.hour,
                cfg.unusual_hour_start,
                cfg.unusual_hour_end,
            )
        ]
        if unusual_hour_events:
            score += cfg.score_unusual_hour
            signals.append("unusual_hour")

        if len(events) >= cfg.activity_threshold:
            score += cfg.score_high_activity
            signals.append("high_activity_volume")

        sensitive_hits = [
            e
            for e in events
            if e.event_type == "HTTP_REQUEST"
            and _is_sensitive_path(e.request or e.path, cfg.sensitive_path_prefixes)
        ]
        if sensitive_hits:
            score += cfg.score_sensitive_resource
            signals.append("sensitive_resource_access")

        majority = _majority_ip(events)
        unusual_ips = []
        if majority is not None:
            for e in events:
                if e.ip_address and e.ip_address != majority:
                    unusual_ips.append(e.ip_address)
        # Require the majority to be established (at least 2 events) before
        # treating other IPs as unusual — avoids FP on first-login diversity.
        if unusual_ips and Counter(e.ip_address for e in events)[majority] >= 2:
            score += cfg.score_unusual_ip
            signals.append("unusual_source_ip")

        if score < cfg.alert_score_threshold:
            continue

        # Prefer the most recent contributing event for the alert timestamp/IP.
        anchor = unusual_hour_events[-1] if unusual_hour_events else events[-1]
        if sensitive_hits:
            anchor = sensitive_hits[-1]

        confidence = min(0.95, 0.55 + (score / max(cfg.alert_score_threshold, 1)) * 0.2)
        risk_score = min(90, 40 + score // 2)

        evidence = {
            "score": score,
            "threshold": cfg.alert_score_threshold,
            "signals": signals,
            "event_count": len(events),
            "privileged": is_privileged,
            "unusual_hour_count": len(unusual_hour_events),
            "sensitive_access_count": len(sensitive_hits),
            "majority_ip": majority,
            "unusual_ips": sorted(set(unusual_ips)),
        }

        alerts.append(
            SecurityAlert(
                alert_type="INSIDER_THREAT",
                severity=_SEVERITY,
                timestamp=anchor.timestamp,
                username=username,
                ip_address=anchor.ip_address,
                description=(
                    f"Heuristic insider-threat signals for '{username}' "
                    f"(score {score}/{cfg.alert_score_threshold}): "
                    + ", ".join(signals)
                ),
                source=anchor.source or "",
                evidence=evidence,
                confidence=confidence,
                risk_score=risk_score,
                metadata={
                    "detector": "insider_threat",
                    "heuristic": True,
                    "not_ml": True,
                },
            )
        )

    return alerts
