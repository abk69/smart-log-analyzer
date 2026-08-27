"""Impossible-travel detector for successful authentication events.

Compares consecutive successful logins for the same user, resolves IPs via a
local geolocation map, and flags transitions whose implied speed exceeds a
configurable heuristic threshold.

This is a portfolio SIEM-style heuristic — not a precise physics or
airline-routing model.
"""

from __future__ import annotations

from collections import defaultdict

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG, ImpossibleTravelConfig
from analyzer.models import LogEntry, SecurityAlert
from analyzer.services.geolocation import (
    GeoLocationService,
    StaticGeoLocationService,
    haversine_km,
    required_speed_kmh,
)

_SEVERITY = "HIGH"


def _resolve_config(
    config: AnalyzerConfig | ImpossibleTravelConfig | None,
) -> ImpossibleTravelConfig:
    if config is None:
        return DEFAULT_CONFIG.impossible_travel
    if isinstance(config, AnalyzerConfig):
        return config.impossible_travel
    return config


def detect_impossible_travel(
    logs: list[LogEntry],
    config: AnalyzerConfig | ImpossibleTravelConfig | None = None,
    *,
    geo_service: GeoLocationService | None = None,
) -> list[SecurityAlert]:
    """Detect physically implausible consecutive successful logins.

    Skips comparisons when either IP is unmapped, IPs/locations are the same,
    only one success exists, or elapsed time allows plausible travel.
    """
    cfg = _resolve_config(config)
    if not cfg.enabled:
        return []

    geo = geo_service if geo_service is not None else StaticGeoLocationService()
    by_user: dict[str, list[LogEntry]] = defaultdict(list)

    for log in logs:
        if log.event_type != "LOGIN_SUCCESS":
            continue
        if not log.username or log.username == "-":
            continue
        by_user[log.username].append(log)

    alerts: list[SecurityAlert] = []

    for username, events in by_user.items():
        events.sort(key=lambda e: e.timestamp)
        if len(events) < 2:
            continue

        for prev, curr in zip(events, events[1:]):
            if prev.ip_address == curr.ip_address:
                continue

            prev_loc = geo.get_location(prev.ip_address)
            curr_loc = geo.get_location(curr.ip_address)
            if prev_loc is None or curr_loc is None:
                continue
            if prev_loc.city == curr_loc.city:
                continue

            elapsed = (curr.timestamp - prev.timestamp).total_seconds()
            if elapsed < 0:
                continue

            distance_km = haversine_km(prev_loc, curr_loc)
            speed = required_speed_kmh(distance_km, elapsed)
            threshold = cfg.max_plausible_speed_kmh

            if speed <= threshold:
                continue

            # Heuristic confidence rises as speed exceeds the threshold.
            overshoot_ratio = speed / threshold if threshold > 0 else 1.0
            confidence = min(0.99, 0.75 + min(overshoot_ratio, 5.0) * 0.04)
            risk_score = min(95, 70 + int(min(overshoot_ratio, 10.0) * 2))

            evidence = {
                "previous_ip": prev.ip_address,
                "current_ip": curr.ip_address,
                "previous_location": prev_loc.city,
                "current_location": curr_loc.city,
                "distance_km": round(distance_km, 2),
                "elapsed_seconds": elapsed,
                "required_speed_kmh": (
                    None if speed == float("inf") else round(speed, 2)
                ),
                "configured_speed_threshold": threshold,
            }

            alerts.append(
                SecurityAlert(
                    alert_type="IMPOSSIBLE_TRAVEL",
                    severity=_SEVERITY,
                    timestamp=curr.timestamp,
                    username=username,
                    ip_address=curr.ip_address,
                    description=(
                        f"Impossible travel for '{username}': "
                        f"{prev_loc.city} → {curr_loc.city} "
                        f"({distance_km:.0f} km) in {elapsed:.0f}s "
                        f"(~{speed:.0f} km/h > {threshold:.0f} km/h heuristic)."
                    ),
                    source=curr.source or prev.source or "",
                    evidence=evidence,
                    confidence=confidence,
                    risk_score=risk_score,
                    metadata={
                        "detector": "impossible_travel",
                        "heuristic": True,
                        "previous_source": prev.source,
                        "current_source": curr.source,
                    },
                )
            )

    return alerts
