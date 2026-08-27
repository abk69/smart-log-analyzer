"""Deterministic behavioral feature extraction for anomaly detection.

Operates on raw ``LogEntry`` aggregates only. Detector outputs are never
used as features (avoids leaking rule-engine answers into the model).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from analyzer.config import AnomalyConfig, DEFAULT_CONFIG
from analyzer.models import LogEntry

# Shared schema for IP and user entities (Isolation Forest matrix columns).
FEATURE_NAMES: tuple[str, ...] = (
    "total_events",
    "failed_logins",
    "successful_logins",
    "failed_ratio",
    "unique_users",
    "unique_ips",
    "unique_paths",
    "http_requests",
    "http_errors",
    "auth_attempts",
    "unusual_hour_events",
    "source_diversity",
)


@dataclass(frozen=True)
class FeatureVector:
    """Behavioral feature vector for one entity (IP or user)."""

    entity_id: str
    entity_type: str  # "ip" | "user"
    feature_names: tuple[str, ...]
    values: tuple[float, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, float]:
        return dict(zip(self.feature_names, self.values))


def _is_unusual_hour(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _aggregate(events: Sequence[LogEntry], *, unusual_start: int, unusual_end: int) -> dict[str, float]:
    total = len(events)
    failed = sum(1 for e in events if e.event_type == "LOGIN_FAILED")
    success = sum(1 for e in events if e.event_type == "LOGIN_SUCCESS")
    auth = failed + success
    http = sum(1 for e in events if e.event_type == "HTTP_REQUEST")
    http_errors = sum(
        1
        for e in events
        if e.event_type == "HTTP_REQUEST"
        and e.status_code is not None
        and e.status_code >= 400
    )
    users = {e.username for e in events if e.username and e.username != "-"}
    ips = {e.ip_address for e in events if e.ip_address}
    paths = {e.path or e.request for e in events if (e.path or e.request)}
    sources = {e.source for e in events if e.source}
    unusual = sum(
        1
        for e in events
        if _is_unusual_hour(e.timestamp.hour, unusual_start, unusual_end)
    )
    failed_ratio = (failed / total) if total else 0.0

    return {
        "total_events": float(total),
        "failed_logins": float(failed),
        "successful_logins": float(success),
        "failed_ratio": float(failed_ratio),
        "unique_users": float(len(users)),
        "unique_ips": float(len(ips)),
        "unique_paths": float(len(paths)),
        "http_requests": float(http),
        "http_errors": float(http_errors),
        "auth_attempts": float(auth),
        "unusual_hour_events": float(unusual),
        "source_diversity": float(len(sources)),
    }


def _vector_from_aggregate(
    entity_id: str,
    entity_type: str,
    events: Sequence[LogEntry],
    *,
    unusual_start: int,
    unusual_end: int,
) -> FeatureVector:
    agg = _aggregate(events, unusual_start=unusual_start, unusual_end=unusual_end)
    values = tuple(agg[name] for name in FEATURE_NAMES)
    last_ts = max(e.timestamp for e in events)
    return FeatureVector(
        entity_id=entity_id,
        entity_type=entity_type,
        feature_names=FEATURE_NAMES,
        values=values,
        metadata={
            "event_count": len(events),
            "last_seen": last_ts.isoformat(sep=" "),
            "sample_sources": sorted({e.source for e in events if e.source}),
        },
    )


def extract_feature_vectors(
    logs: Sequence[LogEntry],
    config: AnomalyConfig | None = None,
) -> list[FeatureVector]:
    """Build deterministic per-IP (and optional per-user) feature vectors."""
    cfg = config if config is not None else DEFAULT_CONFIG.anomaly
    by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    by_user: dict[str, list[LogEntry]] = defaultdict(list)

    for entry in logs:
        if entry.ip_address:
            by_ip[entry.ip_address].append(entry)
        if entry.username and entry.username != "-":
            by_user[entry.username].append(entry)

    vectors: list[FeatureVector] = []
    for ip, events in sorted(by_ip.items()):
        vectors.append(
            _vector_from_aggregate(
                ip,
                "ip",
                events,
                unusual_start=cfg.unusual_hour_start,
                unusual_end=cfg.unusual_hour_end,
            )
        )

    if cfg.include_user_entities:
        for user, events in sorted(by_user.items()):
            vectors.append(
                _vector_from_aggregate(
                    user,
                    "user",
                    events,
                    unusual_start=cfg.unusual_hour_start,
                    unusual_end=cfg.unusual_hour_end,
                )
            )

    return vectors


def describe_unusual_features(
    vector: FeatureVector,
    *,
    peers: Iterable[FeatureVector] | None = None,
    top_n: int = 5,
) -> list[str]:
    """Return human-readable notes for relatively elevated features.

    This is descriptive peer comparison — not Isolation Forest feature
    importance (which IF does not provide per prediction).
    """
    features = vector.as_dict()
    peer_list = list(peers) if peers is not None else []
    notes: list[tuple[float, str]] = []

    for name, value in features.items():
        if value <= 0:
            continue
        if peer_list:
            peer_vals = [v.as_dict().get(name, 0.0) for v in peer_list if v.entity_id != vector.entity_id]
            baseline = (sum(peer_vals) / len(peer_vals)) if peer_vals else 0.0
            if baseline <= 0:
                if value >= 5:
                    notes.append((value, f"{name.replace('_', ' ')}: {value:g}"))
                continue
            ratio = value / baseline
            if ratio >= 2.0 and value >= 1:
                notes.append(
                    (
                        ratio,
                        f"{name.replace('_', ' ')}: {value:g} "
                        f"(~{ratio:.1f}x peer average)",
                    )
                )
        else:
            # Absolute heuristics when peers are unavailable.
            if name == "failed_ratio" and value >= 0.5:
                notes.append((value, f"failed login ratio: {value:.2f}"))
            elif name in {"failed_logins", "total_events", "unusual_hour_events"} and value >= 10:
                notes.append((value, f"{name.replace('_', ' ')}: {value:g}"))
            elif name in {"unique_users", "unique_ips"} and value >= 5:
                notes.append((value, f"{name.replace('_', ' ')}: {value:g}"))

    notes.sort(key=lambda item: item[0], reverse=True)
    return [text for _, text in notes[:top_n]]
