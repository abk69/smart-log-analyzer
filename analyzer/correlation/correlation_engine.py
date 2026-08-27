"""Deterministic alert correlation engine.

Groups related ``SecurityAlert`` objects into ``Incident`` records using
shared IP, shared username, and time proximity. Correlation expresses
observable relatedness — not proven attacker intent.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from analyzer.config import AnalyzerConfig, CorrelationConfig, DEFAULT_CONFIG
from analyzer.models import Incident, SecurityAlert

_SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class _UnionFind:
    """Disjoint-set structure for merging related alert indices."""

    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1


def _resolve_config(
    config: AnalyzerConfig | CorrelationConfig | None,
) -> CorrelationConfig:
    if config is None:
        return DEFAULT_CONFIG.correlation
    if isinstance(config, AnalyzerConfig):
        return config.correlation
    return config


def _normalize_ip(ip: str | None) -> str | None:
    value = (ip or "").strip()
    if not value or value == "-":
        return None
    return value


def _usernames_from_alert(alert: SecurityAlert) -> set[str]:
    """Extract individual usernames (supports comma-separated spray lists)."""
    raw = (alert.username or "").strip()
    if not raw or raw == "-":
        return set()
    return {
        part.strip().lower()
        for part in raw.split(",")
        if part.strip() and part.strip() != "-"
    }


def _chain_by_time(
    indices: list[int],
    alerts: list[SecurityAlert],
    uf: _UnionFind,
    window: timedelta,
) -> None:
    """Union time-ordered alerts when consecutive gaps are within ``window``."""
    if len(indices) < 2:
        return
    ordered = sorted(indices, key=lambda i: alerts[i].timestamp)
    for left, right in zip(ordered, ordered[1:]):
        if alerts[right].timestamp - alerts[left].timestamp <= window:
            uf.union(left, right)


def _highest_severity(alerts: Iterable[SecurityAlert]) -> str:
    best = "LOW"
    best_rank = 0
    for alert in alerts:
        rank = _SEVERITY_RANK.get((alert.severity or "").upper(), 0)
        if rank > best_rank:
            best_rank = rank
            best = (alert.severity or "LOW").upper()
    return best if best_rank else "MEDIUM"


def _attack_chain(alerts: list[SecurityAlert]) -> list[str]:
    """Observed alert-type sequence ordered by first occurrence time."""
    first_seen: dict[str, object] = {}
    for alert in sorted(alerts, key=lambda a: a.timestamp):
        if alert.alert_type not in first_seen:
            first_seen[alert.alert_type] = alert.timestamp
    return list(first_seen.keys())


def _incident_type(chain: list[str]) -> str:
    if not chain:
        return "UNKNOWN"
    if len(chain) == 1:
        return chain[0]
    return "CORRELATED_ACTIVITY"


def _build_incident(member_alerts: list[SecurityAlert]) -> Incident:
    member_alerts = sorted(member_alerts, key=lambda a: a.timestamp)
    chain = _attack_chain(member_alerts)
    ips = sorted(
        {
            ip
            for a in member_alerts
            if (ip := _normalize_ip(a.ip_address)) is not None
        }
    )
    users = sorted(
        {user for a in member_alerts for user in _usernames_from_alert(a)}
    )
    severity = _highest_severity(member_alerts)
    incident_type = _incident_type(chain)

    if len(member_alerts) == 1:
        description = (
            "Single security alert observed "
            f"({member_alerts[0].alert_type})."
        )
    else:
        description = (
            "Multiple related security alerts observed within the "
            "configured correlation window (correlated activity, not "
            "proven attacker intent)."
        )

    return Incident(
        incident_type=incident_type,
        severity=severity,
        first_seen=member_alerts[0].timestamp,
        last_seen=member_alerts[-1].timestamp,
        description=description,
        source_ips=ips,
        usernames=users,
        alert_ids=[a.alert_id for a in member_alerts],
        alerts=member_alerts,
        evidence={
            "alert_count": len(member_alerts),
            "observed_alert_chain": chain,
            "correlation_basis": "shared_ip_or_user_within_time_window",
        },
        metadata={
            "attack_chain": chain,
            "alert_types": sorted({a.alert_type for a in member_alerts}),
        },
    )


def correlate_alerts(
    alerts: list[SecurityAlert],
    config: AnalyzerConfig | CorrelationConfig | None = None,
) -> list[Incident]:
    """Correlate alerts into incidents using IP/user + time proximity.

    Strategy:
    1. Index alerts by IP and by username.
    2. Within each index bucket, chain alerts whose consecutive timestamps
       fall inside ``window_seconds`` (union-find).
    3. Connected components become incidents.

    Complexity is approximately O(n log n) for sorting plus near-linear
    union operations over bucket sizes — not a full O(n²) pairwise scan.
    """
    cfg = _resolve_config(config)
    if not alerts:
        return []

    if not cfg.enabled:
        return [_build_incident([alert]) for alert in alerts]

    n = len(alerts)
    uf = _UnionFind(n)
    window = timedelta(seconds=cfg.window_seconds)

    if cfg.correlate_by_ip:
        by_ip: dict[str, list[int]] = defaultdict(list)
        for idx, alert in enumerate(alerts):
            ip = _normalize_ip(alert.ip_address)
            if ip is not None:
                by_ip[ip].append(idx)
        for indices in by_ip.values():
            _chain_by_time(indices, alerts, uf, window)

    if cfg.correlate_by_user:
        by_user: dict[str, list[int]] = defaultdict(list)
        for idx, alert in enumerate(alerts):
            for user in _usernames_from_alert(alert):
                by_user[user].append(idx)
        for indices in by_user.values():
            _chain_by_time(indices, alerts, uf, window)

    components: dict[int, list[SecurityAlert]] = defaultdict(list)
    for idx, alert in enumerate(alerts):
        components[uf.find(idx)].append(alert)

    incidents = [_build_incident(group) for group in components.values()]
    incidents.sort(key=lambda inc: inc.first_seen)
    return incidents
