"""Shared serialization helpers for analysis reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from analyzer import __version__
from analyzer.models import AnalysisResult, Incident, SecurityAlert

APP_NAME = "Smart Log Analyzer"
APP_VERSION = __version__


def to_iso(value: datetime | None) -> str | None:
    """Serialize datetimes as ISO-8601 strings."""
    if value is None:
        return None
    return value.isoformat(sep=" ")


def json_safe(value: Any) -> Any:
    """Recursively convert values into JSON-serializable forms."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return to_iso(value)
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if hasattr(value, "__dict__") and not isinstance(value, type):
        # Fallback for unexpected objects
        return str(value)
    return str(value)


def alert_to_dict(alert: SecurityAlert) -> dict[str, Any]:
    """Convert a ``SecurityAlert`` into a serializable dictionary."""
    return {
        "alert_id": alert.alert_id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "timestamp": to_iso(alert.timestamp),
        "username": alert.username,
        "ip_address": alert.ip_address,
        "source": alert.source,
        "description": alert.description,
        "evidence": json_safe(alert.evidence),
        "confidence": alert.confidence,
        "risk_score": alert.risk_score,
        "metadata": json_safe(alert.metadata),
    }


def incident_to_dict(incident: Incident, *, include_alerts: bool = False) -> dict[str, Any]:
    """Convert an ``Incident`` into a serializable dictionary."""
    payload: dict[str, Any] = {
        "incident_id": incident.incident_id,
        "incident_type": incident.incident_type,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "first_seen": to_iso(incident.first_seen),
        "last_seen": to_iso(incident.last_seen),
        "source_ips": list(incident.source_ips),
        "usernames": list(incident.usernames),
        "alert_ids": list(incident.alert_ids),
        "description": incident.description,
        "evidence": json_safe(incident.evidence),
        "metadata": json_safe(incident.metadata),
        "alert_count": len(incident.alerts),
    }
    if include_alerts:
        payload["alerts"] = [alert_to_dict(a) for a in incident.alerts]
    return payload


def severity_counts(items: list[Any]) -> dict[str, int]:
    counts = Counter((getattr(item, "severity", "") or "").upper() for item in items)
    return {
        "CRITICAL": counts.get("CRITICAL", 0),
        "HIGH": counts.get("HIGH", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "LOW": counts.get("LOW", 0),
    }


def attack_type_counts(alerts: list[SecurityAlert]) -> dict[str, int]:
    counts = Counter(a.alert_type for a in alerts if a.alert_type)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_report_document(result: AnalysisResult) -> dict[str, Any]:
    """Build the canonical report document consumed by JSON/HTML serializers."""
    alert_sev = severity_counts(result.alerts)
    incident_sev = severity_counts(result.incidents)
    highest_risk = max((i.risk_score for i in result.incidents), default=0)

    return {
        "metadata": {
            "application": APP_NAME,
            "analyzer_version": APP_VERSION,
            "report_generated_at": to_iso(datetime.now()),
            "input_file": result.input_file,
        },
        "analysis": {
            "analyzed_at": to_iso(result.analyzed_at),
            "duration_seconds": round(result.duration_seconds, 4),
            "log_count": result.log_count,
            "total_lines": result.parse_stats.get("total_lines", 0),
            "parsed_lines": result.parse_stats.get("parsed_lines", 0),
            "malformed_lines": result.parse_stats.get("malformed_lines", 0),
            "unsupported_lines": result.parse_stats.get("unsupported_lines", 0),
            "parse_stats": json_safe(result.parse_stats),
        },
        "statistics": json_safe(result.statistics),
        "summary": {
            "total_events": result.statistics.get("total_logs", result.log_count),
            "total_alerts": len(result.alerts),
            "total_incidents": len(result.incidents),
            "alert_severity": alert_sev,
            "incident_severity": incident_sev,
            "attack_types": attack_type_counts(result.alerts),
            "highest_risk_score": highest_risk,
            "critical_alerts": alert_sev["CRITICAL"],
            "high_alerts": alert_sev["HIGH"],
        },
        "alerts": [alert_to_dict(alert) for alert in result.alerts],
        "incidents": [incident_to_dict(inc) for inc in result.incidents],
    }
