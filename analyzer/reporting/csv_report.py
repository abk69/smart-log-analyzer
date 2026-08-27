"""CSV security report writers for alerts and incidents."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from analyzer.exceptions import ReportGenerationError
from analyzer.models import AnalysisResult
from analyzer.reporting.serialize import to_iso


def _evidence_cell(evidence: object) -> str:
    return json.dumps(evidence, ensure_ascii=False, default=str)


def write_alerts_csv(result: AnalysisResult, output_dir: Path) -> Path:
    """Write ``security_alerts.csv`` and return the path."""
    output_dir = Path(output_dir)
    path = output_dir / "security_alerts.csv"
    headers = [
        "alert_id",
        "alert_type",
        "severity",
        "timestamp",
        "username",
        "ip_address",
        "source",
        "description",
        "confidence",
        "risk_score",
        "evidence",
    ]
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            for alert in result.alerts:
                writer.writerow(
                    {
                        "alert_id": alert.alert_id,
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                        "timestamp": to_iso(alert.timestamp),
                        "username": alert.username,
                        "ip_address": alert.ip_address,
                        "source": alert.source,
                        "description": alert.description,
                        "confidence": alert.confidence,
                        "risk_score": alert.risk_score,
                        "evidence": _evidence_cell(alert.evidence),
                    }
                )
        return path
    except OSError as exc:
        raise ReportGenerationError(f"Unable to write alerts CSV: {exc}") from exc


def write_incidents_csv(result: AnalysisResult, output_dir: Path) -> Path:
    """Write ``security_incidents.csv`` and return the path."""
    output_dir = Path(output_dir)
    path = output_dir / "security_incidents.csv"
    headers = [
        "incident_id",
        "incident_type",
        "severity",
        "risk_score",
        "first_seen",
        "last_seen",
        "source_ips",
        "usernames",
        "alert_count",
        "description",
    ]
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            for incident in result.incidents:
                writer.writerow(
                    {
                        "incident_id": incident.incident_id,
                        "incident_type": incident.incident_type,
                        "severity": incident.severity,
                        "risk_score": incident.risk_score,
                        "first_seen": to_iso(incident.first_seen),
                        "last_seen": to_iso(incident.last_seen),
                        "source_ips": "; ".join(incident.source_ips),
                        "usernames": "; ".join(incident.usernames),
                        "alert_count": len(incident.alerts),
                        "description": incident.description,
                    }
                )
        return path
    except OSError as exc:
        raise ReportGenerationError(f"Unable to write incidents CSV: {exc}") from exc


def write_csv_reports(result: AnalysisResult, output_dir: Path) -> dict[str, Path]:
    """Write both alert and incident CSV reports."""
    return {
        "alerts_csv": write_alerts_csv(result, output_dir),
        "incidents_csv": write_incidents_csv(result, output_dir),
    }
