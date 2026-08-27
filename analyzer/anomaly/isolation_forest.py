"""Isolation Forest anomaly detection for behavioral feature vectors.

Local-only classical ML (scikit-learn). No external APIs or deep learning.

``anomaly_score`` is a heuristic 0–100 transform of IsolationForest's
``decision_function`` (higher = more anomalous). It is **not** an attack
probability.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Sequence

from analyzer.config import AnomalyConfig, AnalyzerConfig, DEFAULT_CONFIG
from analyzer.models import LogEntry, SecurityAlert
from analyzer.utils import get_logger

from analyzer.anomaly.features import (
    FEATURE_NAMES,
    FeatureVector,
    describe_unusual_features,
    extract_feature_vectors,
)

logger = get_logger("anomaly.isolation_forest")

try:
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when sklearn missing
    IsolationForest = None  # type: ignore[misc, assignment]
    SKLEARN_AVAILABLE = False

ALERT_TYPE = "ANOMALOUS_BEHAVIOR"


def _resolve_config(
    config: AnalyzerConfig | AnomalyConfig | None,
) -> AnomalyConfig:
    if config is None:
        return DEFAULT_CONFIG.anomaly
    if isinstance(config, AnalyzerConfig):
        return config.anomaly
    return config


def decision_to_anomaly_score(decision: float) -> float:
    """Map IsolationForest decision_function to heuristic 0–100 score.

    sklearn: lower ``decision_function`` ⇒ more anomalous.
    Transform: ``score = clip(50 - 100 * decision, 0, 100)``.
    """
    return float(max(0.0, min(100.0, 50.0 - 100.0 * decision)))


def _severity_for_score(score: float) -> str:
    if score >= 90:
        return "HIGH"
    if score >= 80:
        return "HIGH"
    if score >= 70:
        return "MEDIUM"
    return "LOW"


def _heuristic_confidence(score: float, threshold: float) -> float:
    """Heuristic confidence (not a calibrated probability)."""
    if threshold <= 0:
        return min(0.95, 0.5 + score / 200.0)
    overshoot = max(0.0, score - threshold)
    return float(min(0.95, 0.55 + overshoot / 100.0 + score / 400.0))


def _local_risk(score: float) -> int:
    """Detector-local risk contribution (global engine still re-scores incidents)."""
    return int(max(20, min(85, round(score * 0.85))))


def _build_description(vector: FeatureVector, score: float, notes: list[str]) -> str:
    label = "IP" if vector.entity_type == "ip" else "user"
    lines = [
        f"Statistically unusual behavior for {label} '{vector.entity_id}' "
        f"(heuristic anomaly score {score:.0f}/100).",
        "Isolation Forest compared this entity's activity profile to others "
        "in the same dataset. This does not by itself confirm malicious activity.",
    ]
    if notes:
        lines.append("Observed relative elevations: " + "; ".join(notes) + ".")
    return " ".join(lines)


def _alert_from_vector(
    vector: FeatureVector,
    *,
    score: float,
    decision: float,
    cfg: AnomalyConfig,
    peers: Sequence[FeatureVector],
) -> SecurityAlert:
    features = vector.as_dict()
    notes = describe_unusual_features(vector, peers=peers)
    severity = _severity_for_score(score)
    timestamp = datetime.fromisoformat(vector.metadata.get("last_seen", "1970-01-01 00:00:00"))

    if vector.entity_type == "ip":
        ip_address = vector.entity_id
        username = "-"
    else:
        username = vector.entity_id
        ip_address = ""

    evidence: dict[str, Any] = {
        "model": "IsolationForest",
        "model_parameters": {
            "contamination": cfg.contamination,
            "n_estimators": cfg.n_estimators,
            "random_state": cfg.random_state,
            "minimum_samples": cfg.minimum_samples,
            "alert_threshold": cfg.alert_threshold,
        },
        "entity": vector.entity_id,
        "entity_type": vector.entity_type,
        "anomaly_score": round(score, 2),
        "decision_function": round(decision, 6),
        "features": {name: features[name] for name in FEATURE_NAMES},
        "behavioral_notes": notes,
        "score_note": (
            "anomaly_score is a heuristic transform of IsolationForest "
            "decision_function (0–100, higher = more anomalous); "
            "not an attack probability."
        ),
    }

    return SecurityAlert(
        alert_type=ALERT_TYPE,
        severity=severity,
        timestamp=timestamp,
        username=username,
        ip_address=ip_address,
        description=_build_description(vector, score, notes),
        source="anomaly",
        evidence=evidence,
        confidence=_heuristic_confidence(score, cfg.alert_threshold),
        risk_score=_local_risk(score),
        metadata={
            "detector": "isolation_forest",
            "heuristic_confidence": True,
            "ml": True,
            "entity_type": vector.entity_type,
        },
    )


def detect_anomalies(
    logs: list[LogEntry],
    config: AnalyzerConfig | AnomalyConfig | None = None,
) -> list[SecurityAlert]:
    """Run Isolation Forest on behavioral aggregates and emit anomaly alerts.

    IP and user entities are scored in **separate** models so heterogeneous
    entity types do not dilute each other.

    Safe behaviors:
    - disabled config → ``[]``
    - sklearn missing → ``[]`` (logged)
    - fewer than ``minimum_samples`` entities in a group → that group is skipped
    """
    cfg = _resolve_config(config)
    if not cfg.enabled:
        return []

    if not SKLEARN_AVAILABLE:
        logger.warning(
            "Anomaly detection skipped: scikit-learn is not installed. "
            "Deterministic detectors continue to run."
        )
        return []

    vectors = extract_feature_vectors(logs, config=cfg)
    by_type: dict[str, list[FeatureVector]] = {"ip": [], "user": []}
    for vector in vectors:
        by_type.setdefault(vector.entity_type, []).append(vector)

    alerts: list[SecurityAlert] = []
    for entity_type, group in by_type.items():
        if len(group) < cfg.minimum_samples:
            logger.info(
                "Anomaly detection skipped for %s entities: %s < minimum_samples=%s",
                entity_type,
                len(group),
                cfg.minimum_samples,
            )
            continue

        matrix = [list(v.values) for v in group]
        model = IsolationForest(
            n_estimators=cfg.n_estimators,
            contamination=cfg.contamination,
            random_state=cfg.random_state,
            n_jobs=1,
        )
        model.fit(matrix)
        decisions = model.decision_function(matrix)

        for vector, decision in zip(group, decisions):
            score = decision_to_anomaly_score(float(decision))
            if score < cfg.alert_threshold:
                continue
            alerts.append(
                _alert_from_vector(
                    vector,
                    score=score,
                    decision=float(decision),
                    cfg=cfg,
                    peers=group,
                )
            )

    alerts.sort(key=lambda a: (-float(a.evidence.get("anomaly_score", 0)), a.timestamp))
    logger.info("Isolation Forest produced %s anomaly alert(s)", len(alerts))
    return alerts
