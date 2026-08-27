"""Global incident risk scoring.

Produces an explainable 0–100 score for correlated incidents. This is
separate from detector-local ``SecurityAlert.risk_score`` values, which
reflect individual alert context only and are not summed here.
"""

from __future__ import annotations

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG, RiskScoringConfig
from analyzer.models import Incident


def _resolve_config(
    config: AnalyzerConfig | RiskScoringConfig | None,
) -> RiskScoringConfig:
    if config is None:
        return DEFAULT_CONFIG.risk_scoring
    if isinstance(config, AnalyzerConfig):
        return config.risk_scoring
    return config


def _base_for_severity(severity: str, cfg: RiskScoringConfig) -> int:
    mapping = {
        "LOW": cfg.base_low,
        "MEDIUM": cfg.base_medium,
        "HIGH": cfg.base_high,
        "CRITICAL": cfg.base_critical,
    }
    return mapping.get((severity or "").upper(), cfg.base_medium)


def score_incident(
    incident: Incident,
    config: AnalyzerConfig | RiskScoringConfig | None = None,
) -> Incident:
    """Apply global risk scoring to one incident (mutates and returns it)."""
    cfg = _resolve_config(config)
    if not cfg.enabled:
        incident.risk_score = _base_for_severity(incident.severity, cfg)
        incident.evidence = {
            **incident.evidence,
            "risk_breakdown": {
                "base_score": incident.risk_score,
                "final_score": incident.risk_score,
                "note": "global_risk_scoring_disabled",
            },
        }
        return incident

    base = _base_for_severity(incident.severity, cfg)
    breakdown: dict[str, int | float | str] = {"base_score": base}

    bonus_total = 0

    if len(incident.alerts) >= 2:
        breakdown["multiple_alert_bonus"] = cfg.multiple_alert_bonus
        bonus_total += cfg.multiple_alert_bonus

    alert_types = {a.alert_type for a in incident.alerts}
    if len(alert_types) >= 2:
        breakdown["multiple_attack_type_bonus"] = cfg.multiple_attack_type_bonus
        bonus_total += cfg.multiple_attack_type_bonus

    # Repeated activity: same alert type appearing more than once.
    type_counts: dict[str, int] = {}
    for alert in incident.alerts:
        type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
    if any(count >= 2 for count in type_counts.values()):
        breakdown["repeated_activity_bonus"] = cfg.repeated_activity_bonus
        bonus_total += cfg.repeated_activity_bonus

    privileged = {u.lower() for u in cfg.privileged_users}
    if any(user.lower() in privileged for user in incident.usernames):
        breakdown["privileged_user_bonus"] = cfg.privileged_user_bonus
        bonus_total += cfg.privileged_user_bonus

    confidences = [a.confidence for a in incident.alerts if a.confidence > 0]
    if confidences:
        avg_confidence = sum(confidences) / len(confidences)
        if avg_confidence >= cfg.high_confidence_threshold:
            breakdown["confidence_bonus"] = cfg.high_confidence_bonus
            bonus_total += cfg.high_confidence_bonus
            breakdown["average_alert_confidence"] = round(avg_confidence, 3)

    final = max(0, min(100, base + bonus_total))
    breakdown["final_score"] = final

    incident.risk_score = final
    incident.evidence = {
        **incident.evidence,
        "risk_breakdown": breakdown,
    }
    incident.metadata = {
        **incident.metadata,
        "global_risk_score": final,
        "detector_local_scores_not_summed": True,
    }
    return incident


def score_incidents(
    incidents: list[Incident],
    config: AnalyzerConfig | RiskScoringConfig | None = None,
) -> list[Incident]:
    """Score each incident and return the list sorted by risk descending."""
    scored = [score_incident(incident, config=config) for incident in incidents]
    scored.sort(key=lambda inc: (-inc.risk_score, inc.first_seen))
    return scored
