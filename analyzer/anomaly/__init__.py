"""Optional ML anomaly detection (Isolation Forest).

Separated from deterministic signature detectors in ``analyzer.detectors``.
Rule-based detection finds known attack patterns; this package finds
statistically unusual behavioral aggregates. Anomalies do not prove
malicious intent.
"""

from __future__ import annotations

from analyzer.anomaly.features import (
    FEATURE_NAMES,
    FeatureVector,
    extract_feature_vectors,
)
from analyzer.anomaly.isolation_forest import (
    SKLEARN_AVAILABLE,
    detect_anomalies,
)

__all__ = [
    "FEATURE_NAMES",
    "FeatureVector",
    "SKLEARN_AVAILABLE",
    "detect_anomalies",
    "extract_feature_vectors",
]
