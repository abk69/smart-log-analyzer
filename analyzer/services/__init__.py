"""Service-layer helpers for the analyzer."""

from analyzer.services.analysis_service import AnalysisService, DetectorSpec, deduplicate_alerts
from analyzer.services.geolocation import (
    DEFAULT_IP_LOCATION_MAP,
    GeoLocation,
    GeoLocationService,
    StaticGeoLocationService,
    haversine_km,
    required_speed_kmh,
)

__all__ = [
    "AnalysisService",
    "DEFAULT_IP_LOCATION_MAP",
    "DetectorSpec",
    "GeoLocation",
    "GeoLocationService",
    "StaticGeoLocationService",
    "deduplicate_alerts",
    "haversine_km",
    "required_speed_kmh",
]
