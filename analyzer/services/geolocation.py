"""Geolocation services for heuristic detectors."""

from __future__ import annotations

from dataclasses import dataclass
from math import asin, cos, radians, sin, sqrt
from typing import Mapping, Protocol


@dataclass(frozen=True)
class GeoLocation:
    """Approximate geographic point used for travel heuristics.

    Coordinates are for synthetic/demo IP mappings only. They are not a claim
    of authoritative geolocation for arbitrary public IPs.
    """

    city: str
    latitude: float
    longitude: float
    country: str = ""


class GeoLocationService(Protocol):
    """Interface for resolving an IP address to an approximate location."""

    def get_location(self, ip_address: str) -> GeoLocation | None:
        """Return a location for ``ip_address``, or ``None`` if unknown."""


# Approximate city coordinates for synthetic datasets / local testing.
_CITY_COORDS: dict[str, tuple[float, float, str]] = {
    "Mumbai": (19.0760, 72.8777, "IN"),
    "Pune": (18.5204, 73.8567, "IN"),
    "Delhi": (28.6139, 77.2090, "IN"),
    "Bengaluru": (12.9716, 77.5946, "IN"),
    "London": (51.5074, -0.1278, "GB"),
    "New York": (40.7128, -74.0060, "US"),
    "Singapore": (1.3521, 103.8198, "SG"),
}


def _loc(city: str) -> GeoLocation:
    lat, lon, country = _CITY_COORDS[city]
    return GeoLocation(city=city, latitude=lat, longitude=lon, country=country)


# Deterministic IP → city mapping for offline portfolio demos.
# These addresses are documentation/private-style ranges used by tests and
# synthetic generators — not a real IP geolocation database.
DEFAULT_IP_LOCATION_MAP: dict[str, GeoLocation] = {
    "203.0.113.10": _loc("Mumbai"),
    "203.0.113.20": _loc("Pune"),
    "203.0.113.30": _loc("Delhi"),
    "203.0.113.40": _loc("Bengaluru"),
    "198.51.100.10": _loc("London"),
    "198.51.100.50": _loc("New York"),
    "198.51.100.60": _loc("Singapore"),
    "192.0.2.10": _loc("Mumbai"),
    "192.0.2.50": _loc("New York"),
}


class StaticGeoLocationService:
    """Offline geolocation backed by a static IP map."""

    def __init__(
        self,
        ip_map: Mapping[str, GeoLocation] | None = None,
    ) -> None:
        self._ip_map = dict(ip_map if ip_map is not None else DEFAULT_IP_LOCATION_MAP)

    def get_location(self, ip_address: str) -> GeoLocation | None:
        if not ip_address:
            return None
        return self._ip_map.get(ip_address.strip())


def haversine_km(a: GeoLocation, b: GeoLocation) -> float:
    """Great-circle distance between two points in kilometres."""
    lat1, lon1, lat2, lon2 = map(
        radians,
        [a.latitude, a.longitude, b.latitude, b.longitude],
    )
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    chord = (
        sin(dlat / 2) ** 2
        + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    )
    return 2 * 6371.0 * asin(sqrt(chord))


def required_speed_kmh(distance_km: float, elapsed_seconds: float) -> float:
    """Return implied travel speed in km/h (infinite if elapsed time is zero)."""
    if elapsed_seconds <= 0:
        return float("inf")
    return distance_km / (elapsed_seconds / 3600.0)
