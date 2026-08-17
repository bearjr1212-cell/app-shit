"""
GPS Distance Calculations - Haversine formula and distance tracking.

Provides:
- haversine(): Great-circle distance between two lat/lon points
- calculate_bearing(): Initial bearing from point A to point B
- DistanceTracker: Cumulative distance with jitter/glitch filtering

All calculations use WGS84 Earth radius (6,371,000 meters).
No external dependencies (pure math).

Usage:
    from posframework.gps.distance import haversine, DistanceTracker

    # Single distance calculation
    distance_m = haversine(40.7128, -74.0060, 34.0522, -118.2437)
    print(f"NYC to LA: {distance_m / 1000:.0f} km")

    # Track cumulative distance
    tracker = DistanceTracker()
    for lat, lon in gps_positions:
        moved = tracker.update(lat, lon)
        print(f"Moved {moved:.1f}m, total: {tracker.total_km:.2f} km")
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

# WGS84 Earth radius in meters
EARTH_RADIUS_METERS = 6_371_000


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate great-circle distance between two points using Haversine formula.

    Args:
        lat1, lon1: First point coordinates (decimal degrees)
        lat2, lon2: Second point coordinates (decimal degrees)

    Returns:
        Distance in meters (float)

    Example:
        >>> haversine(40.7128, -74.0060, 34.0522, -118.2437)  # NYC to LA
        3940000.0  # approximately 3940 km
    """
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = (
        math.sin(dlat / 2.0) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return EARTH_RADIUS_METERS * c


def calculate_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate initial bearing from point 1 to point 2.

    Args:
        lat1, lon1: Start point coordinates (decimal degrees)
        lat2, lon2: End point coordinates (decimal degrees)

    Returns:
        Bearing in degrees (0-360, where 0=North, 90=East, 180=South, 270=West)
    """
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    dlon = math.radians(lon2 - lon1)

    x = math.sin(dlon) * math.cos(lat2_rad)
    y = (
        math.cos(lat1_rad) * math.sin(lat2_rad)
        - math.sin(lat1_rad) * math.cos(lat2_rad) * math.cos(dlon)
    )

    bearing = math.degrees(math.atan2(x, y))
    return (bearing + 360.0) % 360.0


@dataclass
class DistanceTracker:
    """
    Track cumulative distance traveled from GPS position updates.

    Features:
    - Ignores small movements below threshold (GPS jitter)
    - Rejects unreasonably large jumps (GPS glitches/cold starts)
    - Calculates average speed from movement history
    - Configurable thresholds

    Usage:
        tracker = DistanceTracker(min_movement_meters=3.0)
        for lat, lon in gps_stream:
            distance = tracker.update(lat, lon)
            if distance > 0:
                print(f"Moved {distance:.1f}m, speed ~{tracker.average_speed_mps:.1f} m/s")
    """
    total_meters: float = 0.0
    last_lat: float | None = None
    last_lon: float | None = None
    min_movement_meters: float = 5.0   # Ignore GPS jitter below this
    max_jump_meters: float = 1000.0    # Reject glitches above this
    points_count: int = 0
    _distances: list[float] = field(default_factory=list)

    def update(self, lat: float, lon: float) -> float:
        """
        Update tracker with a new GPS position.

        Args:
            lat: Latitude in decimal degrees
            lon: Longitude in decimal degrees

        Returns:
            Distance moved in meters (0.0 if first point, below threshold, or glitch)
        """
        self.points_count += 1

        if self.last_lat is None or self.last_lon is None:
            self.last_lat = lat
            self.last_lon = lon
            return 0.0

        distance = haversine(self.last_lat, self.last_lon, lat, lon)

        # Ignore small movements (GPS jitter/noise)
        if distance < self.min_movement_meters:
            return 0.0

        # Reject unreasonably large jumps (GPS glitch, cold start jump)
        if distance > self.max_jump_meters:
            logger_msg = (
                f"GPS glitch rejected: {distance:.0f}m jump from "
                f"({self.last_lat:.6f}, {self.last_lon:.6f}) to ({lat:.6f}, {lon:.6f})"
            )
            # Can't use logger at module level without circular concerns,
            # just skip the point silently
            return 0.0

        self.total_meters += distance
        self._distances.append(distance)
        self.last_lat = lat
        self.last_lon = lon
        return distance

    @property
    def total_km(self) -> float:
        """Total distance traveled in kilometers."""
        return self.total_meters / 1000.0

    @property
    def average_speed_mps(self) -> float:
        """
        Average speed in meters per second.

        Assumes approximately 1 position update per second.
        For accurate speed, use GPSPosition.speed from gpsd.
        """
        if not self._distances:
            return 0.0
        return sum(self._distances) / len(self._distances)

    @property
    def max_speed_mps(self) -> float:
        """Maximum instantaneous speed observed (m/s)."""
        if not self._distances:
            return 0.0
        return max(self._distances)

    def reset(self) -> None:
        """Reset tracker to initial state."""
        self.total_meters = 0.0
        self.last_lat = None
        self.last_lon = None
        self.points_count = 0
        self._distances.clear()

    def to_dict(self) -> dict[str, Any]:
        """Export tracker state."""
        return {
            "total_meters": round(self.total_meters, 2),
            "total_km": round(self.total_km, 3),
            "points_count": self.points_count,
            "last_lat": self.last_lat,
            "last_lon": self.last_lon,
            "average_speed_mps": round(self.average_speed_mps, 2),
        }
