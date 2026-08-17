"""
GPS Module - Real-time positioning and distance tracking.

Provides:
- Async gpsd client with auto-reconnect (raw TCP, JSON protocol)
- Haversine distance calculation (great-circle distance)
- Bearing calculation between coordinates
- Distance tracker with jitter filtering and glitch detection
- Speed estimation from position updates

No external dependencies required (uses stdlib asyncio TCP + json).
"""

from __future__ import annotations

from .gpsd_client import AsyncGPSClient, GPSConfig, GPSState, GPSPosition
from .distance import haversine, calculate_bearing, DistanceTracker

__all__ = [
    "AsyncGPSClient",
    "GPSConfig",
    "GPSState",
    "GPSPosition",
    "haversine",
    "calculate_bearing",
    "DistanceTracker",
]
