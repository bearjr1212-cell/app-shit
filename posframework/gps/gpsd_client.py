"""
Async gpsd Client - Real-time GPS position streaming via gpsd daemon.

Connects to gpsd (GPS daemon) over TCP and streams position updates
using the gpsd JSON protocol. Features auto-reconnect and graceful
degradation when GPS hardware is unavailable.

Protocol:
- Connect to gpsd on TCP port 2947
- Send: ?WATCH={"enable":true,"json":true}
- Receive: JSON lines (TPV, SKY, etc.)
- TPV = Time-Position-Velocity (lat, lon, alt, speed, heading)
- SKY = Satellite visibility information

No external dependencies (uses stdlib asyncio + json).

Usage:
    from posframework.gps import AsyncGPSClient

    client = AsyncGPSClient()
    async for pos in client.stream_positions():
        print(f"Lat: {pos.latitude:.6f}, Lon: {pos.longitude:.6f}")
        print(f"Speed: {pos.speed} m/s, Heading: {pos.heading} deg")
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GPSConfig:
    """gpsd connection configuration."""
    host: str = "localhost"
    port: int = 2947
    reconnect_delay: float = 5.0
    timeout: float = 10.0
    max_reconnect_attempts: int = 0  # 0 = infinite retries


@dataclass
class GPSState:
    """Internal GPS client state."""
    connected: bool = False
    fix_count: int = 0
    error_count: int = 0
    last_fix: datetime | None = None
    satellites: int = 0
    mode: int = 0  # 0=unknown, 1=no fix, 2=2D, 3=3D


@dataclass
class GPSPosition:
    """
    A GPS position fix from gpsd.

    Fields match the gpsd TPV (Time-Position-Velocity) JSON message.
    """
    latitude: float
    longitude: float
    altitude: float | None = None
    speed: float | None = None         # m/s
    heading: float | None = None       # degrees (0=North)
    climb: float | None = None         # m/s vertical speed
    hdop: float | None = None          # Horizontal dilution of precision
    vdop: float | None = None          # Vertical dilution of precision
    fix_quality: int = 0               # 0=none, 1=2D, 2=3D
    satellites: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def has_fix(self) -> bool:
        """Check if position has a valid fix (2D or 3D)."""
        return self.fix_quality >= 1

    @property
    def has_3d_fix(self) -> bool:
        """Check if position has a 3D fix (includes altitude)."""
        return self.fix_quality >= 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "speed": self.speed,
            "heading": self.heading,
            "fix_quality": self.fix_quality,
            "satellites": self.satellites,
            "hdop": self.hdop,
            "timestamp": self.timestamp.isoformat(),
        }


class AsyncGPSClient:
    """
    Async gpsd client with auto-reconnect and position streaming.

    Connects to the gpsd daemon via raw TCP (port 2947) and parses
    the JSON streaming protocol. Handles reconnection automatically
    when the connection drops.

    Usage:
        client = AsyncGPSClient(GPSConfig(host="localhost", port=2947))

        # Stream positions continuously
        async for position in client.stream_positions():
            print(f"{position.latitude}, {position.longitude}")

        # Or get a single position
        pos = await client.get_position_once(timeout=30.0)

        # Register callbacks
        client.on_position(lambda pos: print(pos.latitude))
    """

    def __init__(self, config: GPSConfig | None = None) -> None:
        self.config = config or GPSConfig()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._running = False
        self._position: GPSPosition | None = None
        self._callbacks: list[Callable[[GPSPosition], None]] = []
        self._state = GPSState()
        self._reconnect_attempts = 0

    @property
    def position(self) -> GPSPosition | None:
        """Get last known GPS position."""
        return self._position

    @property
    def has_fix(self) -> bool:
        """Check if GPS has a valid fix."""
        return self._position is not None and self._position.has_fix

    @property
    def is_connected(self) -> bool:
        """Check if connected to gpsd."""
        return self._state.connected

    @property
    def state(self) -> GPSState:
        """Get internal state for diagnostics."""
        return self._state

    def on_position(self, callback: Callable[[GPSPosition], None]) -> None:
        """Register a callback for position updates."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[GPSPosition], None]) -> None:
        """Remove a position callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    async def connect(self) -> bool:
        """
        Connect to gpsd daemon via TCP.

        Sends the WATCH command to enable JSON streaming.
        Returns True if connected successfully.
        """
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=self.config.timeout,
            )

            # Enable JSON streaming mode
            watch_cmd = b'?WATCH={"enable":true,"json":true}\n'
            self._writer.write(watch_cmd)
            await self._writer.drain()

            self._state.connected = True
            self._reconnect_attempts = 0
            logger.info("Connected to gpsd at %s:%d", self.config.host, self.config.port)
            return True

        except TimeoutError:
            logger.warning("gpsd connection timeout (%s:%d)", self.config.host, self.config.port)
            self._state.error_count += 1
            return False

        except ConnectionRefusedError:
            logger.warning("gpsd connection refused - is gpsd running?")
            self._state.error_count += 1
            return False

        except OSError as e:
            logger.warning("gpsd connection failed: %s", e)
            self._state.error_count += 1
            return False

    async def disconnect(self) -> None:
        """Disconnect from gpsd gracefully."""
        if self._writer:
            try:
                self._writer.write(b'?WATCH={"enable":false}\n')
                await self._writer.drain()
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

        self._reader = None
        self._writer = None
        self._state.connected = False

    async def stream_positions(self) -> AsyncIterator[GPSPosition]:
        """
        Async generator that yields GPS positions as they arrive.

        Handles reconnection automatically. Never raises exceptions
        to the caller - logs errors and retries.

        Yields:
            GPSPosition objects with latitude, longitude, speed, etc.
        """
        self._running = True

        while self._running:
            # Connect if needed
            if not self._reader:
                if not await self.connect():
                    self._reconnect_attempts += 1
                    if (
                        self.config.max_reconnect_attempts > 0
                        and self._reconnect_attempts >= self.config.max_reconnect_attempts
                    ):
                        logger.error("gpsd max reconnect attempts reached, stopping")
                        break
                    await asyncio.sleep(self.config.reconnect_delay)
                    continue

            # Read and parse JSON lines from gpsd
            try:
                line = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=self.config.timeout,
                )

                if not line:
                    raise ConnectionError("gpsd connection closed by server")

                data = json.loads(line.decode("utf-8"))

                # TPV (Time-Position-Velocity) messages contain position data
                if data.get("class") == "TPV":
                    pos = self._parse_tpv(data)
                    if pos:
                        self._position = pos
                        self._state.fix_count += 1
                        self._state.last_fix = datetime.now(UTC)

                        # Notify callbacks
                        for cb in self._callbacks:
                            try:
                                cb(pos)
                            except Exception as e:
                                logger.error("GPS callback error: %s", e)

                        yield pos

                # SKY messages contain satellite information
                elif data.get("class") == "SKY":
                    satellites = data.get("satellites", [])
                    self._state.satellites = len(satellites)
                    # Count satellites with signal (used in fix)
                    used = sum(1 for s in satellites if s.get("used", False))
                    self._state.satellites = used

            except TimeoutError:
                # Timeout is normal - just means no new data this interval
                logger.debug("gpsd read timeout (connection alive)")

            except json.JSONDecodeError as e:
                logger.warning("gpsd JSON parse error: %s", e)

            except (ConnectionError, OSError) as e:
                logger.warning("gpsd stream error: %s, reconnecting...", e)
                self._state.error_count += 1
                await self.disconnect()
                await asyncio.sleep(self.config.reconnect_delay)

    def _parse_tpv(self, data: dict[str, Any]) -> GPSPosition | None:
        """
        Parse a TPV (Time-Position-Velocity) JSON message from gpsd.

        Required fields: lat, lon
        Optional: alt, speed, track, climb, hdop, vdop, mode

        Returns GPSPosition if valid lat/lon present, None otherwise.
        """
        if "lat" not in data or "lon" not in data:
            return None

        try:
            # gpsd mode: 0=unknown, 1=no fix, 2=2D, 3=3D
            mode = data.get("mode", 0)
            fix_quality = max(0, mode - 1)  # Map to our 0=none, 1=2D, 2=3D

            return GPSPosition(
                latitude=float(data["lat"]),
                longitude=float(data["lon"]),
                altitude=data.get("alt"),
                speed=data.get("speed"),
                heading=data.get("track"),
                climb=data.get("climb"),
                hdop=data.get("hdop"),
                vdop=data.get("vdop"),
                fix_quality=fix_quality,
                satellites=self._state.satellites,
            )

        except (KeyError, ValueError, TypeError) as e:
            logger.error("TPV parse error: %s (data: %s)", e, data)
            return None

    async def get_position_once(self, timeout: float = 30.0) -> GPSPosition | None:
        """
        Get a single GPS position and disconnect.

        Waits up to `timeout` seconds for a valid fix.
        Returns None if no fix obtained within timeout.
        """
        try:
            deadline = asyncio.get_event_loop().time() + timeout
            async for pos in self.stream_positions():
                if pos.has_fix:
                    await self.stop()
                    return pos
                if asyncio.get_event_loop().time() >= deadline:
                    break
        except Exception as e:
            logger.warning("GPS single position error: %s", e)

        await self.stop()
        return None

    async def stop(self) -> None:
        """Stop streaming and disconnect."""
        self._running = False
        await self.disconnect()

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_gps_connected": 1 if self._state.connected else 0,
            "posframework_gps_fix_count": self._state.fix_count,
            "posframework_gps_errors": self._state.error_count,
            "posframework_gps_satellites": self._state.satellites,
        }
