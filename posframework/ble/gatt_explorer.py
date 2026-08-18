"""
BLE GATT Explorer - Connect and enumerate device services/characteristics.

GATT (Generic Attribute Profile) hierarchy:
- Services: Groups of characteristics (e.g., Heart Rate Service 0x180D)
- Characteristics: Data points with properties (read/write/notify)
- Descriptors: Metadata about characteristics

This module enables:
- Full service discovery on connected devices
- Characteristic value reading/writing
- Notification subscription for real-time data
- Security assessment (finding writable/notifiable characteristics)

Requirements: pip install bleak
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

UTC = timezone.utc
from typing import Any

logger = logging.getLogger(__name__)

# Graceful bleak import
try:
    from bleak import BleakClient
    from bleak.exc import BleakError
    _HAS_BLEAK = True
except ImportError:
    _HAS_BLEAK = False
    BleakClient = None  # type: ignore[assignment, misc]
    BleakError = Exception  # type: ignore[assignment, misc]


# Well-known GATT service UUIDs
KNOWN_SERVICES: dict[str, str] = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Mi Band Service",
    "0000fff0-0000-1000-8000-00805f9b34fb": "Custom Service (Common)",
}


@dataclass
class GATTCharacteristic:
    """A GATT characteristic with its properties and value."""
    uuid: str
    handle: int
    properties: list[str]
    value: bytes | None = None
    value_hex: str = ""
    value_str: str = ""
    descriptors: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_readable(self) -> bool:
        return "read" in self.properties

    @property
    def is_writable(self) -> bool:
        return "write" in self.properties or "write-without-response" in self.properties

    @property
    def is_notifiable(self) -> bool:
        return "notify" in self.properties or "indicate" in self.properties

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "handle": self.handle,
            "properties": self.properties,
            "is_readable": self.is_readable,
            "is_writable": self.is_writable,
            "is_notifiable": self.is_notifiable,
            "value_hex": self.value_hex,
            "value_str": self.value_str,
            "descriptors": self.descriptors,
        }


@dataclass
class GATTService:
    """A GATT service containing characteristics."""
    uuid: str
    handle: int
    characteristics: list[GATTCharacteristic] = field(default_factory=list)

    @property
    def name(self) -> str:
        """Resolve well-known service name or 'Unknown'."""
        return KNOWN_SERVICES.get(self.uuid.lower(), "Unknown Service")

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "handle": self.handle,
            "characteristics": [c.to_dict() for c in self.characteristics],
        }


@dataclass
class DeviceProfile:
    """Complete GATT profile of a connected BLE device."""
    address: str
    name: str | None = None
    connected: bool = False
    services: list[GATTService] = field(default_factory=list)
    writable_chars: int = 0
    readable_chars: int = 0
    notifiable_chars: int = 0
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "connected": self.connected,
            "services_count": len(self.services),
            "writable_chars": self.writable_chars,
            "readable_chars": self.readable_chars,
            "notifiable_chars": self.notifiable_chars,
            "services": [s.to_dict() for s in self.services],
            "discovered_at": self.discovered_at.isoformat(),
        }


class GATTExplorer:
    """
    BLE GATT Explorer - enumerate services and interact with characteristics.

    Connects to a BLE device and discovers all GATT services, reads
    characteristic values, and can write data or subscribe to notifications.

    Usage:
        explorer = GATTExplorer(timeout=15.0)

        # Full device exploration
        profile = await explorer.explore("AA:BB:CC:DD:EE:FF")
        for svc in profile.services:
            print(f"Service: {svc.name} ({svc.uuid})")
            for char in svc.characteristics:
                print(f"  {char.uuid}: {char.properties} = {char.value_hex}")

        # Direct read/write
        value = await explorer.read_characteristic("AA:BB:CC:DD:EE:FF", "00002a00-...")
        await explorer.write_characteristic("AA:BB:CC:DD:EE:FF", "00002a00-...", b"\\x01")
    """

    def __init__(self, timeout: float = 10.0):
        if not _HAS_BLEAK:
            raise RuntimeError(
                "bleak library required for GATT exploration - install with: pip install bleak"
            )
        self.timeout = timeout
        self._profiles: dict[str, DeviceProfile] = {}
        self._stats = {
            "devices_explored": 0,
            "services_found": 0,
            "chars_found": 0,
            "reads_total": 0,
            "writes_total": 0,
        }

    async def explore(self, address: str, read_values: bool = True) -> DeviceProfile:
        """
        Connect to device and enumerate all GATT services/characteristics.

        Args:
            address: BLE device MAC address
            read_values: If True, reads all readable characteristic values

        Returns:
            DeviceProfile with full GATT structure
        """
        profile = DeviceProfile(address=address)

        try:
            async with BleakClient(address, timeout=self.timeout) as client:
                profile.connected = True
                profile.name = getattr(client, 'name', None)

                for service in client.services:
                    gatt_service = GATTService(
                        uuid=str(service.uuid),
                        handle=service.handle,
                    )

                    for char in service.characteristics:
                        gatt_char = GATTCharacteristic(
                            uuid=str(char.uuid),
                            handle=char.handle,
                            properties=list(char.properties),
                        )

                        # Read value if readable and requested
                        if read_values and gatt_char.is_readable:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                gatt_char.value = value
                                gatt_char.value_hex = value.hex()
                                gatt_char.value_str = self._try_decode(value)
                                self._stats["reads_total"] += 1
                            except Exception as e:
                                logger.debug("Read failed for %s: %s", char.uuid, e)

                        # Enumerate descriptors
                        for desc in char.descriptors:
                            gatt_char.descriptors.append({
                                "uuid": str(desc.uuid),
                                "handle": desc.handle,
                            })

                        # Update counters
                        if gatt_char.is_readable:
                            profile.readable_chars += 1
                        if gatt_char.is_writable:
                            profile.writable_chars += 1
                        if gatt_char.is_notifiable:
                            profile.notifiable_chars += 1

                        gatt_service.characteristics.append(gatt_char)
                        self._stats["chars_found"] += 1

                    profile.services.append(gatt_service)
                    self._stats["services_found"] += 1

                self._stats["devices_explored"] += 1

        except Exception as e:
            logger.error("GATT explore failed for %s: %s", address, e)
            profile.connected = False

        self._profiles[address] = profile
        return profile

    async def read_characteristic(self, address: str, char_uuid: str) -> bytes | None:
        """Read a single characteristic value from a device."""
        try:
            async with BleakClient(address, timeout=self.timeout) as client:
                value = await client.read_gatt_char(char_uuid)
                self._stats["reads_total"] += 1
                return value
        except Exception as e:
            logger.error("Characteristic read failed (%s on %s): %s", char_uuid, address, e)
            return None

    async def write_characteristic(
        self,
        address: str,
        char_uuid: str,
        data: bytes,
        response: bool = True,
    ) -> bool:
        """
        Write data to a characteristic.

        Args:
            address: Device MAC address
            char_uuid: Target characteristic UUID
            data: Bytes to write
            response: If True, waits for write response (False for write-without-response)

        Returns True on success.
        """
        try:
            async with BleakClient(address, timeout=self.timeout) as client:
                await client.write_gatt_char(char_uuid, data, response=response)
                self._stats["writes_total"] += 1
                logger.info("Wrote %d bytes to %s on %s", len(data), char_uuid, address)
                return True
        except Exception as e:
            logger.error("Characteristic write failed: %s", e)
            return False

    async def subscribe_notifications(
        self,
        address: str,
        char_uuid: str,
        duration: float = 10.0,
    ) -> list[bytes]:
        """
        Subscribe to characteristic notifications for a duration.

        Returns list of all notification payloads received.
        """
        notifications: list[bytes] = []

        def _callback(sender: int, data: bytes) -> None:
            notifications.append(data)
            logger.debug("Notification from handle %s: %s", sender, data.hex())

        try:
            async with BleakClient(address, timeout=self.timeout) as client:
                await client.start_notify(char_uuid, _callback)
                await asyncio.sleep(duration)
                await client.stop_notify(char_uuid)
        except Exception as e:
            logger.error("Notification subscription failed: %s", e)

        return notifications

    def get_profile(self, address: str) -> DeviceProfile | None:
        """Get cached device profile."""
        return self._profiles.get(address)

    def _try_decode(self, data: bytes) -> str:
        """Attempt to decode bytes as printable UTF-8 string."""
        try:
            text = data.decode("utf-8", errors="ignore")
            return "".join(c for c in text if c.isprintable())
        except Exception:
            return ""

    def get_stats(self) -> dict[str, Any]:
        """Get explorer statistics."""
        return self._stats.copy()

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_gatt_devices_explored": self._stats["devices_explored"],
            "posframework_gatt_services_found": self._stats["services_found"],
            "posframework_gatt_chars_found": self._stats["chars_found"],
            "posframework_gatt_reads": self._stats["reads_total"],
            "posframework_gatt_writes": self._stats["writes_total"],
        }
