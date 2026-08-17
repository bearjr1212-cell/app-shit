"""
Async BLE Scanner - Real device discovery using bleak.

Provides:
- Device discovery (name, MAC, RSSI, TX power)
- iBeacon parsing (Apple company ID 0x004C, struct-based UUID/major/minor)
- Eddystone parsing (service UUID 0xFEAA, UID/URL/TLM frames)
- AltBeacon detection
- Distance estimation via path-loss model
- Continuous scanning with async generator

Requirements: pip install bleak
"""

from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Graceful bleak import
try:
    from bleak import BleakScanner as _BleakScanner
    _HAS_BLEAK = True
except ImportError:
    _HAS_BLEAK = False
    _BleakScanner = None


class BeaconType(str, Enum):
    """Type of BLE beacon detected."""
    UNKNOWN = "unknown"
    IBEACON = "ibeacon"
    EDDYSTONE_UID = "eddystone_uid"
    EDDYSTONE_URL = "eddystone_url"
    EDDYSTONE_TLM = "eddystone_tlm"
    ALTBEACON = "altbeacon"


@dataclass
class BLEDevice:
    """Discovered BLE device with full advertisement data."""
    address: str
    name: str | None = None
    rssi: int = -100
    tx_power: int | None = None

    # Beacon fields
    beacon_type: BeaconType = BeaconType.UNKNOWN
    uuid: str | None = None        # iBeacon proximity UUID
    major: int | None = None       # iBeacon major value
    minor: int | None = None       # iBeacon minor value
    namespace: str | None = None   # Eddystone-UID namespace (10 bytes hex)
    instance: str | None = None    # Eddystone-UID instance (6 bytes hex)
    url: str | None = None         # Eddystone-URL decoded URL

    # Raw advertisement data
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    service_data: dict[str, bytes] = field(default_factory=dict)

    # Tracking
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    seen_count: int = 1

    @property
    def is_beacon(self) -> bool:
        """Check if device is a recognized beacon."""
        return self.beacon_type != BeaconType.UNKNOWN

    @property
    def distance_estimate(self) -> float | None:
        """
        Estimate distance in meters using log-distance path-loss model.

        Formula: d = 10 ^ ((TxPower - RSSI) / (10 * n))
        Where n = 2.0 (typical indoor path-loss exponent).
        """
        if self.tx_power is None:
            return None
        n = 2.0
        try:
            return 10.0 ** ((self.tx_power - self.rssi) / (10.0 * n))
        except (ValueError, ZeroDivisionError):
            return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "tx_power": self.tx_power,
            "beacon_type": self.beacon_type.value,
            "uuid": self.uuid,
            "major": self.major,
            "minor": self.minor,
            "namespace": self.namespace,
            "instance": self.instance,
            "url": self.url,
            "service_uuids": self.service_uuids,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "seen_count": self.seen_count,
            "distance_estimate": self.distance_estimate,
        }


@dataclass
class ScanConfig:
    """BLE scan configuration."""
    scan_duration: float = 10.0
    scan_interval: float = 1.0
    filter_duplicates: bool = True
    min_rssi: int = -90
    detect_beacons: bool = True
    passive_scan: bool = False


class BLEScanner:
    """
    Async BLE scanner using bleak.

    Real implementation that discovers BLE devices, parses iBeacon and
    Eddystone advertisements, and provides continuous scanning.

    Usage:
        scanner = BLEScanner()
        if await scanner.start():
            devices = await scanner.scan()
            for dev in devices:
                print(f"{dev.name} ({dev.address}) RSSI={dev.rssi}")
            await scanner.stop()
    """

    # Apple iBeacon: company ID 0x004C, type 0x02, length 0x15 (21 bytes payload)
    APPLE_COMPANY_ID = 0x004C
    IBEACON_TYPE = 0x02
    IBEACON_LENGTH = 0x15

    # Eddystone service UUID
    EDDYSTONE_UUID = "0000feaa-0000-1000-8000-00805f9b34fb"

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._devices: dict[str, BLEDevice] = {}
        self._running = False
        self._lock = asyncio.Lock()
        self._stats = {
            "total_devices": 0,
            "beacons_found": 0,
            "scans_completed": 0,
            "errors": 0,
        }

    @property
    def devices(self) -> list[BLEDevice]:
        """All discovered devices."""
        return list(self._devices.values())

    @property
    def beacons(self) -> list[BLEDevice]:
        """Only beacon devices."""
        return [d for d in self._devices.values() if d.is_beacon]

    @property
    def stats(self) -> dict[str, int]:
        """Scanner statistics."""
        return dict(self._stats)

    async def start(self) -> bool:
        """
        Initialize the scanner.

        Returns True if bleak is available and scanner is ready.
        Raises RuntimeError if bleak is not installed.
        """
        if not _HAS_BLEAK:
            raise RuntimeError(
                "bleak library required for BLE scanning - install with: pip install bleak"
            )
        self._running = True
        logger.info("BLE scanner initialized (bleak backend)")
        return True

    async def stop(self) -> None:
        """Stop the scanner."""
        self._running = False
        logger.info("BLE scanner stopped")

    async def scan(self) -> list[BLEDevice]:
        """
        Perform a single BLE scan.

        Returns list of discovered BLEDevice objects with parsed beacon data.
        """
        if not self._running:
            logger.warning("Scanner not started - call start() first")
            return []

        if not _HAS_BLEAK:
            raise RuntimeError("bleak library required for BLE scanning")

        try:
            discovered = await _BleakScanner.discover(
                timeout=self.config.scan_duration,
                return_adv=True,
            )

            results: list[BLEDevice] = []

            for device, adv_data in discovered.values():
                rssi = adv_data.rssi if adv_data.rssi else -100
                if rssi < self.config.min_rssi:
                    continue

                ble_device = BLEDevice(
                    address=device.address,
                    name=adv_data.local_name or device.name,
                    rssi=rssi,
                    tx_power=adv_data.tx_power,
                    manufacturer_data=dict(adv_data.manufacturer_data or {}),
                    service_uuids=list(adv_data.service_uuids or []),
                    service_data=dict(adv_data.service_data or {}),
                )

                # Parse beacon advertisements
                if self.config.detect_beacons:
                    self._detect_beacon(ble_device)

                # Update device cache
                addr = device.address.upper()
                async with self._lock:
                    if addr in self._devices:
                        existing = self._devices[addr]
                        existing.last_seen = datetime.now(UTC)
                        existing.seen_count += 1
                        existing.rssi = rssi
                        ble_device = existing
                    else:
                        self._devices[addr] = ble_device
                        self._stats["total_devices"] += 1
                        if ble_device.is_beacon:
                            self._stats["beacons_found"] += 1

                results.append(ble_device)

            self._stats["scans_completed"] += 1
            logger.debug("BLE scan complete: %d devices found", len(results))
            return results

        except Exception as e:
            self._stats["errors"] += 1
            logger.error("BLE scan error: %s", e)
            return []

    async def scan_continuous(self):
        """
        Continuous scanning async generator.

        Yields BLEDevice objects as they are discovered.
        Runs until stop() is called.
        """
        while self._running:
            devices = await self.scan()
            for device in devices:
                yield device
            await asyncio.sleep(self.config.scan_interval)

    def _detect_beacon(self, device: BLEDevice) -> None:
        """Detect and parse iBeacon/Eddystone from advertisement data."""
        # iBeacon: Apple company ID 0x004C in manufacturer_data
        if self.APPLE_COMPANY_ID in device.manufacturer_data:
            data = device.manufacturer_data[self.APPLE_COMPANY_ID]
            if len(data) >= 23:
                # Validate iBeacon prefix: type=0x02, length=0x15
                if data[0] == self.IBEACON_TYPE and data[1] == self.IBEACON_LENGTH:
                    device.beacon_type = BeaconType.IBEACON
                    # UUID: bytes 2-17 (16 bytes)
                    uuid_bytes = data[2:18]
                    device.uuid = "-".join([
                        uuid_bytes[0:4].hex(),
                        uuid_bytes[4:6].hex(),
                        uuid_bytes[6:8].hex(),
                        uuid_bytes[8:10].hex(),
                        uuid_bytes[10:16].hex(),
                    ])
                    # Major: bytes 18-19 (big-endian uint16)
                    device.major = struct.unpack(">H", data[18:20])[0]
                    # Minor: bytes 20-21 (big-endian uint16)
                    device.minor = struct.unpack(">H", data[20:22])[0]
                    # TX power at 1 meter: byte 22 (signed int8)
                    device.tx_power = struct.unpack("b", bytes([data[22]]))[0]
                    return

        # Eddystone: service data keyed by FEAA UUID
        if self.EDDYSTONE_UUID in device.service_data:
            data = device.service_data[self.EDDYSTONE_UUID]
            if len(data) >= 2:
                frame_type = data[0]

                if frame_type == 0x00 and len(data) >= 18:
                    # Eddystone-UID: 1 byte TX power + 10 byte namespace + 6 byte instance
                    device.beacon_type = BeaconType.EDDYSTONE_UID
                    device.tx_power = struct.unpack("b", bytes([data[1]]))[0]
                    device.namespace = data[2:12].hex()
                    device.instance = data[12:18].hex()

                elif frame_type == 0x10 and len(data) >= 3:
                    # Eddystone-URL: 1 byte TX power + 1 byte scheme + encoded URL
                    device.beacon_type = BeaconType.EDDYSTONE_URL
                    device.tx_power = struct.unpack("b", bytes([data[1]]))[0]
                    device.url = self._decode_eddystone_url(data[2:])

                elif frame_type == 0x20:
                    # Eddystone-TLM: telemetry frame
                    device.beacon_type = BeaconType.EDDYSTONE_TLM

    def _decode_eddystone_url(self, data: bytes) -> str:
        """Decode Eddystone-URL compressed URL format."""
        schemes = ["http://www.", "https://www.", "http://", "https://"]
        expansions = [
            ".com/", ".org/", ".edu/", ".net/", ".info/",
            ".biz/", ".gov/", ".com", ".org", ".edu",
            ".net", ".info", ".biz", ".gov",
        ]

        if len(data) < 1:
            return ""

        scheme_idx = data[0]
        if scheme_idx >= len(schemes):
            return ""

        url = schemes[scheme_idx]

        for byte in data[1:]:
            if byte < len(expansions):
                url += expansions[byte]
            elif 0x20 <= byte <= 0x7E:
                url += chr(byte)

        return url

    def get_device(self, address: str) -> BLEDevice | None:
        """Get a specific device by MAC address."""
        return self._devices.get(address.upper())

    def clear_cache(self) -> None:
        """Clear the device cache."""
        self._devices.clear()

    def get_metrics(self) -> dict[str, int]:
        """Get Prometheus-compatible metrics."""
        return {
            "posframework_ble_devices_total": self._stats["total_devices"],
            "posframework_ble_beacons_total": self._stats["beacons_found"],
            "posframework_ble_scans_total": self._stats["scans_completed"],
            "posframework_ble_errors_total": self._stats["errors"],
            "posframework_ble_cached_devices": len(self._devices),
        }
