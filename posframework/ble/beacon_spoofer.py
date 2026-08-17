"""
BLE Beacon Spoofing - Create fake iBeacon/Eddystone beacons.

Uses hcitool LE advertising commands to broadcast crafted beacon packets.
Supports iBeacon (Apple 0x004C format) and Eddystone-URL frames.

Requirements:
- Linux with bluez (hcitool, hciconfig)
- Root/sudo privileges for HCI advertising commands
- Bluetooth adapter (hci0 or specified)
"""

from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class BeaconType(str, Enum):
    """Beacon types supported for spoofing."""
    IBEACON = "ibeacon"
    EDDYSTONE_UID = "eddystone_uid"
    EDDYSTONE_URL = "eddystone_url"


@dataclass
class BeaconConfig:
    """Configuration for beacon advertisement."""
    beacon_type: BeaconType = BeaconType.IBEACON
    uuid: str = "E2C56DB5-DFFB-48D2-B060-D0F5A71096E0"
    major: int = 1
    minor: int = 1
    namespace: str = "EDD1EBEAC04E5DEFA017"
    instance: str = "0BDB87539B67"
    url: str = "https://example.com"
    tx_power: int = -59


class BeaconSpoofer:
    """
    BLE Beacon Spoofer using hcitool advertising.

    Builds real iBeacon and Eddystone-URL advertisement payloads and
    broadcasts them via HCI LE Set Advertising Data/Enable commands.

    Usage:
        spoofer = BeaconSpoofer(interface="hci0")
        await spoofer.start_ibeacon(
            uuid="E2C56DB5-DFFB-48D2-B060-D0F5A71096E0",
            major=100, minor=1
        )
        # Beacon is now broadcasting...
        await spoofer.stop()
    """

    def __init__(self, interface: str = "hci0"):
        self.interface = interface
        self._active = False
        self._config: BeaconConfig | None = None
        self._start_time: datetime | None = None

    def _build_ibeacon(self, uuid: str, major: int, minor: int, tx_power: int) -> bytes:
        """
        Build a complete iBeacon advertisement payload.

        Format (31 bytes max):
          02 01 06              - AD flags (LE General Discoverable + BR/EDR Not Supported)
          1a ff 4c 00           - AD length=26, type=manufacturer_specific, company=Apple
          02 15                 - iBeacon sub-type and length
          [16 bytes UUID]       - Proximity UUID
          [2 bytes major]       - Major (big-endian)
          [2 bytes minor]       - Minor (big-endian)
          [1 byte tx_power]    - Calibrated TX power at 1 meter (signed)

        Raises ValueError on invalid UUID.
        """
        try:
            uuid_bytes = bytes.fromhex(uuid.replace("-", ""))
        except ValueError as e:
            raise ValueError(f"Invalid iBeacon UUID (not valid hex): {uuid}") from e
        if len(uuid_bytes) != 16:
            raise ValueError(f"iBeacon UUID must be 16 bytes, got {len(uuid_bytes)}")

        return (
            b"\x02\x01\x06"              # AD: Flags
            b"\x1a\xff\x4c\x00"          # AD: Manufacturer Specific (Apple 0x004C)
            b"\x02\x15"                   # iBeacon prefix
            + uuid_bytes                  # 16-byte proximity UUID
            + struct.pack(">HHb", major, minor, tx_power)
        )

    def _build_eddystone_url(self, url: str) -> bytes:
        """
        Build an Eddystone-URL advertisement payload.

        Format:
          02 01 06              - AD flags
          03 03 aa fe           - Complete 16-bit service UUID list (Eddystone 0xFEAA)
          [len] 16 aa fe       - Service Data AD (Eddystone)
          10                    - Frame type: URL
          [tx_power]            - Calibrated TX power (signed)
          [scheme + encoded]    - URL scheme byte + compressed URL

        Raises ValueError if encoded advertisement exceeds 31 bytes.
        """
        encoded_url = self._encode_url(url)
        # Service data length = type(0x16) + uuid(aa fe) + frame(0x10) + txpower + url
        sd_len = len(encoded_url) + 5
        adv = (
            b"\x02\x01\x06"             # Flags
            b"\x03\x03\xaa\xfe"         # 16-bit UUID list: Eddystone
            + bytes([sd_len, 0x16])     # Service Data AD header
            + b"\xaa\xfe"               # Eddystone UUID
            + b"\x10"                   # Frame type: URL
            + struct.pack("b", -20)     # TX power at 0m
            + encoded_url               # Encoded URL
        )
        if len(adv) > 31:
            raise ValueError(
                f"Eddystone-URL advertisement exceeds 31 bytes ({len(adv)}); "
                f"shorten the URL"
            )
        return adv

    def _encode_url(self, url: str) -> bytes:
        """Encode URL using Eddystone URL compression scheme."""
        schemes = {
            "http://www.": 0,
            "https://www.": 1,
            "http://": 2,
            "https://": 3,
        }
        for prefix, code in schemes.items():
            if url.startswith(prefix):
                remainder = url[len(prefix):]
                return bytes([code]) + remainder.encode("ascii")[:17]
        # Default to https:// scheme
        return bytes([3]) + url.encode("ascii")[:17]

    async def start_ibeacon(
        self,
        uuid: str,
        major: int = 1,
        minor: int = 1,
        tx_power: int = -59,
    ) -> bool:
        """
        Start broadcasting an iBeacon advertisement.

        Args:
            uuid: 16-byte proximity UUID (hex with optional dashes)
            major: Major value (0-65535)
            minor: Minor value (0-65535)
            tx_power: Calibrated TX power at 1 meter (dBm, signed)

        Returns True if advertising started successfully.
        """
        config = BeaconConfig(
            beacon_type=BeaconType.IBEACON,
            uuid=uuid,
            major=major,
            minor=minor,
            tx_power=tx_power,
        )
        adv_data = self._build_ibeacon(uuid, major, minor, tx_power)
        return await self._advertise(adv_data, config)

    async def start_eddystone_url(self, url: str) -> bool:
        """
        Start broadcasting an Eddystone-URL beacon.

        Args:
            url: URL to broadcast (will be compressed per Eddystone spec)

        Returns True if advertising started successfully.
        """
        config = BeaconConfig(beacon_type=BeaconType.EDDYSTONE_URL, url=url)
        adv_data = self._build_eddystone_url(url)
        return await self._advertise(adv_data, config)

    async def _advertise(self, data: bytes, config: BeaconConfig) -> bool:
        """Send HCI commands to start LE advertising with given payload."""
        await self.stop()

        try:
            # Bring up the HCI interface
            await self._cmd(["hciconfig", self.interface, "up"])

            # Set advertising data via HCI command:
            # OGF=0x08 (LE Controller), OCF=0x0008 (LE Set Advertising Data)
            hex_data = " ".join(f"{b:02x}" for b in data)
            await self._cmd([
                "hcitool", "-i", self.interface, "cmd",
                "0x08", "0x0008",
                f"{len(data):02x}", *hex_data.split()
            ])

            # Enable advertising:
            # OGF=0x08, OCF=0x000a (LE Set Advertise Enable), 01=enable
            await self._cmd([
                "hcitool", "-i", self.interface, "cmd",
                "0x08", "0x000a", "01"
            ])

            self._active = True
            self._config = config
            self._start_time = datetime.now(UTC)
            logger.info(
                "Beacon advertising started: %s on %s",
                config.beacon_type.value, self.interface
            )
            return True

        except Exception as e:
            logger.error("Beacon advertising failed: %s", e)
            return False

    async def stop(self) -> None:
        """Stop beacon advertising."""
        if self._active:
            # Disable advertising: OCF=0x000a, 00=disable
            await self._cmd([
                "hcitool", "-i", self.interface, "cmd",
                "0x08", "0x000a", "00"
            ])
            self._active = False
            self._config = None
            logger.info("Beacon advertising stopped on %s", self.interface)

    async def _cmd(self, cmd: list[str]) -> tuple[bytes, bytes]:
        """Execute a shell command and return stdout/stderr."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr

    @property
    def is_active(self) -> bool:
        """Check if beacon is currently advertising."""
        return self._active

    @property
    def current_config(self) -> BeaconConfig | None:
        """Get current beacon configuration."""
        return self._config

    def get_metrics(self) -> dict[str, Any]:
        """Get metrics for monitoring."""
        return {
            "posframework_beacon_active": 1 if self._active else 0,
            "posframework_beacon_type": self._config.beacon_type.value if self._config else "none",
        }
