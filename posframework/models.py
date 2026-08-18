"""
POSFramework Domain Models - Dataclass models for core entities.

These replace Pydantic models from MoMo with stdlib-only dataclasses,
preserving validation logic in __post_init__ where needed.

Models:
- EncryptionType: WiFi encryption type enum
- AccessPoint: Detected WiFi access point
- Client: Discovered WiFi client device
- Handshake: Captured WPA handshake data
- Credential: Captured credential from attack
- Target: Attack target with scoring data
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# MAC address regex pattern for validation
_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _now_utc() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


class EncryptionType(str, Enum):
    """WiFi encryption types."""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    WPA2_ENTERPRISE = "wpa2-enterprise"
    OWE = "owe"  # Opportunistic Wireless Encryption


class CaptureType(str, Enum):
    """Type of WiFi handshake capture."""
    PMKID = "pmkid"
    EAPOL = "eapol"
    EAPOL_M2 = "eapol_m2"
    UNKNOWN = "unknown"


class CaptureStatus(str, Enum):
    """Status of a capture operation."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TargetStatus(str, Enum):
    """Target attack status."""
    PENDING = "pending"
    SCANNING = "scanning"
    ATTACKING = "attacking"
    CAPTURED = "captured"
    CRACKED = "cracked"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AccessPoint:
    """Detected WiFi access point."""

    bssid: str
    ssid: str = "<hidden>"
    channel: int = 1
    rssi: int = -100  # dBm
    encryption: EncryptionType = EncryptionType.OPEN
    wps_enabled: bool = False
    vendor: str | None = None
    clients_count: int = 0
    first_seen: datetime = field(default_factory=_now_utc)
    last_seen: datetime = field(default_factory=_now_utc)
    frequency: int = 0  # MHz

    # Best signal tracking
    best_rssi: int = -100

    def __post_init__(self) -> None:
        """Validate fields after initialization."""
        if not _MAC_PATTERN.match(self.bssid):
            raise ValueError(f"Invalid BSSID format: {self.bssid}")
        if not -100 <= self.rssi <= 0:
            import logging
            logging.getLogger("POSFramework").warning(
                f"AccessPoint RSSI {self.rssi} out of range [-100, 0] for {self.bssid}, clamping"
            )
            self.rssi = max(-100, min(0, self.rssi))
        if not 1 <= self.channel <= 165:
            import logging
            logging.getLogger("POSFramework").warning(
                f"AccessPoint channel {self.channel} out of range [1, 165] for {self.bssid}, clamping"
            )
            self.channel = max(1, min(165, self.channel))
        if len(self.ssid) > 32:
            self.ssid = self.ssid[:32]

    @property
    def is_hidden(self) -> bool:
        """Check if SSID is hidden/empty."""
        return not self.ssid or self.ssid in ("<hidden>", "\\x00", "")

    @property
    def is_5ghz(self) -> bool:
        """Check if AP is on 5GHz band."""
        return self.channel > 14 or self.frequency > 5000

    @property
    def signal_quality(self) -> int:
        """Convert RSSI to percentage (0-100)."""
        if self.rssi >= -50:
            return 100
        elif self.rssi <= -100:
            return 0
        else:
            return 2 * (self.rssi + 100)


@dataclass
class Client:
    """Discovered WiFi client device."""

    mac: str
    vendor: str | None = None
    associated_bssid: str | None = None
    rssi: int = -100
    probed_ssids: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=_now_utc)
    last_seen: datetime = field(default_factory=_now_utc)
    packets_count: int = 0

    def __post_init__(self) -> None:
        """Validate MAC address format."""
        if not _MAC_PATTERN.match(self.mac):
            raise ValueError(f"Invalid MAC format: {self.mac}")
        if self.associated_bssid and not _MAC_PATTERN.match(self.associated_bssid):
            raise ValueError(f"Invalid associated BSSID format: {self.associated_bssid}")


@dataclass
class Handshake:
    """Captured WiFi handshake data."""

    bssid: str
    ssid: str = "<hidden>"
    capture_type: CaptureType = CaptureType.UNKNOWN
    status: CaptureStatus = CaptureStatus.PENDING

    # File paths
    pcap_path: str | None = None
    hashcat_path: str | None = None  # .22000 file

    # Capture details
    channel: int = 0
    client_mac: str | None = None
    eapol_count: int = 0
    pmkid_found: bool = False

    # Timestamps
    started_at: datetime = field(default_factory=_now_utc)
    completed_at: datetime | None = None

    # Cracking status
    cracked: bool = False
    password: str | None = None
    cracked_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate BSSID format."""
        if not _MAC_PATTERN.match(self.bssid):
            raise ValueError(f"Invalid BSSID format: {self.bssid}")

    @property
    def is_valid(self) -> bool:
        """Check if capture contains valid handshake data."""
        return (
            self.status == CaptureStatus.SUCCESS
            and (self.pmkid_found or self.eapol_count >= 2)
        )

    @property
    def is_crackable(self) -> bool:
        """Check if capture can be submitted for cracking."""
        return self.is_valid and self.hashcat_path is not None and not self.cracked


@dataclass
class Credential:
    """Captured credential from evil twin / MITM attack."""

    client_ip: str = ""
    client_mac: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    timestamp: datetime = field(default_factory=_now_utc)
    user_agent: str = ""
    target_ssid: str = ""
    protocol: str = ""  # http, ftp, smtp, etc.


@dataclass
class Target:
    """Attack target with scoring and status tracking."""

    id: str = ""
    ssid: str = ""
    bssid: str = ""
    channel: int = 6
    encryption: EncryptionType = EncryptionType.WPA2
    signal_dbm: int = -100
    status: TargetStatus = TargetStatus.PENDING
    priority: int = 0  # Higher = more important
    client_count: int = 0
    active_clients: list[str] = field(default_factory=list)
    attack_attempts: int = 0
    handshake_captured: bool = False
    pmkid_captured: bool = False
    password: str | None = None
    vendor: str | None = None
    first_seen: datetime = field(default_factory=_now_utc)
    last_seen: datetime = field(default_factory=_now_utc)
    score: float = 0.0

    def __post_init__(self) -> None:
        """Validate and set defaults."""
        if self.bssid and not _MAC_PATTERN.match(self.bssid):
            raise ValueError(f"Invalid BSSID format: {self.bssid}")
        # Auto-generate ID if not provided
        if not self.id and self.bssid:
            self.id = self.bssid.replace(":", "").lower()

    @property
    def is_cracked(self) -> bool:
        """Check if target password has been recovered."""
        return self.password is not None

    @property
    def needs_handshake(self) -> bool:
        """Check if target still needs handshake capture."""
        return (
            self.encryption in (EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA3)
            and not self.handshake_captured
            and not self.pmkid_captured
        )
