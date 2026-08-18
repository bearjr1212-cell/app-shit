"""
WPA3 Detector - Identify WPA3/SAE capabilities from beacon/probe frames.

Parses RSN (Robust Security Network) Information Elements to detect:
- WPA3-Personal (SAE): AKM suite type 8 (00-0f-ac:8)
- WPA3-Enterprise (Suite-B 192): AKM suite type 12
- Transition Mode: Both PSK (type 2) and SAE (type 8) in same RSN IE
- PMF status: RSN Capabilities field bit 6 (capable) and bit 7 (required)
- OWE: AKM suite type 18 (00-0f-ac:18)

Uses `iw dev <iface> scan` output parsing for detection.
No external Python dependencies.

RSN IE Structure (IEEE 802.11-2020, Section 9.4.2.25.2):
  Element ID: 48 (0x30)
  Version: 2 bytes (always 1)
  Group Data Cipher Suite: 4 bytes
  Pairwise Cipher Suite Count: 2 bytes
  Pairwise Cipher Suites: 4 bytes each
  AKM Suite Count: 2 bytes
  AKM Suites: 4 bytes each (OUI 00-0f-ac + type)
  RSN Capabilities: 2 bytes
    - Bit 6: Management Frame Protection Capable (MFPC)
    - Bit 7: Management Frame Protection Required (MFPR)
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

UTC = timezone.utc
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SAEStatus(str, Enum):
    """SAE (WPA3-Personal) support status."""
    NOT_SUPPORTED = "not_supported"
    SUPPORTED = "supported"
    REQUIRED = "required"       # SAE only, no WPA2 fallback
    TRANSITION = "transition"   # SAE + WPA2 (downgrade possible)


class PMFStatus(str, Enum):
    """Protected Management Frames (802.11w) status."""
    DISABLED = "disabled"       # No PMF (vulnerable to deauth)
    OPTIONAL = "optional"       # PMF capable but not required
    REQUIRED = "required"       # PMF mandatory (deauth blocked)


class WPA3Mode(str, Enum):
    """WPA3 operation modes."""
    NONE = "none"
    PERSONAL = "personal"            # WPA3-SAE only
    ENTERPRISE = "enterprise"        # WPA3-Enterprise/Suite-B
    TRANSITION = "transition"        # WPA3 + WPA2 mixed mode
    OWE = "owe"                      # Opportunistic Wireless Encryption
    OWE_TRANSITION = "owe_transition"


@dataclass
class WPA3Capabilities:
    """
    WPA3 security capabilities of an access point.

    Key properties for attack planning:
    - is_downgradable: True if WPA3->WPA2 downgrade attack is possible
    - is_vulnerable_to_deauth: True if PMF is not required
    - attack_recommendations: List of recommended attack vectors
    """
    bssid: str
    ssid: str

    # WPA3 status
    wpa3_mode: WPA3Mode = WPA3Mode.NONE
    sae_status: SAEStatus = SAEStatus.NOT_SUPPORTED

    # PMF status (determines if deauth attacks work)
    pmf_status: PMFStatus = PMFStatus.DISABLED

    # Transition mode (primary attack vector)
    transition_mode: bool = False
    wpa2_available: bool = False

    # OWE (Enhanced Open)
    owe_supported: bool = False
    owe_transition: bool = False

    # Additional
    mfp_capable: bool = False
    sha384: bool = False
    rsn_capabilities: int = 0
    akm_suites: list[str] = field(default_factory=list)

    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_vulnerable_to_deauth(self) -> bool:
        """AP is vulnerable to deauth if PMF is not required."""
        return self.pmf_status != PMFStatus.REQUIRED

    @property
    def is_downgradable(self) -> bool:
        """WPA3 to WPA2 downgrade is possible in transition mode."""
        return self.transition_mode and self.wpa2_available

    @property
    def attack_recommendations(self) -> list[str]:
        """Generate attack recommendations based on capabilities."""
        attacks = []

        if self.is_downgradable:
            attacks.append("DOWNGRADE: Force WPA2 association, capture PMKID/handshake")

        if self.is_vulnerable_to_deauth:
            attacks.append("DEAUTH: PMF not required, standard deauth effective")

        if self.sae_status in (SAEStatus.SUPPORTED, SAEStatus.TRANSITION):
            attacks.append("SAE_FLOOD: DoS via SAE commit frame flooding (Dragonblood)")

        if self.owe_transition:
            attacks.append("OWE_DOWNGRADE: Force open network association")

        if not attacks:
            attacks.append("LIMITED: Pure WPA3 with PMF required, minimal attack surface")

        return attacks

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "wpa3_mode": self.wpa3_mode.value,
            "sae_status": self.sae_status.value,
            "pmf_status": self.pmf_status.value,
            "transition_mode": self.transition_mode,
            "wpa2_available": self.wpa2_available,
            "owe_supported": self.owe_supported,
            "is_vulnerable_to_deauth": self.is_vulnerable_to_deauth,
            "is_downgradable": self.is_downgradable,
            "attack_recommendations": self.attack_recommendations,
            "akm_suites": self.akm_suites,
            "detected_at": self.detected_at.isoformat(),
        }


class WPA3Detector:
    """
    WPA3/SAE Capability Detector.

    Scans for WiFi networks and parses RSN Information Elements to
    determine WPA3 support, PMF status, and transition mode.

    Detection method:
    1. Run `iw dev <interface> scan` to get beacon/probe data
    2. Parse RSN IE for AKM suite types:
       - Type 2 (00-0f-ac:2) = WPA2-PSK
       - Type 8 (00-0f-ac:8) = WPA3-SAE
       - Type 9 (00-0f-ac:9) = FT-SAE
       - Type 12 (00-0f-ac:12) = Suite-B 192
       - Type 18 (00-0f-ac:18) = OWE
    3. Parse RSN Capabilities for PMF bits:
       - Bit 6 = MFPC (Management Frame Protection Capable)
       - Bit 7 = MFPR (Management Frame Protection Required)

    Usage:
        detector = WPA3Detector("wlan0mon")
        await detector.start()
        networks = await detector.scan_all()
        for net in networks:
            if net.is_downgradable:
                print(f"VULNERABLE: {net.ssid} supports downgrade attack!")
    """

    # AKM Suite Type identifiers (OUI 00-0f-ac)
    AKM_PSK = "00-0f-ac:2"
    AKM_SAE = "00-0f-ac:8"
    AKM_FT_SAE = "00-0f-ac:9"
    AKM_SAE_EXT = "00-0f-ac:24"
    AKM_OWE = "00-0f-ac:18"
    AKM_SUITE_B = "00-0f-ac:12"

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self._running = False
        self._cache: dict[str, WPA3Capabilities] = {}
        self._stats = {
            "scans_total": 0,
            "wpa3_found": 0,
            "transition_mode_found": 0,
            "pmf_required_found": 0,
        }

    async def start(self) -> bool:
        """Initialize detector."""
        self._running = True
        logger.info("WPA3 detector started on %s", self.interface)
        return True

    async def stop(self) -> None:
        """Stop detector."""
        self._running = False

    async def scan_all(self) -> list[WPA3Capabilities]:
        """
        Scan for all visible APs and detect WPA3 capabilities.

        Runs `iw dev <interface> scan` and parses the output.
        Returns list of WPA3Capabilities for all detected networks.
        """
        if not self._running:
            await self.start()

        self._stats["scans_total"] += 1

        try:
            proc = await asyncio.create_subprocess_exec(
                "iw", "dev", self.interface, "scan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)

            if proc.returncode != 0:
                logger.error("iw scan failed (rc=%d): %s", proc.returncode, stderr.decode())
                return []

            return self._parse_scan_output(stdout.decode())

        except TimeoutError:
            logger.error("iw scan timed out after 30s")
            return []
        except FileNotFoundError:
            logger.error("iw command not found - install iw (apt install iw)")
            return []
        except Exception as e:
            logger.error("WPA3 scan error: %s", e)
            return []

    async def detect_ap(self, bssid: str) -> WPA3Capabilities | None:
        """
        Detect WPA3 capabilities for a specific AP.

        Checks cache first (60s TTL), then performs full scan.
        """
        # Check cache
        bssid_upper = bssid.upper()
        if bssid_upper in self._cache:
            cached = self._cache[bssid_upper]
            age = (datetime.now(UTC) - cached.detected_at).total_seconds()
            if age < 60:
                return cached

        # Full scan
        all_caps = await self.scan_all()
        for caps in all_caps:
            if caps.bssid.upper() == bssid_upper:
                self._cache[bssid_upper] = caps
                return caps

        return None

    def _parse_scan_output(self, output: str) -> list[WPA3Capabilities]:
        """Parse iw scan output and extract WPA3 capabilities."""
        results: list[WPA3Capabilities] = []

        current_bssid = ""
        current_ssid = ""
        current_akm: list[str] = []
        has_wpa2 = False
        has_wpa3 = False
        pmf_capable = False
        pmf_required = False
        has_owe = False
        has_owe_transition = False

        for line in output.splitlines():
            stripped = line.strip()

            # New BSS entry
            if stripped.startswith("BSS "):
                # Save previous AP
                if current_bssid:
                    caps = self._build_capabilities(
                        current_bssid, current_ssid, current_akm,
                        has_wpa2, has_wpa3, pmf_capable, pmf_required,
                        has_owe, has_owe_transition,
                    )
                    results.append(caps)
                    self._cache[caps.bssid] = caps
                    self._update_stats(caps)

                # Parse BSSID from "BSS aa:bb:cc:dd:ee:ff(on wlan0)"
                match = re.search(r"([0-9a-fA-F:]{17})", stripped)
                current_bssid = match.group(1).upper() if match else ""
                current_ssid = ""
                current_akm = []
                has_wpa2 = False
                has_wpa3 = False
                pmf_capable = False
                pmf_required = False
                has_owe = False
                has_owe_transition = False

            elif stripped.startswith("SSID:"):
                ssid = stripped[5:].strip()
                if ssid:
                    current_ssid = ssid

            # Detect AKM suites in iw output
            elif "Authentication suites:" in stripped or "* Authentication" in stripped:
                if "PSK" in stripped:
                    has_wpa2 = True
                    if "PSK" not in current_akm:
                        current_akm.append("PSK")
                if "SAE" in stripped:
                    has_wpa3 = True
                    if "SAE" not in current_akm:
                        current_akm.append("SAE")
                if "OWE" in stripped:
                    has_owe = True
                    if "OWE" not in current_akm:
                        current_akm.append("OWE")

            # AKM suite OUI-based detection
            elif "00-0f-ac:2" in stripped:
                has_wpa2 = True
                if "PSK" not in current_akm:
                    current_akm.append("PSK")
            elif "00-0f-ac:8" in stripped:
                has_wpa3 = True
                if "SAE" not in current_akm:
                    current_akm.append("SAE")
            elif "00-0f-ac:18" in stripped:
                has_owe = True
                if "OWE" not in current_akm:
                    current_akm.append("OWE")

            # OWE Transition Mode: WFA vendor IE (OUI 50:6f:9a, type 0x1c)
            elif "50:6f:9a" in stripped.lower() and re.search(
                r"data:\s*1c\b", stripped.lower()
            ):
                has_owe_transition = True

            # PMF detection from RSN Capabilities line
            elif "Capabilities:" in stripped:
                if "MFPC" in stripped or "MFP capable" in stripped:
                    pmf_capable = True
                if "MFPR" in stripped or "MFP required" in stripped:
                    pmf_required = True

            elif "management frame protection" in stripped.lower():
                if "required" in stripped.lower():
                    pmf_required = True
                elif "capable" in stripped.lower():
                    pmf_capable = True

        # Save last AP
        if current_bssid:
            caps = self._build_capabilities(
                current_bssid, current_ssid, current_akm,
                has_wpa2, has_wpa3, pmf_capable, pmf_required,
                has_owe, has_owe_transition,
            )
            results.append(caps)
            self._cache[caps.bssid] = caps
            self._update_stats(caps)

        return results

    def _build_capabilities(
        self,
        bssid: str,
        ssid: str,
        akm_suites: list[str],
        has_wpa2: bool,
        has_wpa3: bool,
        pmf_capable: bool,
        pmf_required: bool,
        has_owe: bool,
        has_owe_transition: bool = False,
    ) -> WPA3Capabilities:
        """Build WPA3Capabilities from parsed fields."""
        # Determine WPA3 mode
        if has_wpa3 and has_wpa2:
            wpa3_mode = WPA3Mode.TRANSITION
        elif has_wpa3:
            wpa3_mode = WPA3Mode.PERSONAL
        elif has_owe and has_owe_transition:
            wpa3_mode = WPA3Mode.OWE_TRANSITION
        elif has_owe:
            wpa3_mode = WPA3Mode.OWE
        else:
            wpa3_mode = WPA3Mode.NONE

        # SAE status
        if has_wpa3 and has_wpa2:
            sae_status = SAEStatus.TRANSITION
        elif has_wpa3:
            sae_status = SAEStatus.REQUIRED
        elif has_wpa3 and not has_wpa2:
            sae_status = SAEStatus.SUPPORTED
        else:
            sae_status = SAEStatus.NOT_SUPPORTED

        # PMF status
        if pmf_required:
            pmf_status = PMFStatus.REQUIRED
        elif pmf_capable:
            pmf_status = PMFStatus.OPTIONAL
        else:
            pmf_status = PMFStatus.DISABLED

        return WPA3Capabilities(
            bssid=bssid,
            ssid=ssid,
            wpa3_mode=wpa3_mode,
            sae_status=sae_status,
            pmf_status=pmf_status,
            transition_mode=(has_wpa3 and has_wpa2),
            wpa2_available=has_wpa2,
            owe_supported=has_owe or has_owe_transition,
            owe_transition=has_owe_transition,
            mfp_capable=pmf_capable,
            akm_suites=akm_suites,
        )

    def _update_stats(self, caps: WPA3Capabilities) -> None:
        """Update detection statistics."""
        if caps.wpa3_mode != WPA3Mode.NONE:
            self._stats["wpa3_found"] += 1
        if caps.transition_mode:
            self._stats["transition_mode_found"] += 1
        if caps.pmf_status == PMFStatus.REQUIRED:
            self._stats["pmf_required_found"] += 1

    def get_stats(self) -> dict[str, Any]:
        """Get detection statistics."""
        return self._stats.copy()

    def get_wpa3_networks(self) -> list[WPA3Capabilities]:
        """Get all cached WPA3 networks."""
        return [c for c in self._cache.values() if c.wpa3_mode != WPA3Mode.NONE]

    def get_downgradable_networks(self) -> list[WPA3Capabilities]:
        """Get networks vulnerable to WPA3->WPA2 downgrade."""
        return [c for c in self._cache.values() if c.is_downgradable]

    def get_deauth_vulnerable(self) -> list[WPA3Capabilities]:
        """Get networks vulnerable to deauth (PMF not required)."""
        return [c for c in self._cache.values() if c.is_vulnerable_to_deauth]

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_wpa3_scans": self._stats["scans_total"],
            "posframework_wpa3_found": self._stats["wpa3_found"],
            "posframework_wpa3_transition": self._stats["transition_mode_found"],
            "posframework_wpa3_pmf_required": self._stats["pmf_required_found"],
        }
