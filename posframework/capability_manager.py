"""
POSFramework Capability Manager - Hardware-aware feature gating.

Automatically enables/disables features based on available hardware.
Designed for headless operation where hardware may not always be present.

Features:
- HardwareRequirement Flag enum for declaring needs
- Feature gating based on hardware availability
- Manual set_available for current state (no auto-detection dependency)
- Plugin integration (plugins declare requirements)
- Clean degradation (unavailable features are silently skipped)
- MockCapabilityManager for testing

Usage:
    from posframework.capability_manager import CapabilityManager, HardwareRequirement

    capability = CapabilityManager()
    capability.set_available(HardwareRequirement.WIFI, True)

    if capability.is_available(HardwareRequirement.WIFI_ATTACK):
        start_attack()

    capability.register_feature("wifi_deauth", HardwareRequirement.WIFI_ATTACK)
    if capability.is_feature_enabled("wifi_deauth"):
        deauth_engine.start()
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Flag, auto
from typing import Any

logger = logging.getLogger(__name__)


class HardwareRequirement(Flag):
    """Hardware requirements for features."""
    NONE = 0

    # WiFi
    WIFI = auto()                    # Any WiFi adapter
    WIFI_MONITOR = auto()            # Monitor mode capable
    WIFI_INJECTION = auto()          # Packet injection capable
    WIFI_5GHZ = auto()               # 5GHz support

    # SDR
    SDR = auto()                     # Any SDR device
    SDR_TX = auto()                  # SDR with TX capability

    # Bluetooth
    BLUETOOTH = auto()               # Any Bluetooth adapter
    BLE = auto()                     # BLE support

    # GPS
    GPS = auto()                     # Any GPS module

    # Compound flags
    WIFI_ATTACK = WIFI | WIFI_MONITOR | WIFI_INJECTION
    WARDRIVING = WIFI | GPS


@dataclass
class CapabilityStatus:
    """Status of a single capability."""
    name: str
    available: bool
    reason: str = ""
    hardware_count: int = 0
    last_checked: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "reason": self.reason,
            "hardware_count": self.hardware_count,
            "last_checked": self.last_checked.isoformat(),
        }


@dataclass
class FeatureGate:
    """A feature that requires specific hardware."""
    name: str
    requirements: HardwareRequirement
    enabled: bool = False
    reason: str = ""
    fallback_enabled: bool = False  # Allow mock/simulation mode

    def to_dict(self) -> dict[str, Any]:
        requirements = [
            r.name for r in HardwareRequirement
            if r in self.requirements and r != HardwareRequirement.NONE
        ]
        return {
            "name": self.name,
            "requirements": requirements,
            "enabled": self.enabled,
            "reason": self.reason,
            "fallback_enabled": self.fallback_enabled,
        }


class CapabilityManager:
    """
    Hardware-aware capability manager.

    Enables/disables features based on detected or manually set hardware status.

    Usage:
        capability = CapabilityManager()
        capability.set_available(HardwareRequirement.WIFI, True)

        if capability.is_available(HardwareRequirement.WIFI_MONITOR):
            monitor_engine.start()

        capability.register_feature("deauth", HardwareRequirement.WIFI_ATTACK)
        if capability.is_feature_enabled("deauth"):
            deauth_engine.start()
    """

    _instance: CapabilityManager | None = None

    def __new__(cls) -> CapabilityManager:
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, '_initialized', False):
            return

        self._capabilities: dict[HardwareRequirement, CapabilityStatus] = {}
        self._features: dict[str, FeatureGate] = {}
        self._change_handlers: list[Callable[[str, bool], None]] = []
        self._running = False
        self._last_scan: datetime | None = None
        self._initialized = True

        # Initialize all capability statuses as unavailable
        for req in HardwareRequirement:
            if req != HardwareRequirement.NONE and req.name is not None:
                self._capabilities[req] = CapabilityStatus(
                    name=req.name,
                    available=False,
                    reason="Not scanned yet",
                )

        logger.info("CapabilityManager initialized")

    def set_available(
        self,
        requirement: HardwareRequirement,
        available: bool = True,
        reason: str = "",
        hardware_count: int = 1,
    ) -> None:
        """
        Manually set a capability as available or unavailable.

        Args:
            requirement: The hardware requirement flag
            available: Whether the hardware is present
            reason: Human-readable reason
            hardware_count: Number of hardware items detected
        """
        name = requirement.name or str(requirement)
        self._capabilities[requirement] = CapabilityStatus(
            name=name,
            available=available,
            reason=reason or ("Available" if available else "Not available"),
            hardware_count=hardware_count if available else 0,
        )
        self._update_all_features()

    async def refresh(self) -> dict[str, bool]:
        """
        Refresh hardware status. Without a hardware detector, returns current state.

        Override in subclass or set capabilities manually with set_available().
        """
        self._last_scan = datetime.now(timezone.utc)
        return self._get_all_status()

    def _get_all_status(self) -> dict[str, bool]:
        """Get all capability statuses as a simple dict."""
        return {
            cap.name: cap.available
            for cap in self._capabilities.values()
        }

    # =========================================================================
    # Capability Checking
    # =========================================================================

    def is_available(self, requirement: HardwareRequirement) -> bool:
        """
        Check if a hardware requirement is satisfied.

        For compound requirements (using |), ALL constituent flags must be satisfied.
        """
        if requirement == HardwareRequirement.NONE:
            return True

        # Check each individual flag in the compound requirement
        for req in HardwareRequirement:
            if req == HardwareRequirement.NONE:
                continue
            if (req & requirement) == req:
                cap = self._capabilities.get(req)
                if not cap or not cap.available:
                    return False

        return True

    def get_status(self, requirement: HardwareRequirement) -> CapabilityStatus | None:
        """Get detailed status for a requirement."""
        return self._capabilities.get(requirement)

    def get_missing(self, requirement: HardwareRequirement) -> list[str]:
        """Get list of missing capabilities for a compound requirement."""
        missing = []
        for req in HardwareRequirement:
            if req == HardwareRequirement.NONE:
                continue
            if (req & requirement) == req:
                cap = self._capabilities.get(req)
                if not cap or not cap.available:
                    missing.append(req.name or str(req))
        return missing

    # =========================================================================
    # Feature Gates
    # =========================================================================

    def register_feature(
        self,
        name: str,
        requirements: HardwareRequirement,
        fallback_enabled: bool = False,
    ) -> FeatureGate:
        """
        Register a feature with hardware requirements.

        Args:
            name: Feature identifier
            requirements: Required hardware flags
            fallback_enabled: Allow mock/simulation when hardware missing

        Returns:
            The created FeatureGate
        """
        gate = FeatureGate(
            name=name,
            requirements=requirements,
            fallback_enabled=fallback_enabled,
        )
        self._features[name] = gate
        self._update_feature(gate)

        logger.debug("Registered feature: %s requires %s", name, requirements)
        return gate

    def _update_feature(self, gate: FeatureGate) -> None:
        """Update a feature gate based on current capabilities."""
        old_enabled = gate.enabled

        if self.is_available(gate.requirements):
            gate.enabled = True
            gate.reason = "Hardware available"
        else:
            missing = self.get_missing(gate.requirements)
            if gate.fallback_enabled:
                gate.enabled = True
                gate.reason = f"Mock mode (missing: {', '.join(missing)})"
            else:
                gate.enabled = False
                gate.reason = f"Missing: {', '.join(missing)}"

        # Notify if changed
        if old_enabled != gate.enabled:
            self._notify_change(gate.name, gate.enabled)

    def _update_all_features(self) -> None:
        """Update all registered feature gates."""
        for gate in self._features.values():
            self._update_feature(gate)

    def is_feature_enabled(self, name: str) -> bool:
        """Check if a feature is enabled."""
        gate = self._features.get(name)
        return gate.enabled if gate else False

    def get_feature(self, name: str) -> FeatureGate | None:
        """Get feature gate details."""
        return self._features.get(name)

    def get_all_features(self) -> dict[str, FeatureGate]:
        """Get all registered features."""
        return dict(self._features)

    # =========================================================================
    # Change Notifications
    # =========================================================================

    def on_change(self, handler: Callable[[str, bool], None]) -> None:
        """Register a handler for capability changes. Receives (feature_name, is_enabled)."""
        self._change_handlers.append(handler)

    def _notify_change(self, name: str, enabled: bool) -> None:
        """Notify all handlers of a feature state change."""
        for handler in self._change_handlers:
            try:
                handler(name, enabled)
            except Exception as e:
                logger.error("Change handler error: %s", e)

    # =========================================================================
    # Convenience Properties
    # =========================================================================

    @property
    def has_wifi(self) -> bool:
        """Check if WiFi is available."""
        return self.is_available(HardwareRequirement.WIFI)

    @property
    def has_sdr(self) -> bool:
        """Check if SDR is available."""
        return self.is_available(HardwareRequirement.SDR)

    @property
    def has_bluetooth(self) -> bool:
        """Check if Bluetooth is available."""
        return self.is_available(HardwareRequirement.BLUETOOTH)

    @property
    def has_gps(self) -> bool:
        """Check if GPS is available."""
        return self.is_available(HardwareRequirement.GPS)

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all capabilities and features."""
        return {
            "capabilities": {
                cap.name: cap.to_dict()
                for cap in self._capabilities.values()
            },
            "features": {
                name: gate.to_dict()
                for name, gate in self._features.items()
            },
            "summary": {
                "wifi": self.has_wifi,
                "sdr": self.has_sdr,
                "bluetooth": self.has_bluetooth,
                "gps": self.has_gps,
            },
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
        }


# =========================================================================
# Pre-defined Feature Registrations
# =========================================================================

STANDARD_FEATURES: dict[str, HardwareRequirement] = {
    # WiFi features
    "wifi_scan": HardwareRequirement.WIFI,
    "wifi_monitor": HardwareRequirement.WIFI_MONITOR,
    "wifi_deauth": HardwareRequirement.WIFI_ATTACK,
    "wifi_capture": HardwareRequirement.WIFI_MONITOR,
    "evil_twin": HardwareRequirement.WIFI_ATTACK,
    "karma_attack": HardwareRequirement.WIFI_ATTACK,
    "wpa3_detect": HardwareRequirement.WIFI_MONITOR,
    "wpa3_attack": HardwareRequirement.WIFI_ATTACK,

    # SDR features
    "sdr_spectrum": HardwareRequirement.SDR,
    "sdr_transmit": HardwareRequirement.SDR_TX,
    "sdr_decode": HardwareRequirement.SDR,

    # Bluetooth features
    "ble_scan": HardwareRequirement.BLE,
    "ble_gatt": HardwareRequirement.BLE,
    "ble_hid_inject": HardwareRequirement.BLUETOOTH,
    "ble_beacon_spoof": HardwareRequirement.BLUETOOTH,

    # GPS features
    "gps_tracking": HardwareRequirement.GPS,
    "wardriving": HardwareRequirement.WARDRIVING,

    # Combined features
    "full_attack": HardwareRequirement.WIFI_ATTACK | HardwareRequirement.BLE,
}


def register_standard_features(manager: CapabilityManager) -> None:
    """Register all standard POSFramework features."""
    for name, requirement in STANDARD_FEATURES.items():
        manager.register_feature(name, requirement)


def get_capability_manager() -> CapabilityManager:
    """Get the singleton capability manager instance."""
    return CapabilityManager()


# =========================================================================
# Mock Capability Manager for Testing
# =========================================================================

class MockCapabilityManager(CapabilityManager):
    """Mock capability manager for testing - does not use singleton."""

    _instance = None  # Override singleton

    def __new__(cls) -> MockCapabilityManager:
        instance = object.__new__(cls)
        instance._initialized = False
        return instance

    def set_available(  # type: ignore[override]
        self,
        requirement: HardwareRequirement,
        available: bool = True,
        reason: str = "",
        hardware_count: int = 1,
    ) -> None:
        """Manually set a capability as available (mock)."""
        name = requirement.name or str(requirement)
        self._capabilities[requirement] = CapabilityStatus(
            name=name,
            available=available,
            reason=reason or "Mock",
            hardware_count=hardware_count if available else 0,
        )
        self._update_all_features()

    def set_all_available(self, available: bool = True) -> None:
        """Set all capabilities as available/unavailable."""
        for req in HardwareRequirement:
            if req != HardwareRequirement.NONE and req.name is not None:
                self.set_available(req, available)

    async def refresh(self) -> dict[str, bool]:
        """No-op for mock."""
        self._last_scan = datetime.now(timezone.utc)
        return self._get_all_status()
