"""
WPA3 Detection and Attack Module
---------------------------------

Detects WPA3/SAE capabilities by parsing RSN Information Elements
and executes attack vectors against transition-mode networks.

Capabilities:
- WPA3 detection via RSN IE parsing (AKM suite type 8 = SAE)
- PMF (Protected Management Frames) status detection
- Transition mode identification (WPA2 + WPA3 mixed)
- OWE (Opportunistic Wireless Encryption) detection
- Downgrade attack (force WPA2 on transition-mode networks)
- SAE commit flood (DoS against WPA3-SAE APs)
- Attack recommendations based on target capabilities

No external Python dependencies (uses system tools: iw, hcxdumptool, mdk4).
"""

from __future__ import annotations

from .wpa3_detector import (
    WPA3Detector,
    WPA3Capabilities,
    WPA3Mode,
    SAEStatus,
    PMFStatus,
)
from .wpa3_attack import (
    WPA3AttackManager,
    DowngradeAttack,
    SAEFloodAttack,
    AttackType,
    AttackStatus,
    AttackResult,
)

__all__ = [
    "WPA3Detector",
    "WPA3Capabilities",
    "WPA3Mode",
    "SAEStatus",
    "PMFStatus",
    "WPA3AttackManager",
    "DowngradeAttack",
    "SAEFloodAttack",
    "AttackType",
    "AttackStatus",
    "AttackResult",
]
