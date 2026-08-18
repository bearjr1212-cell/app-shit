"""
Attack State Persistence.

Provides live auto-save and auto-load for attack vectors, selected targets,
and UI settings. State is persisted immediately on any change (live save)
and restored immediately on startup (live load) so the user resumes
exactly where they left off.

Features:
- JSON-based persistence to logs/attack_state.json
- Atomic writes (write .tmp then rename) for crash safety
- Live save: state is flushed to disk on every change
- Live load: state is read and applied on startup
- Graceful handling of missing or corrupted state files

Usage:
    persistence = AttackPersistence()
    persistence.save(state_dict)
    state = persistence.load()
    persistence.clear()
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .config import log

logger = logging.getLogger(__name__)


class AttackPersistence:
    """Manages live persistence of attack state (targets, vectors, settings).

    Saves immediately on every change and loads immediately on startup
    so attack vectors are always persisted live.
    """

    # Default schema for the state file
    DEFAULT_STATE: Dict[str, Any] = {
        "selected_target": None,
        "selected_client": None,
        "enabled_attacks": {},
        "attack_params": {},
        "settings": {
            "monitor_iface": "",
            "ap_iface": "",
            "use_5ghz": False,
            "channels": [],
            "rssi_limit": -80,
            "recon_duration": 30,
            "mitm_target_ip": "",
            "mitm_gateway_ip": "",
            "dns_spoof_domain": "",
            "wordlist_path": "/usr/share/wordlists/rockyou.txt",
            "cracking_mode": "dictionary",
        },
    }

    def __init__(self, state_path: str = "logs/attack_state.json") -> None:
        """Initialize attack persistence.

        Args:
            state_path: Path to the JSON state file.
        """
        self.state_path = Path(state_path)
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure the parent directory exists."""
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Cannot create state directory: %s", e)

    def save(self, state: Dict[str, Any]) -> bool:
        """Save state to disk atomically (live save).

        Writes to a .tmp file first, then renames atomically to prevent
        corruption from crashes or partial writes.

        Args:
            state: Dictionary containing attack state to persist.

        Returns:
            True if save succeeded, False otherwise.
        """
        try:
            self._ensure_directory()
            temp_path = self.state_path.with_suffix(".tmp")
            data = json.dumps(state, indent=2, default=str)
            temp_path.write_text(data, encoding="utf-8")
            temp_path.replace(self.state_path)
            logger.debug("Attack state saved to %s", self.state_path)
            return True
        except (OSError, TypeError, ValueError) as e:
            logger.error("Failed to save attack state: %s", e)
            return False

    def load(self) -> Optional[Dict[str, Any]]:
        """Load state from disk (live load on startup).

        Reads the persisted JSON state file. If the file is missing or
        corrupted, returns None gracefully without crashing.

        Returns:
            The loaded state dictionary, or None if unavailable.
        """
        if not self.state_path.exists():
            logger.debug("No attack state file found at %s", self.state_path)
            return None

        try:
            data = self.state_path.read_text(encoding="utf-8")
            state = json.loads(data)
            if not isinstance(state, dict):
                logger.warning("Attack state file is not a valid dict")
                return None
            logger.info("Attack state loaded from %s", self.state_path)
            return state
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Failed to load attack state (corrupted?): %s", e
            )
            return None

    def clear(self) -> bool:
        """Clear persisted state by removing the state file.

        Returns:
            True if cleared (or already absent), False on error.
        """
        try:
            if self.state_path.exists():
                self.state_path.unlink()
                logger.info("Attack state cleared")
            return True
        except OSError as e:
            logger.error("Failed to clear attack state: %s", e)
            return False

    def build_state(
        self,
        selected_target: Optional[Dict[str, Any]] = None,
        selected_client: Optional[Dict[str, Any]] = None,
        enabled_attacks: Optional[Dict[str, bool]] = None,
        attack_params: Optional[Dict[str, Dict[str, Any]]] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a state dictionary from components.

        Convenience method to construct the state dict with proper structure.

        Args:
            selected_target: Target AP info (bssid, ssid, channel, security).
            selected_client: Client info (mac, associated_ap).
            enabled_attacks: Map of attack_key -> enabled bool.
            attack_params: Map of attack_key -> kwargs dict.
            settings: UI settings dict.

        Returns:
            A structured state dictionary ready for save().
        """
        return {
            "selected_target": selected_target,
            "selected_client": selected_client,
            "enabled_attacks": enabled_attacks or {},
            "attack_params": attack_params or {},
            "settings": settings or {},
        }
