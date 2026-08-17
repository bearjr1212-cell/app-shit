"""
WiFi Denial of Service Plugin
──────────────────────────────
Wraps the WiFiDoSEngine class to provide multiple DoS attack
modes via the plugin interface.

Supported modes:
    - cts_flood: CTS frame flooding (silences the channel)
    - beacon_exhaust: Beacon frame exhaustion
    - qos_null: QoS null frame flooding
    - fragment: Fragmentation attack
"""

from typing import Any, Dict

from posframework.plugin_loader import AttackPlugin


class DoSPlugin(AttackPlugin):
    """
    Plugin wrapper for the WiFiDoSEngine.

    Configuration keys (setup):
        interface: str - Monitor mode interface name
        target_bssid: str - Target AP BSSID
        channel: int - Target channel number

    Context keys (execute):
        mode: str - DoS mode (cts_flood, beacon_exhaust, qos_null, fragment)
        duration: int - Attack duration in seconds (0 = until stopped)
    """

    def __init__(self):
        self._engine = None
        self._interface = None
        self._target_bssid = None
        self._channel = None
        self._enabled = True

    def name(self) -> str:
        return "dos"

    def description(self) -> str:
        return "WiFi denial of service (CTS flood, beacon exhaust, QoS null, fragment)"

    def category(self) -> str:
        return "dos"

    def setup(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the WiFiDoSEngine.

        Args:
            config: Must contain 'interface', 'target_bssid', 'channel'.

        Returns:
            True if setup succeeded.
        """
        self._interface = config.get("interface")
        self._target_bssid = config.get("target_bssid")
        self._channel = config.get("channel", 6)

        if not self._interface or not self._target_bssid:
            return False

        # Lazy import to avoid triggering scapy at module load time
        from posframework.dos_wifi import WiFiDoSEngine

        self._engine = WiFiDoSEngine(
            self._interface, self._target_bssid, self._channel
        )
        return True

    def execute(self, context: Dict[str, Any]) -> Any:
        """
        Execute the DoS attack.

        Args:
            context: Optional 'mode' key (default: 'cts_flood').
                    Optional 'duration' key (default: 0, run until stopped).

        Returns:
            Dict with status, mode, and target info.
        """
        if not self._engine:
            return {"status": "error", "reason": "Engine not initialized. Call setup() first."}

        mode = context.get("mode", "cts_flood")
        duration = context.get("duration", 0)

        self._engine.start(mode=mode)

        return {
            "status": "running",
            "mode": mode,
            "target_bssid": self._target_bssid,
            "channel": self._channel,
            "duration": duration,
        }

    def teardown(self) -> None:
        """Stop the DoS engine and release resources."""
        if self._engine:
            try:
                self._engine.stop()
            except Exception:
                pass
            self._engine = None
