"""
Deauthentication Attack Plugin
──────────────────────────────
Wraps the DeauthEngine class to provide targeted deauthentication
attacks via the plugin interface.

This plugin sends 802.11 deauthentication frames to disconnect
clients from their access point, forcing them to reconnect
(potentially to a rogue AP).
"""

from typing import Any, Dict

from posframework.plugin_loader import AttackPlugin


class DeauthPlugin(AttackPlugin):
    """
    Plugin wrapper for the DeauthEngine.

    Configuration keys (setup):
        interface: str - Monitor mode interface name
        burst_count: int - Number of deauth frames per burst (default: 5)
        interval: float - Seconds between bursts (default: 0.1)

    Context keys (execute):
        target_bssid: str - Target AP BSSID
        client_macs: set[str] - Set of client MAC addresses to deauth
        broadcast: bool - Whether to also send broadcast deauth (default: True)
    """

    def __init__(self):
        self._engine = None
        self._interface = None
        self._enabled = True

    def name(self) -> str:
        return "deauth"

    def description(self) -> str:
        return "Targeted deauthentication attack against WiFi clients"

    def category(self) -> str:
        return "deauth"

    def setup(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the DeauthEngine with the given configuration.

        Args:
            config: Must contain 'interface' key. Optional: 'burst_count', 'interval'.

        Returns:
            True if setup succeeded.
        """
        self._interface = config.get("interface")
        if not self._interface:
            return False

        # Lazy import to avoid triggering scapy at module load time
        from posframework.deauth import DeauthEngine

        self._engine = DeauthEngine(self._interface)

        # Apply optional configuration
        burst_count = config.get("burst_count")
        if burst_count and hasattr(self._engine, "burst_count"):
            self._engine.burst_count = burst_count

        interval = config.get("interval")
        if interval and hasattr(self._engine, "interval"):
            self._engine.interval = interval

        return True

    def execute(self, context: Dict[str, Any]) -> Any:
        """
        Execute the deauthentication attack.

        Args:
            context: Must contain 'target_bssid' and 'client_macs'.
                    Optional: 'broadcast' (default True).

        Returns:
            Dict with status and number of targets.
        """
        if not self._engine:
            return {"status": "error", "reason": "Engine not initialized. Call setup() first."}

        target_bssid = context.get("target_bssid")
        client_macs = context.get("client_macs", set())
        broadcast = context.get("broadcast", True)

        if not target_bssid:
            return {"status": "error", "reason": "No target_bssid provided"}

        # Add targets to the deauth engine
        self._engine.add_target(target_bssid, client_macs)

        # Start the attack
        self._engine.start()

        return {
            "status": "running",
            "target_bssid": target_bssid,
            "client_count": len(client_macs),
            "broadcast": broadcast,
        }

    def teardown(self) -> None:
        """Stop the deauth engine and release resources."""
        if self._engine:
            try:
                self._engine.stop()
            except Exception:
                pass
            self._engine = None
