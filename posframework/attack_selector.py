"""
Attack Selector
───────────────
Maps scored targets to appropriate attack strategies and module chains.

Based on target security type, POS status, and available modules, returns
an ordered list of attack modules/configurations to execute.

Attack Chain Logic:
  - Open network:       RogueAP + DNS Spoof + Credential Harvest
  - WPA2-PSK:          Deauth + Handshake Capture + Evil Twin
  - WPA2-Enterprise:   KARMA + Credential Harvest
  - POS target:        Full chain (deauth + rogue + MITM + printer scan)
  - Custom chains via config overrides
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from .config import log


@dataclass
class AttackStep:
    """A single step in an attack chain."""
    module: str
    description: str
    priority: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    requires: List[str] = field(default_factory=list)
    optional: bool = False

    def __repr__(self):
        opt = " (optional)" if self.optional else ""
        return f"AttackStep({self.module}: {self.description}{opt})"


@dataclass
class AttackChain:
    """An ordered sequence of attack steps for a target."""
    target_bssid: str
    target_ssid: str
    strategy_name: str
    steps: List[AttackStep] = field(default_factory=list)
    estimated_duration: int = 0  # seconds
    stealth_compatible: bool = True

    def __repr__(self):
        return (f"AttackChain({self.strategy_name} -> {self.target_ssid} "
                f"[{len(self.steps)} steps, ~{self.estimated_duration}s])")


class AttackSelector:
    """
    Selects and orders attack modules based on target characteristics.

    Takes a scored target (from TargetScorer) and returns an ordered
    AttackChain specifying which modules to run and in what order.

    Supports:
      - Built-in attack chains for common security types
      - Custom chains via config file overrides
      - Stealth mode (quieter techniques, longer intervals)
      - Plugin-based attack modules
    """

    # Built-in attack chain definitions
    CHAINS = {
        "rogue_ap_mitm": {
            "name": "Rogue AP + MITM",
            "description": "Open network exploitation via rogue AP",
            "duration": 120,
            "stealth": True,
            "steps": [
                {"module": "rogueap", "desc": "Deploy rogue AP cloning target SSID",
                 "priority": 1},
                {"module": "dns_spoof", "desc": "DNS spoofing to redirect traffic",
                 "priority": 2},
                {"module": "mitm", "desc": "ARP poisoning for traffic interception",
                 "priority": 3},
                {"module": "cred_harvester", "desc": "Harvest credentials from HTTP/FTP",
                 "priority": 4},
                {"module": "ssl_strip", "desc": "HTTPS downgrade to HTTP",
                 "priority": 5, "optional": True},
            ],
        },
        "handshake_capture": {
            "name": "WPA Handshake Capture",
            "description": "Deauth clients to capture WPA handshake",
            "duration": 90,
            "stealth": False,
            "steps": [
                {"module": "deauth", "desc": "Deauthenticate clients from target AP",
                 "priority": 1},
                {"module": "handshake", "desc": "Capture WPA 4-way handshake",
                 "priority": 1},
                {"module": "ap_clone", "desc": "Clone target AP for evil twin",
                 "priority": 2},
                {"module": "rogueap", "desc": "Deploy evil twin with captive portal",
                 "priority": 3},
                {"module": "cred_harvester", "desc": "Harvest credentials from portal",
                 "priority": 4},
            ],
        },
        "karma_credential": {
            "name": "KARMA + Credential Harvest",
            "description": "Enterprise network credential capture via KARMA",
            "duration": 180,
            "stealth": True,
            "steps": [
                {"module": "karma", "desc": "KARMA attack - respond to all probes",
                 "priority": 1},
                {"module": "rogueap", "desc": "Deploy rogue AP with captive portal",
                 "priority": 2},
                {"module": "cred_harvester", "desc": "Capture enterprise credentials",
                 "priority": 3},
            ],
        },
        "pos_full_chain": {
            "name": "POS Full Chain Attack",
            "description": "Complete POS target exploitation",
            "duration": 300,
            "stealth": False,
            "steps": [
                {"module": "deauth", "desc": "Deauth POS terminals from network",
                 "priority": 1},
                {"module": "handshake", "desc": "Capture WPA handshake if applicable",
                 "priority": 1, "optional": True},
                {"module": "rogueap", "desc": "Deploy clone AP for POS terminals",
                 "priority": 2},
                {"module": "mitm", "desc": "MITM attack on POS traffic",
                 "priority": 3},
                {"module": "dns_spoof", "desc": "Redirect POS DNS queries",
                 "priority": 3},
                {"module": "cred_harvester", "desc": "Harvest payment/auth credentials",
                 "priority": 4},
                {"module": "printer_recon", "desc": "Scan for receipt printers",
                 "priority": 5, "optional": True},
                {"module": "print_interceptor", "desc": "Intercept print jobs",
                 "priority": 6, "optional": True},
            ],
        },
        "wep_crack": {
            "name": "WEP Crack",
            "description": "WEP network key recovery",
            "duration": 60,
            "stealth": False,
            "steps": [
                {"module": "deauth", "desc": "Generate traffic via deauth",
                 "priority": 1},
                {"module": "rogueap", "desc": "Deploy rogue AP after crack",
                 "priority": 2},
                {"module": "mitm", "desc": "MITM on cracked network",
                 "priority": 3},
            ],
        },
        "sae_downgrade": {
            "name": "SAE/WPA3 Downgrade",
            "description": "WPA3 transition mode downgrade attack",
            "duration": 150,
            "stealth": False,
            "steps": [
                {"module": "deauth", "desc": "Force client disconnection",
                 "priority": 1},
                {"module": "rogueap", "desc": "Deploy WPA2 clone of WPA3 AP",
                 "priority": 2, "config": {"force_wpa2": True}},
                {"module": "handshake", "desc": "Capture downgraded handshake",
                 "priority": 3},
                {"module": "cred_harvester", "desc": "Credential harvest via portal",
                 "priority": 4},
            ],
        },
        "generic_attack": {
            "name": "Generic Attack",
            "description": "Fallback attack chain for unknown security types",
            "duration": 120,
            "stealth": True,
            "steps": [
                {"module": "deauth", "desc": "Deauthenticate clients",
                 "priority": 1},
                {"module": "rogueap", "desc": "Deploy rogue AP",
                 "priority": 2},
                {"module": "cred_harvester", "desc": "Harvest credentials",
                 "priority": 3},
            ],
        },
    }

    def __init__(self, plugin_loader=None, custom_chains: Optional[Dict] = None,
                 stealth_mode: bool = False):
        """
        Initialize the AttackSelector.

        Args:
            plugin_loader: Optional PluginLoader instance for plugin-based attacks.
            custom_chains: Optional dict of custom chain definitions (from config).
            stealth_mode: If True, prefer stealth-compatible chains and techniques.
        """
        self.plugin_loader = plugin_loader
        self.stealth_mode = stealth_mode
        self._custom_chains: Dict[str, Dict] = custom_chains or {}
        self._available_modules: set = set()

    def set_plugin_loader(self, plugin_loader):
        """Set or update the plugin loader reference."""
        self.plugin_loader = plugin_loader

    def set_available_modules(self, modules: List[str]):
        """
        Set the list of available attack modules.
        Used to filter out steps that require unavailable modules.
        """
        self._available_modules = set(modules)

    def select_attack(self, target) -> AttackChain:
        """
        Select the best attack chain for a given scored target.

        Args:
            target: A ScoredTarget instance from TargetScorer.

        Returns:
            An AttackChain with ordered steps for execution.
        """
        strategy = target.recommended_strategy

        # Check for custom chain override
        if strategy in self._custom_chains:
            chain_def = self._custom_chains[strategy]
        elif strategy in self.CHAINS:
            chain_def = self.CHAINS[strategy]
        else:
            # Fallback to generic
            log.warning(f"AttackSelector: Unknown strategy '{strategy}', using generic")
            chain_def = self.CHAINS["generic_attack"]

        # If stealth mode is on, check compatibility
        if self.stealth_mode and not chain_def.get("stealth", False):
            # Try to find a stealth-compatible alternative
            stealth_chain = self._find_stealth_alternative(strategy)
            if stealth_chain:
                chain_def = stealth_chain

        # Build the attack chain
        steps = []
        for step_def in chain_def["steps"]:
            step = AttackStep(
                module=step_def["module"],
                description=step_def["desc"],
                priority=step_def.get("priority", 0),
                config=step_def.get("config", {}),
                requires=step_def.get("requires", []),
                optional=step_def.get("optional", False),
            )

            # Apply stealth config overrides
            if self.stealth_mode:
                step.config["stealth"] = True
                step.config.setdefault("delay_multiplier", 3.0)
                step.config.setdefault("burst_count", 1)

            steps.append(step)

        # Sort steps by priority
        steps.sort(key=lambda s: s.priority)

        # Check for plugin-based additions
        if self.plugin_loader:
            plugin_steps = self._get_plugin_steps(target)
            steps.extend(plugin_steps)

        chain = AttackChain(
            target_bssid=target.bssid,
            target_ssid=target.ssid,
            strategy_name=chain_def.get("name", strategy),
            steps=steps,
            estimated_duration=chain_def.get("duration", 120),
            stealth_compatible=chain_def.get("stealth", False),
        )

        log.info(f"AttackSelector: Selected '{chain.strategy_name}' for "
                 f"{target.ssid} ({len(steps)} steps, ~{chain.estimated_duration}s)")

        return chain

    def _find_stealth_alternative(self, original_strategy: str) -> Optional[Dict]:
        """
        Find a stealth-compatible alternative to the given strategy.

        Returns the chain definition or None if no alternative found.
        """
        # Stealth alternatives mapping
        stealth_alternatives = {
            "handshake_capture": "karma_credential",
            "pos_full_chain": "karma_credential",
            "wep_crack": "rogue_ap_mitm",
            "sae_downgrade": "karma_credential",
        }

        alt_key = stealth_alternatives.get(original_strategy)
        if alt_key and alt_key in self.CHAINS:
            alt_chain = self.CHAINS[alt_key]
            if alt_chain.get("stealth", False):
                log.info(f"AttackSelector: Stealth mode - switching from "
                         f"'{original_strategy}' to '{alt_key}'")
                return alt_chain

        return None

    def _get_plugin_steps(self, target) -> List[AttackStep]:
        """
        Query the plugin loader for any additional attack steps
        that plugins can provide for this target.
        """
        plugin_steps = []
        if not self.plugin_loader:
            return plugin_steps

        # Check for plugins matching the target's security type
        security = (target.security or "").upper()

        # Get plugins that match relevant categories
        relevant_categories = ["deauth", "mitm", "credential", "rogue_ap"]
        if target.is_pos:
            relevant_categories.extend(["printer", "isolation"])

        for category in relevant_categories:
            plugins = self.plugin_loader.get_plugins_by_category(category)
            for plugin in plugins:
                if hasattr(plugin, 'enabled') and not plugin.enabled:
                    continue
                plugin_steps.append(AttackStep(
                    module=f"plugin:{plugin.name()}",
                    description=f"Plugin: {plugin.description()}",
                    priority=99,  # Plugins run after built-in steps
                    config={"plugin_name": plugin.name()},
                    optional=True,
                ))

        return plugin_steps

    def get_available_strategies(self) -> List[str]:
        """Return list of all available strategy names."""
        strategies = list(self.CHAINS.keys())
        strategies.extend(self._custom_chains.keys())
        return strategies

    def get_chain_info(self, strategy: str) -> Optional[Dict]:
        """
        Get information about a specific attack chain.

        Args:
            strategy: Strategy name to look up.

        Returns:
            Chain definition dict or None if not found.
        """
        if strategy in self._custom_chains:
            return self._custom_chains[strategy]
        return self.CHAINS.get(strategy)

    def add_custom_chain(self, name: str, chain_def: Dict):
        """
        Add a custom attack chain definition.

        Args:
            name: Strategy name for the custom chain.
            chain_def: Chain definition dict with 'name', 'steps', 'duration', etc.
        """
        required_keys = {"name", "steps"}
        if not required_keys.issubset(chain_def.keys()):
            raise ValueError(f"Chain definition must include: {required_keys}")

        self._custom_chains[name] = chain_def
        log.info(f"AttackSelector: Added custom chain '{name}' "
                 f"with {len(chain_def['steps'])} steps")
