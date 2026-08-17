"""
YAML Configuration Loader for POSFramework.

Supports:
  - Loading from YAML config files (posframework.yaml or ~/.posframework.yaml)
  - Named profiles for different attack scenarios (stealth, aggressive, recon-only)
  - Environment variable interpolation in string values (${VAR_NAME} syntax)
  - Merging with CLI arguments (CLI takes precedence)
  - get(key, default) access and attribute-style access
  - Graceful fallback when PyYAML is not installed
"""

import os
import re
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ─── Default Configuration ───────────────────────────────────────────────────
# These mirror the constants in config.py as structured defaults.

DEFAULT_CONFIG = {
    "general": {
        "interface": "wlan0mon",
        "ap_interface": "wlan1",
        "channels": "2.4ghz",
    },
    "recon": {
        "timeout": None,
        "channel_hop_interval": 0.3,
        "status_interval": 30,
    },
    "attack": {
        "deauth_burst_count": 5,
        "deauth_burst_interval": 0.1,
        "beacon_interval": 0.1,
        "rssi_limit": -80,
        "enable_karma": True,
        "enable_beacons": True,
        "enable_ap_clone": False,
        "enable_krack": False,
        "enable_dos": False,
        "dos_mode": "cts_flood",
        "enable_client_isolation": False,
        "enable_printer_attacks": False,
    },
    "rogue_ap": {
        "network_gw_ip": "${POSFW_NETWORK_GW}",
        "network_mask": "${POSFW_NETWORK_MASK}",
        "network_ip": "${POSFW_NETWORK_IP}",
        "dhcp_lease": "${POSFW_DHCP_LEASE}",
        "captive_portal_port": 80,
        "captive_portal_ssl_port": 443,
    },
    "plugins": {
        "enabled": [],
        "plugins_dir": None,
    },
    "profiles": {
        "stealth": {
            "recon.channel_hop_interval": 1.0,
            "recon.status_interval": 60,
            "attack.deauth_burst_count": 2,
            "attack.deauth_burst_interval": 0.5,
            "attack.beacon_interval": 0.5,
            "attack.enable_karma": False,
            "attack.enable_dos": False,
        },
        "aggressive": {
            "recon.channel_hop_interval": 0.1,
            "recon.status_interval": 10,
            "attack.deauth_burst_count": 10,
            "attack.deauth_burst_interval": 0.05,
            "attack.beacon_interval": 0.05,
            "attack.enable_karma": True,
            "attack.enable_ap_clone": True,
            "attack.enable_dos": True,
        },
        "recon-only": {
            "attack.deauth_burst_count": 0,
            "attack.enable_karma": False,
            "attack.enable_beacons": False,
            "attack.enable_ap_clone": False,
            "attack.enable_krack": False,
            "attack.enable_dos": False,
            "attack.enable_client_isolation": False,
            "attack.enable_printer_attacks": False,
        },
    },
}

# Regex for ${VAR_NAME} environment variable interpolation
_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _interpolate_env(value):
    """Replace ${VAR_NAME} patterns in a string with environment variable values."""
    if not isinstance(value, str):
        return value

    def _replacer(match):
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return _ENV_VAR_PATTERN.sub(_replacer, value)


def _deep_merge(base, override):
    """Deep merge override dict into base dict. Override values win."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _interpolate_recursive(data):
    """Recursively interpolate environment variables in all string values."""
    if isinstance(data, dict):
        return {k: _interpolate_recursive(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_interpolate_recursive(item) for item in data]
    elif isinstance(data, str):
        return _interpolate_env(data)
    return data


class ConfigLoader:
    """
    Loads framework configuration from YAML files with profile and
    environment variable support.

    Usage:
        config = ConfigLoader("posframework.yaml", profile="stealth")
        hop_interval = config.get("recon.channel_hop_interval", 0.3)
        interface = config.general.interface
    """

    def __init__(self, config_path=None, profile=None):
        """
        Initialize the config loader.

        Args:
            config_path: Path to a YAML config file. If None, searches
                         for posframework.yaml in cwd and ~/.posframework.yaml.
            profile: Name of a profile to activate. Profile values override
                     the base configuration.
        """
        self._data = dict(DEFAULT_CONFIG)
        self._profile = profile
        self._config_path = config_path
        self._loaded = False

        # Attempt to load from file
        resolved_path = self._resolve_path(config_path)
        if resolved_path:
            self._load_file(resolved_path)

        # Apply profile overrides
        if profile:
            self._apply_profile(profile)

        # Interpolate environment variables in all string values
        self._data = _interpolate_recursive(self._data)

    def _resolve_path(self, config_path):
        """Resolve config file path, searching default locations if not given."""
        if config_path:
            path = Path(config_path)
            if path.exists():
                return path
            return None

        # Search default locations
        candidates = [
            Path("posframework.yaml"),
            Path("posframework.yml"),
            Path.home() / ".posframework.yaml",
            Path.home() / ".posframework.yml",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _load_file(self, path):
        """Load configuration from a YAML file."""
        if not YAML_AVAILABLE:
            print(
                "[!] PyYAML is not installed. Cannot load config file.\n"
                "    Install with: pip install pyyaml\n"
                "    Using built-in defaults instead."
            )
            return

        try:
            with open(path, "r") as f:
                file_data = yaml.safe_load(f)
            if file_data and isinstance(file_data, dict):
                self._data = _deep_merge(self._data, file_data)
                self._loaded = True
        except Exception as e:
            print(f"[!] Error loading config file '{path}': {e}")
            print("    Using built-in defaults instead.")

    def _apply_profile(self, profile_name):
        """Apply a named profile's overrides to the configuration."""
        profiles = self._data.get("profiles", {})
        if profile_name not in profiles:
            available = ", ".join(profiles.keys()) if profiles else "none"
            print(
                f"[!] Profile '{profile_name}' not found. "
                f"Available profiles: {available}"
            )
            return

        overrides = profiles[profile_name]
        if not isinstance(overrides, dict):
            return

        for dotted_key, value in overrides.items():
            self._set_dotted(dotted_key, value)

    def _set_dotted(self, dotted_key, value):
        """Set a value using dotted key notation (e.g., 'recon.timeout')."""
        parts = dotted_key.split(".")
        target = self._data
        for part in parts[:-1]:
            if part not in target or not isinstance(target[part], dict):
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value

    def get(self, key, default=None):
        """
        Get a configuration value using dotted key notation.

        Args:
            key: Dotted key like 'recon.channel_hop_interval' or 'general.interface'.
            default: Value to return if key is not found.

        Returns:
            The configuration value, or default if not found.
        """
        parts = key.split(".")
        current = self._data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def __getattr__(self, name):
        """Allow attribute-style access to top-level config sections."""
        if name.startswith("_"):
            raise AttributeError(name)
        data = object.__getattribute__(self, "_data")
        if name in data:
            value = data[name]
            if isinstance(value, dict):
                return _ConfigSection(value)
            return value
        raise AttributeError(f"No config section '{name}'")

    @property
    def loaded(self):
        """Whether a config file was successfully loaded."""
        return self._loaded

    @property
    def profile(self):
        """The active profile name (or None)."""
        return self._profile

    @property
    def data(self):
        """The full config data dict."""
        return dict(self._data)

    def as_flat_dict(self):
        """Return all config values as a flat dotted-key dict."""
        result = {}
        self._flatten(self._data, "", result)
        return result

    def _flatten(self, data, prefix, result):
        """Recursively flatten a nested dict."""
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                self._flatten(value, full_key, result)
            else:
                result[full_key] = value


class _ConfigSection:
    """Provides attribute-style access to a config dict section."""

    def __init__(self, data):
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        data = object.__getattribute__(self, "_data")
        if name in data:
            value = data[name]
            if isinstance(value, dict):
                return _ConfigSection(value)
            return value
        raise AttributeError(f"No config key '{name}'")

    def __repr__(self):
        data = object.__getattribute__(self, "_data")
        return f"ConfigSection({data})"
