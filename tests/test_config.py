"""
Unit tests for posframework/config.py and posframework/config_loader.py.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch


class TestConfigConstants:
    """Tests for config.py module-level constants."""

    def test_channels_24ghz_range(self):
        """2.4GHz channels should be 1-14."""
        from posframework.config import CHANNELS_24GHZ
        assert CHANNELS_24GHZ == list(range(1, 15))

    def test_channels_5ghz_populated(self):
        """5GHz channel list should contain expected channels."""
        from posframework.config import CHANNELS_5GHZ
        assert 36 in CHANNELS_5GHZ
        assert 40 in CHANNELS_5GHZ
        assert 149 in CHANNELS_5GHZ
        assert 165 in CHANNELS_5GHZ
        assert len(CHANNELS_5GHZ) > 15

    def test_deauth_constants(self):
        """Deauth constants should have sane defaults."""
        from posframework.config import DEAUTH_BURST_COUNT, DEAUTH_BURST_INTERVAL
        assert DEAUTH_BURST_COUNT > 0
        assert DEAUTH_BURST_INTERVAL > 0
        assert DEAUTH_BURST_INTERVAL < 5

    def test_beacon_interval(self):
        from posframework.config import BEACON_INTERVAL
        assert 0 < BEACON_INTERVAL <= 1.0

    def test_db_name_default(self):
        from posframework.config import DB_NAME
        assert DB_NAME.endswith(".db")

    def test_platform_detection(self):
        """Platform flags should be consistent with current OS."""
        from posframework.config import IS_LINUX, IS_WINDOWS
        import sys
        if sys.platform.startswith("linux"):
            assert IS_LINUX is True
            assert IS_WINDOWS is False
        elif sys.platform == "win32":
            assert IS_WINDOWS is True
            assert IS_LINUX is False

    def test_wifi_broadcast(self):
        from posframework.config import WIFI_BROADCAST
        assert WIFI_BROADCAST == "ff:ff:ff:ff:ff:ff"

    def test_log_exists(self):
        """Logger should be configured."""
        from posframework.config import log
        assert log is not None
        assert log.name == "POSFramework"


class TestConfigLoader:
    """Tests for config_loader.py — YAML configuration loading."""

    def test_default_config_structure(self):
        """DEFAULT_CONFIG should have all required sections."""
        from posframework.config_loader import DEFAULT_CONFIG
        assert "general" in DEFAULT_CONFIG
        assert "recon" in DEFAULT_CONFIG
        assert "attack" in DEFAULT_CONFIG
        assert "rogue_ap" in DEFAULT_CONFIG
        assert "plugins" in DEFAULT_CONFIG
        assert "profiles" in DEFAULT_CONFIG

    def test_load_config_from_file(self, tmp_config_file):
        """ConfigLoader should load values from a YAML file."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=tmp_config_file)
        assert config.get("general.interface") == "wlan0test"
        assert config.get("general.ap_interface") == "wlan1test"
        assert config.get("recon.channel_hop_interval") == 0.5
        assert config.get("attack.deauth_burst_count") == 3

    def test_get_with_default(self, tmp_config_file):
        """get() should return default when key doesn't exist."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=tmp_config_file)
        assert config.get("nonexistent.key", "fallback") == "fallback"
        assert config.get("nonexistent.deep.key", 42) == 42

    def test_get_nested_keys(self, tmp_config_file):
        """Dotted key access should work for nested config."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=tmp_config_file)
        assert config.get("attack.enable_dos") is True
        assert config.get("attack.dos_mode") == "beacon_exhaust"

    def test_profile_override(self, tmp_config_file):
        """Named profile should override base config values."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=tmp_config_file, profile="custom")
        assert config.get("recon.channel_hop_interval") == 2.0
        assert config.get("attack.deauth_burst_count") == 1

    def test_nonexistent_file_uses_defaults(self, tmp_path):
        """Non-existent config file should fall back to defaults."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=str(tmp_path / "missing.yaml"))
        # Should still have defaults
        assert config.get("general.interface") is not None
        assert config.get("recon.channel_hop_interval") == 0.3

    def test_builtin_profiles(self):
        """Built-in profiles (stealth, aggressive, recon-only) should exist."""
        from posframework.config_loader import DEFAULT_CONFIG
        profiles = DEFAULT_CONFIG["profiles"]
        assert "stealth" in profiles
        assert "aggressive" in profiles
        assert "recon-only" in profiles

    def test_stealth_profile_reduces_aggression(self):
        """Stealth profile should have lower burst counts and longer intervals."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(profile="stealth")
        assert config.get("attack.deauth_burst_count") == 2
        assert config.get("recon.channel_hop_interval") == 1.0
        assert config.get("attack.enable_karma") is False

    def test_aggressive_profile_increases_aggression(self):
        """Aggressive profile should have higher burst counts."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(profile="aggressive")
        assert config.get("attack.deauth_burst_count") == 10
        assert config.get("recon.channel_hop_interval") == 0.1
        assert config.get("attack.enable_karma") is True
        assert config.get("attack.enable_ap_clone") is True

    def test_recon_only_profile_disables_attacks(self):
        """Recon-only profile should disable all attack modules."""
        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(profile="recon-only")
        assert config.get("attack.deauth_burst_count") == 0
        assert config.get("attack.enable_karma") is False
        assert config.get("attack.enable_beacons") is False
        assert config.get("attack.enable_ap_clone") is False
        assert config.get("attack.enable_dos") is False

    def test_env_var_interpolation(self, tmp_path, monkeypatch):
        """Environment variables in ${VAR} format should be interpolated."""
        monkeypatch.setenv("POSFW_NETWORK_GW", "192.168.1.1")
        monkeypatch.setenv("POSFW_NETWORK_MASK", "255.255.0.0")

        config_content = """
rogue_ap:
  network_gw_ip: "${POSFW_NETWORK_GW}"
  network_mask: "${POSFW_NETWORK_MASK}"
"""
        config_file = tmp_path / "env_test.yaml"
        config_file.write_text(config_content)

        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=str(config_file))
        assert config.get("rogue_ap.network_gw_ip") == "192.168.1.1"
        assert config.get("rogue_ap.network_mask") == "255.255.0.0"

    def test_env_var_unset_returns_empty(self, tmp_path, monkeypatch):
        """Unset env vars should resolve to empty string."""
        monkeypatch.delenv("POSFW_NONEXISTENT_VAR", raising=False)

        config_content = """
test:
  value: "${POSFW_NONEXISTENT_VAR}"
"""
        config_file = tmp_path / "env_unset.yaml"
        config_file.write_text(config_content)

        from posframework.config_loader import ConfigLoader
        config = ConfigLoader(config_path=str(config_file))
        # Should either be empty string or the literal pattern
        val = config.get("test.value", "")
        assert val == "" or "${" not in val


class TestConfigLoadFunction:
    """Tests for config.py's load_config() function."""

    def test_load_config_updates_globals(self, tmp_config_file):
        """load_config() should update module-level constants."""
        from posframework import config
        original_hop = config.CHANNEL_HOP_INTERVAL

        config.load_config(path=tmp_config_file)

        assert config.CHANNEL_HOP_INTERVAL == 0.5
        assert config.DEAUTH_BURST_COUNT == 3

        # Restore
        config.CHANNEL_HOP_INTERVAL = original_hop

    def test_load_config_with_profile(self, tmp_config_file):
        """load_config() with profile should apply overrides."""
        from posframework import config
        result = config.load_config(path=tmp_config_file, profile="custom")
        assert result is not None  # returns ConfigLoader instance
