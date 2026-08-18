"""
Tests for posframework.attack_persistence module.

Tests cover:
- Save/load roundtrip
- Auto-load populates fields correctly
- clear() removes the state file
- Atomic write pattern (.tmp then rename)
- Handles missing/corrupted file gracefully
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Allow running directly: python tests/test_attack_persistence.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posframework.attack_persistence import AttackPersistence


class TestAttackPersistence(unittest.TestCase):
    """Test suite for AttackPersistence class."""

    def setUp(self):
        """Create a temporary directory for test state files."""
        self.tmp_dir = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp_dir, "test_attack_state.json")
        self.persistence = AttackPersistence(state_path=self.state_path)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _sample_state(self):
        """Return a sample state dictionary."""
        return {
            "selected_target": {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "ssid": "TestNetwork",
                "channel": 6,
                "security": "WPA2",
            },
            "selected_client": {
                "mac": "11:22:33:44:55:66",
                "associated_ap": "AA:BB:CC:DD:EE:FF",
            },
            "enabled_attacks": {
                "wifi_deauth": True,
                "wifi_handshake": False,
                "mitm_arp": True,
            },
            "attack_params": {
                "wifi_deauth": {"count": 10, "interval": 0.1},
            },
            "settings": {
                "monitor_iface": "wlan0mon",
                "ap_iface": "wlan1",
                "use_5ghz": True,
                "channels": [1, 6, 11, 36, 40],
                "rssi_limit": -70,
                "recon_duration": 45,
                "mitm_target_ip": "192.168.1.100",
                "mitm_gateway_ip": "192.168.1.1",
                "dns_spoof_domain": "evil.com",
                "wordlist_path": "/tmp/wordlist.txt",
                "cracking_mode": "brute-force",
            },
        }

    def test_save_load_roundtrip(self):
        """Test that saving and loading state produces identical data."""
        state = self._sample_state()
        result = self.persistence.save(state)
        self.assertTrue(result)

        loaded = self.persistence.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["selected_target"]["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(loaded["selected_target"]["ssid"], "TestNetwork")
        self.assertEqual(loaded["selected_client"]["mac"], "11:22:33:44:55:66")
        self.assertEqual(loaded["enabled_attacks"]["wifi_deauth"], True)
        self.assertEqual(loaded["enabled_attacks"]["wifi_handshake"], False)
        self.assertEqual(loaded["settings"]["monitor_iface"], "wlan0mon")
        self.assertEqual(loaded["settings"]["rssi_limit"], -70)
        self.assertEqual(loaded["settings"]["recon_duration"], 45)
        self.assertEqual(loaded["settings"]["cracking_mode"], "brute-force")

    def test_load_populates_fields(self):
        """Test that loaded state has all expected keys for field population."""
        state = self._sample_state()
        self.persistence.save(state)

        loaded = self.persistence.load()
        self.assertIn("selected_target", loaded)
        self.assertIn("selected_client", loaded)
        self.assertIn("enabled_attacks", loaded)
        self.assertIn("attack_params", loaded)
        self.assertIn("settings", loaded)

        settings = loaded["settings"]
        self.assertIn("monitor_iface", settings)
        self.assertIn("ap_iface", settings)
        self.assertIn("use_5ghz", settings)
        self.assertIn("rssi_limit", settings)
        self.assertIn("recon_duration", settings)
        self.assertIn("mitm_target_ip", settings)
        self.assertIn("mitm_gateway_ip", settings)
        self.assertIn("dns_spoof_domain", settings)
        self.assertIn("wordlist_path", settings)
        self.assertIn("cracking_mode", settings)

    def test_clear_removes_file(self):
        """Test that clear() removes the state file."""
        state = self._sample_state()
        self.persistence.save(state)
        self.assertTrue(Path(self.state_path).exists())

        result = self.persistence.clear()
        self.assertTrue(result)
        self.assertFalse(Path(self.state_path).exists())

    def test_clear_nonexistent_file(self):
        """Test that clear() succeeds even if file does not exist."""
        self.assertFalse(Path(self.state_path).exists())
        result = self.persistence.clear()
        self.assertTrue(result)

    def test_atomic_write_pattern(self):
        """Test that saves use atomic write (write .tmp then rename)."""
        state = self._sample_state()
        tmp_path = Path(self.state_path).with_suffix(".tmp")

        # After a successful save, the .tmp file should NOT remain
        # (it gets renamed to the final path)
        self.persistence.save(state)
        self.assertFalse(tmp_path.exists())
        self.assertTrue(Path(self.state_path).exists())

    def test_handles_missing_file(self):
        """Test that load() returns None gracefully for missing file."""
        loaded = self.persistence.load()
        self.assertIsNone(loaded)

    def test_handles_corrupted_json(self):
        """Test that load() handles corrupted JSON gracefully."""
        # Write invalid JSON
        Path(self.state_path).write_text("{ not valid json !!!}", encoding="utf-8")
        loaded = self.persistence.load()
        self.assertIsNone(loaded)

    def test_handles_non_dict_json(self):
        """Test that load() returns None if JSON is not a dict."""
        Path(self.state_path).write_text("[1, 2, 3]", encoding="utf-8")
        loaded = self.persistence.load()
        self.assertIsNone(loaded)

    def test_build_state(self):
        """Test the build_state convenience method."""
        target = {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "Test"}
        client = {"mac": "11:22:33:44:55:66"}
        attacks = {"wifi_deauth": True}
        params = {"wifi_deauth": {"count": 5}}
        settings = {"monitor_iface": "wlan0mon"}

        state = self.persistence.build_state(
            selected_target=target,
            selected_client=client,
            enabled_attacks=attacks,
            attack_params=params,
            settings=settings,
        )

        self.assertEqual(state["selected_target"]["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(state["selected_client"]["mac"], "11:22:33:44:55:66")
        self.assertEqual(state["enabled_attacks"]["wifi_deauth"], True)
        self.assertEqual(state["attack_params"]["wifi_deauth"]["count"], 5)
        self.assertEqual(state["settings"]["monitor_iface"], "wlan0mon")

    def test_save_creates_directory(self):
        """Test that save creates parent directories if they do not exist."""
        nested_path = os.path.join(self.tmp_dir, "sub", "dir", "state.json")
        persistence = AttackPersistence(state_path=nested_path)
        state = self._sample_state()
        result = persistence.save(state)
        self.assertTrue(result)
        self.assertTrue(Path(nested_path).exists())

    def test_overwrite_existing_state(self):
        """Test that saving overwrites previous state completely."""
        state1 = self._sample_state()
        self.persistence.save(state1)

        state2 = {
            "selected_target": {"bssid": "FF:EE:DD:CC:BB:AA", "ssid": "Other"},
            "selected_client": None,
            "enabled_attacks": {},
            "attack_params": {},
            "settings": {"monitor_iface": "wlan2mon"},
        }
        self.persistence.save(state2)

        loaded = self.persistence.load()
        self.assertEqual(loaded["selected_target"]["bssid"], "FF:EE:DD:CC:BB:AA")
        self.assertIsNone(loaded["selected_client"])
        self.assertEqual(loaded["settings"]["monitor_iface"], "wlan2mon")


if __name__ == "__main__":
    unittest.main()
