"""
Tests for IntelEnricher and TargetQueue modules.
Standalone test runner (no pytest required).
"""

import sys
import os
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posframework.intel_enricher import IntelEnricher
from posframework.target_queue import (
    TargetQueue, ATTACK_VECTORS, TARGET_TYPES, ATTACK_PROFILES
)


class TestIntelEnricher(unittest.TestCase):
    """Tests for IntelEnricher lifecycle and polling."""

    def test_instantiation(self):
        """IntelEnricher can be created with a mock database."""
        db = MagicMock()
        enricher = IntelEnricher(interface="wlan0mon", db=db)
        self.assertFalse(enricher.running)
        self.assertEqual(enricher.interface, "wlan0mon")

    def test_start_no_tools_available(self):
        """IntelEnricher starts gracefully when no tools are installed."""
        db = MagicMock()
        # Disable all tools so none will start
        enricher = IntelEnricher(
            interface="wlan0mon", db=db,
            enable_p0f=False, enable_horst=False, enable_kismet=False
        )
        result = enricher.start()
        self.assertEqual(result, 0)
        self.assertFalse(enricher.running)

    @patch("posframework.intel_enricher.IntelEnricher._start_p0f", return_value=True)
    @patch("posframework.intel_enricher.IntelEnricher._start_horst", return_value=False)
    @patch("posframework.intel_enricher.IntelEnricher._start_kismet", return_value=False)
    def test_start_with_p0f_only(self, mock_kismet, mock_horst, mock_p0f):
        """IntelEnricher starts with only p0f available."""
        db = MagicMock()
        enricher = IntelEnricher(interface="wlan0mon", db=db)
        result = enricher.start()
        self.assertEqual(result, 1)
        self.assertTrue(enricher.running)
        enricher.stop()
        self.assertFalse(enricher.running)

    @patch("posframework.intel_enricher.IntelEnricher._start_p0f", return_value=True)
    @patch("posframework.intel_enricher.IntelEnricher._start_horst", return_value=True)
    @patch("posframework.intel_enricher.IntelEnricher._start_kismet", return_value=True)
    def test_start_all_tools(self, mock_kismet, mock_horst, mock_p0f):
        """IntelEnricher starts all 3 tools."""
        db = MagicMock()
        enricher = IntelEnricher(interface="wlan0mon", db=db)
        result = enricher.start()
        self.assertEqual(result, 3)
        self.assertTrue(enricher.running)
        enricher.stop()

    def test_get_summary_empty(self):
        """Summary is empty before any polling."""
        db = MagicMock()
        enricher = IntelEnricher(interface="wlan0mon", db=db)
        summary = enricher.get_summary()
        self.assertEqual(summary["os_fingerprints"], 0)
        self.assertEqual(summary["signal_entries"], 0)
        self.assertEqual(summary["device_types"], 0)
        self.assertFalse(summary["running"])

    def test_stop_idempotent(self):
        """Calling stop multiple times doesn't raise."""
        db = MagicMock()
        enricher = IntelEnricher(interface="wlan0mon", db=db)
        enricher.stop()
        enricher.stop()  # Should not raise

    def test_double_start_ignored(self):
        """Starting an already-running enricher returns 0."""
        db = MagicMock()
        enricher = IntelEnricher(interface="wlan0mon", db=db)
        enricher._running = True  # Simulate already running
        result = enricher.start()
        self.assertEqual(result, 0)
        enricher._running = False


class TestTargetQueue(unittest.TestCase):
    """Tests for TargetQueue dynamic target list."""

    def _make_mock_db(self, aps=None):
        """Create a mock database with preset AP data."""
        db = MagicMock()
        cursor = MagicMock()
        db.cursor = cursor

        if aps is None:
            aps = [
                # (bssid, ssid, vendor, channel, security, rssi, is_pos_vendor, is_pos_ssid, is_hidden)
                ("AA:BB:CC:DD:EE:01", "POS-Terminal-1", "Verifone", 6, "WPA2", -45, 1, 1, 0),
                ("AA:BB:CC:DD:EE:02", "HomeWiFi", "TP-Link", 11, "WPA2", -60, 0, 0, 0),
                ("AA:BB:CC:DD:EE:03", "CorpNet", "Cisco", 1, "WPA2/802.1X", -55, 0, 0, 0),
                ("AA:BB:CC:DD:EE:04", "IoT-Sensor", "Espressif", 6, "OPEN", -70, 0, 0, 0),
            ]

        cursor.execute = MagicMock()
        cursor.fetchall = MagicMock(return_value=aps)
        db.get_clients_for_bssid = MagicMock(return_value=[
            ("11:22:33:44:55:01", -50),
            ("11:22:33:44:55:02", -65),
        ])
        return db

    def test_instantiation(self):
        """TargetQueue can be created."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        self.assertIsNotNone(queue)

    def test_refresh_populates_targets(self):
        """Refresh pulls APs from database and creates target entries."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        count = queue.refresh()
        self.assertEqual(count, 4)

    def test_pos_target_highest_priority(self):
        """POS targets get the highest priority score."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()
        # POS target should be first
        self.assertTrue(targets[0]["is_pos"])
        self.assertEqual(targets[0]["target_type"], "pos")

    def test_target_types_classified(self):
        """Targets are classified by type correctly."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        types = {t["ssid"]: t["target_type"] for t in targets}
        self.assertEqual(types["POS-Terminal-1"], "pos")
        self.assertEqual(types["IoT-Sensor"], "iot")
        self.assertEqual(types["CorpNet"], "enterprise")
        self.assertEqual(types["HomeWiFi"], "consumer")

    def test_attack_vectors_assigned(self):
        """Each target gets applicable attack vectors."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        for target in targets:
            self.assertGreater(len(target["attack_vectors"]), 0)
            for vector in target["attack_vectors"]:
                self.assertIn("id", vector)
                self.assertIn("name", vector)
                self.assertIn("ready", vector)

    def test_attack_profiles_assigned(self):
        """Each target gets an attack profile."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        for target in targets:
            self.assertIn(target["attack_profile"], ATTACK_PROFILES)
            self.assertIn("profile_config", target)

    def test_pos_gets_aggressive_profile(self):
        """POS targets are assigned aggressive profile."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        pos_target = next(t for t in targets if t["is_pos"])
        self.assertEqual(pos_target["attack_profile"], "aggressive")

    def test_enterprise_gets_stealth_profile(self):
        """Enterprise targets are assigned stealth profile."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        enterprise_target = next(t for t in targets if t["target_type"] == "enterprise")
        self.assertEqual(enterprise_target["attack_profile"], "stealth")

    def test_get_top_targets(self):
        """get_top_targets returns limited count."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        top = queue.get_top_targets(count=2)
        self.assertEqual(len(top), 2)

    def test_get_target_by_bssid(self):
        """Can look up a target by BSSID."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        target = queue.get_target_by_bssid("AA:BB:CC:DD:EE:02")
        self.assertIsNotNone(target)
        self.assertEqual(target["ssid"], "HomeWiFi")

    def test_get_target_by_bssid_not_found(self):
        """Returns None for unknown BSSID."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        target = queue.get_target_by_bssid("FF:FF:FF:FF:FF:FF")
        self.assertIsNone(target)

    def test_open_network_gets_deauth_vector(self):
        """OPEN networks should still get deauth vector."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        open_target = next(t for t in targets if "OPEN" in t["security"])
        vector_ids = [v["id"] for v in open_target["attack_vectors"]]
        self.assertIn("deauth", vector_ids)

    def test_wpa2_gets_handshake_vector(self):
        """WPA2 targets should get handshake capture vector."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        wpa2_target = next(
            t for t in targets
            if "WPA2" in t["security"] and "802.1X" not in t["security"]
            and not t["is_pos"]
        )
        vector_ids = [v["id"] for v in wpa2_target["attack_vectors"]]
        self.assertIn("handshake_capture", vector_ids)

    def test_automate_prerequisites(self):
        """automate_prerequisites attempts to fulfill missing prereqs."""
        db = self._make_mock_db()
        queue = TargetQueue(db=db)
        queue.refresh()
        targets = queue.get_prioritized()

        # Get a target with some vectors
        target = targets[0]
        # This should not raise regardless of what's available
        automated = queue.automate_prerequisites(target)
        self.assertIsInstance(automated, list)

    def test_attack_vectors_constants(self):
        """ATTACK_VECTORS registry has expected entries."""
        self.assertIn("deauth", ATTACK_VECTORS)
        self.assertIn("handshake_capture", ATTACK_VECTORS)
        self.assertIn("evil_twin", ATTACK_VECTORS)
        self.assertIn("karma", ATTACK_VECTORS)
        self.assertIn("krack", ATTACK_VECTORS)

    def test_target_types_constants(self):
        """TARGET_TYPES registry has expected entries."""
        self.assertIn("pos", TARGET_TYPES)
        self.assertIn("iot", TARGET_TYPES)
        self.assertIn("enterprise", TARGET_TYPES)
        self.assertIn("consumer", TARGET_TYPES)

    def test_attack_profiles_constants(self):
        """ATTACK_PROFILES registry has expected entries."""
        self.assertIn("aggressive", ATTACK_PROFILES)
        self.assertIn("balanced", ATTACK_PROFILES)
        self.assertIn("stealth", ATTACK_PROFILES)

    def test_empty_database(self):
        """Queue handles empty database gracefully."""
        db = MagicMock()
        db.cursor = MagicMock()
        db.cursor.execute = MagicMock()
        db.cursor.fetchall = MagicMock(return_value=[])
        queue = TargetQueue(db=db)
        count = queue.refresh()
        self.assertEqual(count, 0)
        self.assertEqual(queue.get_prioritized(), [])


class TestReconStopEvent(unittest.TestCase):
    """Tests for ReconEngine stop event integration."""

    def test_recon_has_stop_event(self):
        """ReconEngine has _stop_event attribute."""
        try:
            import posframework.recon as recon_mod
            import inspect
            source = inspect.getsource(recon_mod.ReconEngine.__init__)
            self.assertIn("_stop_event", source)
            self.assertIn("threading.Event", source)
        except ImportError:
            # scapy not available in test env - verify via AST
            import ast
            with open(os.path.join(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__))), "posframework", "recon.py")) as f:
                source = f.read()
            tree = ast.parse(source)
            self.assertIn("_stop_event", source)
            self.assertIn("threading.Event()", source)

    def test_recon_accepts_intel_enricher(self):
        """ReconEngine __init__ accepts intel_enricher parameter."""
        try:
            import inspect
            from posframework.recon import ReconEngine
            sig = inspect.signature(ReconEngine.__init__)
            self.assertIn("intel_enricher", sig.parameters)
        except ImportError:
            # scapy not available - verify via source text
            with open(os.path.join(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__))), "posframework", "recon.py")) as f:
                source = f.read()
            self.assertIn("intel_enricher=None", source)


if __name__ == "__main__":
    # Standalone test runner
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestIntelEnricher))
    suite.addTests(loader.loadTestsFromTestCase(TestTargetQueue))
    suite.addTests(loader.loadTestsFromTestCase(TestReconStopEvent))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    total = result.testsRun
    failures = len(result.failures) + len(result.errors)
    print(f"\nResults: {total - failures} passed, {failures} failed")
    sys.exit(0 if failures == 0 else 1)
