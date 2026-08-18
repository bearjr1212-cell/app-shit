"""
Unit Tests for tshark Decryption Engine

Tests decryption capability listing, argument building for various scenarios
(WPA-PSK, WEP, TLS), LiveDecryptionSession start/stop lifecycle, and parsing
of tshark JSON output for DNS/HTTP/DHCP extraction.
"""

import json
import subprocess
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, call, PropertyMock

from posframework.tshark_decrypt import (
    TsharkDecryptionEngine,
    LiveDecryptionSession,
    DECRYPTION_CAPABILITIES,
    PROTOCOL_DISSECTORS,
)


# ─── DECRYPTION_CAPABILITIES Tests ───────────────────────────────────────────


class TestDecryptionCapabilities(unittest.TestCase):
    """Tests for the DECRYPTION_CAPABILITIES dict."""

    def test_wpa_pwd_present(self):
        """WPA-PSK passphrase decryption should be listed."""
        self.assertIn("wpa-pwd", DECRYPTION_CAPABILITIES)
        self.assertEqual(DECRYPTION_CAPABILITIES["wpa-pwd"]["protocol"], "WPA/WPA2-PSK")

    def test_wpa_psk_present(self):
        """WPA2-PSK raw hex decryption should be listed."""
        self.assertIn("wpa-psk", DECRYPTION_CAPABILITIES)
        self.assertIn("psk hex", DECRYPTION_CAPABILITIES["wpa-psk"]["description"].lower())

    def test_wep_present(self):
        """WEP decryption should be listed."""
        self.assertIn("wep", DECRYPTION_CAPABILITIES)
        self.assertEqual(DECRYPTION_CAPABILITIES["wep"]["protocol"], "WEP")

    def test_tls_keylog_present(self):
        """TLS keylog decryption should be listed."""
        self.assertIn("tls-keylog", DECRYPTION_CAPABILITIES)
        self.assertIn("keylog", DECRYPTION_CAPABILITIES["tls-keylog"]["description"].lower())

    def test_all_entries_have_required_fields(self):
        """All entries should have protocol, description, tshark_option, key_format, requirements."""
        required_fields = {"protocol", "description", "tshark_option", "key_format", "requirements"}
        for name, entry in DECRYPTION_CAPABILITIES.items():
            for field in required_fields:
                self.assertIn(
                    field, entry,
                    f"Capability '{name}' missing field '{field}'"
                )


# ─── PROTOCOL_DISSECTORS Tests ───────────────────────────────────────────────


class TestProtocolDissectors(unittest.TestCase):
    """Tests for the PROTOCOL_DISSECTORS dict."""

    def test_minimum_10_protocols(self):
        """Must have at least 10 protocol dissectors listed."""
        self.assertGreaterEqual(len(PROTOCOL_DISSECTORS), 10)

    def test_required_protocols_present(self):
        """Core 802.11/network protocols should be present."""
        expected = [
            "wlan", "wlan_mgt", "eapol", "eap", "dns",
            "http", "dhcp", "mdns", "tls", "kerberos",
        ]
        for proto in expected:
            self.assertIn(proto, PROTOCOL_DISSECTORS, f"Missing protocol: {proto}")

    def test_all_entries_have_required_fields(self):
        """All dissector entries should have field_name, display_filter, description."""
        required_fields = {"field_name", "display_filter", "description"}
        for name, entry in PROTOCOL_DISSECTORS.items():
            for field in required_fields:
                self.assertIn(
                    field, entry,
                    f"Dissector '{name}' missing field '{field}'"
                )

    def test_descriptions_are_non_empty(self):
        """All protocol descriptions should be non-empty."""
        for name, entry in PROTOCOL_DISSECTORS.items():
            self.assertTrue(
                len(entry["description"]) > 10,
                f"Dissector '{name}' has too short a description"
            )


# ─── TsharkDecryptionEngine Tests ────────────────────────────────────────────


class TestTsharkDecryptionEngine(unittest.TestCase):
    """Tests for TsharkDecryptionEngine class."""

    def setUp(self):
        self.engine = TsharkDecryptionEngine()

    def test_list_capabilities_returns_dict(self):
        """list_capabilities should return a dict of strings."""
        caps = self.engine.list_capabilities()
        self.assertIsInstance(caps, dict)
        self.assertGreaterEqual(len(caps), 4)
        for key, value in caps.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, str)

    def test_list_capabilities_includes_wpa_psk(self):
        """list_capabilities should include WPA-PSK info."""
        caps = self.engine.list_capabilities()
        self.assertIn("wpa-pwd", caps)
        self.assertIn("WPA/WPA2-PSK", caps["wpa-pwd"])

    def test_list_dissectors_returns_dict(self):
        """list_dissectors should return protocol name to description map."""
        dissectors = self.engine.list_dissectors()
        self.assertIsInstance(dissectors, dict)
        self.assertGreaterEqual(len(dissectors), 10)
        self.assertIn("dns", dissectors)

    # ─── build_decrypt_args Tests ─────────────────────────────────────────────

    def test_build_decrypt_args_wpa_pwd(self):
        """WPA-PSK with passphrase and SSID should build correct args."""
        args = self.engine.build_decrypt_args(psk="MyPassword", ssid="TestNetwork")

        self.assertIn("-o", args)
        self.assertIn("wlan.enable_decryption:TRUE", args)

        # Should contain the key entry
        key_args = [a for a in args if "80211_keys" in a]
        self.assertTrue(len(key_args) > 0)
        self.assertIn("wpa-pwd", key_args[0])
        self.assertIn("MyPassword", key_args[0])
        self.assertIn("TestNetwork", key_args[0])

    def test_build_decrypt_args_wpa_psk_raw_hex(self):
        """WPA-PSK with 64-char hex key (no SSID) should use wpa-psk format."""
        hex_key = "a" * 64
        args = self.engine.build_decrypt_args(psk=hex_key)

        self.assertIn("wlan.enable_decryption:TRUE", args)
        key_args = [a for a in args if "80211_keys" in a]
        self.assertTrue(len(key_args) > 0)
        self.assertIn("wpa-psk", key_args[0])
        self.assertIn(hex_key, key_args[0])

    def test_build_decrypt_args_wep(self):
        """WEP keys should produce correct uat:80211_keys entries."""
        wep_keys = ["0102030405", "aabbccddee"]
        args = self.engine.build_decrypt_args(wep_keys=wep_keys)

        self.assertIn("wlan.enable_decryption:TRUE", args)
        key_args = [a for a in args if "80211_keys" in a]
        self.assertEqual(len(key_args), 2)
        self.assertIn("wep,0102030405", key_args[0])
        self.assertIn("wep,aabbccddee", key_args[1])

    @patch("os.path.isfile")
    def test_build_decrypt_args_tls_keylog(self, mock_isfile):
        """TLS keylog file should add tls.keylog_file option."""
        mock_isfile.return_value = True
        args = self.engine.build_decrypt_args(tls_keylog="/tmp/sslkeys.log")

        tls_args = [a for a in args if "tls.keylog_file" in a]
        self.assertTrue(len(tls_args) > 0)
        self.assertIn("/tmp/sslkeys.log", tls_args[0])

    @patch("os.path.isfile")
    def test_build_decrypt_args_tls_keylog_missing_file(self, mock_isfile):
        """Missing TLS keylog file should not add the option."""
        mock_isfile.return_value = False
        args = self.engine.build_decrypt_args(tls_keylog="/nonexistent/path.log")

        tls_args = [a for a in args if "tls.keylog_file" in a]
        self.assertEqual(len(tls_args), 0)

    def test_build_decrypt_args_no_keys(self):
        """No keys should produce empty args list."""
        args = self.engine.build_decrypt_args()
        self.assertEqual(args, [])

    def test_build_decrypt_args_psk_without_ssid_non_hex(self):
        """PSK without SSID (not hex) should warn and produce no key entry."""
        args = self.engine.build_decrypt_args(psk="shortkey")
        # Should not contain any key entry since no SSID and not valid hex PSK
        key_args = [a for a in args if "80211_keys" in a]
        self.assertEqual(len(key_args), 0)

    # ─── _get_tshark_path Tests ───────────────────────────────────────────────

    @patch("os.path.exists")
    def test_get_tshark_path_found(self, mock_exists):
        """Should find tshark when it exists on the filesystem."""
        mock_exists.side_effect = lambda p: p == "tshark"
        engine = TsharkDecryptionEngine()
        path = engine._get_tshark_path()
        self.assertEqual(path, "tshark")

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_get_tshark_path_via_which(self, mock_run, mock_exists):
        """Should find tshark via 'which' when not at known paths."""
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(
            returncode=0, stdout="/usr/bin/tshark\n"
        )
        engine = TsharkDecryptionEngine()
        path = engine._get_tshark_path()
        self.assertEqual(path, "/usr/bin/tshark")

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_get_tshark_path_not_found(self, mock_run, mock_exists):
        """Should return None when tshark is not found anywhere."""
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        engine = TsharkDecryptionEngine()
        path = engine._get_tshark_path()
        self.assertIsNone(path)

    @patch("os.path.exists")
    def test_is_available_true(self, mock_exists):
        """is_available should return True when tshark found."""
        mock_exists.side_effect = lambda p: p == "tshark"
        engine = TsharkDecryptionEngine()
        self.assertTrue(engine.is_available())

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_is_available_false(self, mock_run, mock_exists):
        """is_available should return False when tshark not found."""
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        engine = TsharkDecryptionEngine()
        self.assertFalse(engine.is_available())

    # ─── get_dissector_fields Tests ───────────────────────────────────────────

    def test_get_dissector_fields_default(self):
        """Default fields should include dns, http, dhcp, eapol."""
        fields = self.engine.get_dissector_fields()
        self.assertIn("-e", fields)
        self.assertIn("dns.qry.name", fields)
        self.assertIn("http.host", fields)
        self.assertIn("dhcp.option.hostname", fields)

    def test_get_dissector_fields_custom(self):
        """Custom protocol list should return only those fields."""
        fields = self.engine.get_dissector_fields(protocols=["dns"])
        self.assertIn("dns.qry.name", fields)
        self.assertNotIn("http.host", fields)

    def test_get_dissector_fields_unknown_protocol(self):
        """Unknown protocol name should produce no extra fields."""
        fields = self.engine.get_dissector_fields(protocols=["nonexistent"])
        # Should have no -e entries
        self.assertEqual(fields, [])


# ─── LiveDecryptionSession Tests ──────────────────────────────────────────────


class TestLiveDecryptionSession(unittest.TestCase):
    """Tests for LiveDecryptionSession lifecycle and output parsing."""

    def test_init_defaults(self):
        """Session should initialize with empty state."""
        session = LiveDecryptionSession()
        self.assertFalse(session.running)
        self.assertEqual(session._frame_count, 0)
        self.assertEqual(len(session._dns_queries), 0)
        self.assertEqual(len(session._http_requests), 0)
        self.assertEqual(len(session._dhcp_leases), 0)
        self.assertEqual(len(session._eapol_events), 0)
        self.assertEqual(len(session._credentials), 0)

    def test_init_with_callback(self):
        """Session should accept a callback function."""
        cb = MagicMock()
        session = LiveDecryptionSession(callback=cb)
        self.assertEqual(session._callback, cb)

    # ─── start() Tests ────────────────────────────────────────────────────────

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_start_returns_false_when_tshark_missing(self, mock_run, mock_exists):
        """start() should return False when tshark is not found."""
        mock_exists.return_value = False
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        session = LiveDecryptionSession()
        result = session.start("wlan0mon", psk="test", ssid="TestAP")

        self.assertFalse(result)
        self.assertFalse(session.running)

    @patch("subprocess.Popen")
    @patch("os.path.exists")
    def test_start_launches_tshark(self, mock_exists, mock_popen):
        """start() should launch tshark subprocess with correct arguments."""
        mock_exists.side_effect = lambda p: p == "tshark"
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        session = LiveDecryptionSession()
        result = session.start("wlan0mon", psk="MyPass", ssid="MyAP")

        self.assertTrue(result)
        self.assertTrue(session.running)

        # Verify tshark was called with expected args
        call_args = mock_popen.call_args
        cmd = call_args[0][0]
        self.assertEqual(cmd[0], "tshark")
        self.assertIn("-i", cmd)
        self.assertIn("wlan0mon", cmd)
        self.assertIn("-T", cmd)
        self.assertIn("json", cmd)

        session.stop()

    @patch("subprocess.Popen")
    @patch("os.path.exists")
    def test_start_oserror_returns_false(self, mock_exists, mock_popen):
        """start() should return False when Popen raises OSError."""
        mock_exists.side_effect = lambda p: p == "tshark"
        mock_popen.side_effect = OSError("Permission denied")

        session = LiveDecryptionSession()
        result = session.start("wlan0mon", psk="test", ssid="TestAP")

        self.assertFalse(result)
        self.assertFalse(session.running)

    # ─── stop() Tests ─────────────────────────────────────────────────────────

    @patch("subprocess.Popen")
    @patch("os.path.exists")
    def test_stop_terminates_process(self, mock_exists, mock_popen):
        """stop() should terminate the tshark process."""
        mock_exists.side_effect = lambda p: p == "tshark"
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock()
        mock_popen.return_value = mock_proc

        session = LiveDecryptionSession()
        session.start("wlan0mon", psk="test", ssid="AP")
        session.stop()

        mock_proc.terminate.assert_called_once()
        self.assertFalse(session.running)

    @patch("subprocess.Popen")
    @patch("os.path.exists")
    def test_stop_kills_on_timeout(self, mock_exists, mock_popen):
        """stop() should kill tshark if it does not terminate within timeout."""
        mock_exists.side_effect = lambda p: p == "tshark"
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(
            side_effect=[subprocess.TimeoutExpired("tshark", 5), None]
        )
        mock_proc.kill = MagicMock()
        mock_popen.return_value = mock_proc

        session = LiveDecryptionSession()
        session.start("wlan0mon", psk="test", ssid="AP")
        session.stop()

        mock_proc.kill.assert_called_once()

    def test_stop_when_not_started(self):
        """stop() should not raise when session was never started."""
        session = LiveDecryptionSession()
        # Should not raise
        session.stop()
        self.assertFalse(session.running)

    # ─── JSON Parsing Tests ───────────────────────────────────────────────────

    def test_parse_dns_frame(self):
        """Should extract DNS query name and response address."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "dns": {
                        "dns.qry.name": "pos.payment-gateway.com",
                        "dns.a": "10.0.1.50",
                        "dns.resp.name": "pos.payment-gateway.com",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(session._frame_count, 1)
        self.assertEqual(len(session._dns_queries), 1)
        self.assertEqual(session._dns_queries[0]["query"], "pos.payment-gateway.com")
        self.assertEqual(session._dns_queries[0]["response"], "10.0.1.50")

    def test_parse_http_frame(self):
        """Should extract HTTP host, method, and URI."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "http": {
                        "http.host": "api.merchant.com",
                        "http.request.method": "POST",
                        "http.request.uri": "/v2/transaction",
                        "http.user_agent": "POS-Terminal/3.1",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(session._frame_count, 1)
        self.assertEqual(len(session._http_requests), 1)
        self.assertEqual(session._http_requests[0]["host"], "api.merchant.com")
        self.assertEqual(session._http_requests[0]["method"], "POST")
        self.assertEqual(session._http_requests[0]["uri"], "/v2/transaction")

    def test_parse_http_with_auth_header(self):
        """Should extract HTTP authorization header as credential."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "http": {
                        "http.host": "admin.pos-system.local",
                        "http.request.method": "GET",
                        "http.request.uri": "/api/config",
                        "http.authorization": "Basic YWRtaW46cGFzc3dvcmQ=",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(len(session._http_requests), 1)
        self.assertEqual(len(session._credentials), 1)
        self.assertEqual(session._credentials[0]["protocol"], "http")
        self.assertEqual(session._credentials[0]["type"], "authorization_header")
        self.assertIn("Basic", session._credentials[0]["value"])

    def test_parse_dhcp_frame(self):
        """Should extract DHCP hostname and MAC address."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "dhcp": {
                        "dhcp.option.hostname": "POS-TERMINAL-01",
                        "dhcp.option.requested_ip_address": "192.168.1.100",
                        "dhcp.hw.mac_addr": "aa:bb:cc:dd:ee:ff",
                        "dhcp.option.vendor_class_id": "MSFT 5.0",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(session._frame_count, 1)
        self.assertEqual(len(session._dhcp_leases), 1)
        self.assertEqual(session._dhcp_leases[0]["hostname"], "POS-TERMINAL-01")
        self.assertEqual(session._dhcp_leases[0]["mac_addr"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(session._dhcp_leases[0]["requested_ip"], "192.168.1.100")
        self.assertEqual(session._dhcp_leases[0]["vendor_class"], "MSFT 5.0")

    def test_parse_eapol_frame(self):
        """Should extract EAPOL handshake event."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "eapol": {
                        "eapol.type": "3",
                    },
                    "wlan": {
                        "wlan.sa": "aa:bb:cc:dd:ee:ff",
                        "wlan.da": "11:22:33:44:55:66",
                        "wlan.bssid": "11:22:33:44:55:66",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(session._frame_count, 1)
        self.assertEqual(len(session._eapol_events), 1)
        self.assertEqual(session._eapol_events[0]["type"], "3")
        self.assertEqual(session._eapol_events[0]["source"], "aa:bb:cc:dd:ee:ff")

    def test_parse_alternative_json_format(self):
        """Should handle alternative tshark JSON format (layers at top level)."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "layers": {
                "dns": {
                    "dns.qry.name": "test.example.com",
                    "dns.a": "1.2.3.4",
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(session._frame_count, 1)
        self.assertEqual(len(session._dns_queries), 1)
        self.assertEqual(session._dns_queries[0]["query"], "test.example.com")

    def test_parse_invalid_json(self):
        """Should handle invalid JSON gracefully."""
        session = LiveDecryptionSession()
        session._parse_json_frame("not valid json{{{")

        self.assertEqual(session._frame_count, 0)
        self.assertEqual(len(session._dns_queries), 0)

    def test_parse_empty_layers(self):
        """Should handle frame with no layers gracefully."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({"_source": {"layers": {}}})
        session._parse_json_frame(frame_json)

        self.assertEqual(session._frame_count, 1)
        self.assertEqual(len(session._dns_queries), 0)

    def test_parse_dns_with_list_values(self):
        """Should handle DNS fields that are lists (multiple answers)."""
        session = LiveDecryptionSession()
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "dns": {
                        "dns.qry.name": ["cdn.paymentgateway.com"],
                        "dns.a": ["10.0.0.1", "10.0.0.2"],
                        "dns.resp.name": ["cdn.paymentgateway.com"],
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        self.assertEqual(session._dns_queries[0]["query"], "cdn.paymentgateway.com")
        self.assertEqual(session._dns_queries[0]["response"], "10.0.0.1")

    # ─── get_decrypted_summary Tests ──────────────────────────────────────────

    def test_get_decrypted_summary_empty(self):
        """Summary should return empty state when no data captured."""
        session = LiveDecryptionSession()
        session._start_time = time.time()
        summary = session.get_decrypted_summary()

        self.assertEqual(summary["frame_count"], 0)
        self.assertEqual(summary["dns_queries"], [])
        self.assertEqual(summary["http_requests"], [])
        self.assertEqual(summary["dhcp_leases"], [])
        self.assertEqual(summary["eapol_events"], [])
        self.assertEqual(summary["credentials"], [])
        self.assertIsInstance(summary["duration_seconds"], float)

    def test_get_decrypted_summary_with_data(self):
        """Summary should reflect parsed frames."""
        session = LiveDecryptionSession()
        session._start_time = time.time() - 10.0
        session._frame_count = 5
        session._dns_queries.append({"query": "test.com", "response": "1.2.3.4"})
        session._http_requests.append({"host": "web.com", "method": "GET"})

        summary = session.get_decrypted_summary()

        self.assertEqual(summary["frame_count"], 5)
        self.assertEqual(len(summary["dns_queries"]), 1)
        self.assertEqual(len(summary["http_requests"]), 1)
        self.assertGreaterEqual(summary["duration_seconds"], 10.0)

    # ─── Callback Tests ───────────────────────────────────────────────────────

    def test_callback_invoked_on_dns(self):
        """Callback should be invoked when DNS data is parsed."""
        cb = MagicMock()
        session = LiveDecryptionSession(callback=cb)
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "dns": {
                        "dns.qry.name": "callback.test.com",
                        "dns.a": "5.6.7.8",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        cb.assert_called_once()
        call_data = cb.call_args[0][0]
        self.assertEqual(call_data["protocol"], "dns")
        self.assertEqual(call_data["data"]["query"], "callback.test.com")
        self.assertIn("timestamp", call_data)

    def test_callback_invoked_on_http(self):
        """Callback should be invoked when HTTP data is parsed."""
        cb = MagicMock()
        session = LiveDecryptionSession(callback=cb)
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "http": {
                        "http.host": "callback-test.com",
                        "http.request.method": "POST",
                        "http.request.uri": "/data",
                    }
                }
            }
        })

        session._parse_json_frame(frame_json)

        cb.assert_called_once()
        call_data = cb.call_args[0][0]
        self.assertEqual(call_data["protocol"], "http")

    def test_callback_exception_does_not_crash(self):
        """Callback that raises should not crash the session."""
        cb = MagicMock(side_effect=RuntimeError("callback error"))
        session = LiveDecryptionSession(callback=cb)
        frame_json = json.dumps({
            "_source": {
                "layers": {
                    "dns": {"dns.qry.name": "fail.test.com", "dns.a": "1.1.1.1"}
                }
            }
        })

        # Should not raise
        session._parse_json_frame(frame_json)
        self.assertEqual(session._frame_count, 1)

    # ─── Bounded Deque Tests ──────────────────────────────────────────────────

    def test_data_lists_are_bounded(self):
        """Data lists should be bounded deques to prevent unbounded memory growth."""
        from collections import deque
        session = LiveDecryptionSession()
        self.assertIsInstance(session._dns_queries, deque)
        self.assertIsInstance(session._http_requests, deque)
        self.assertIsInstance(session._dhcp_leases, deque)
        self.assertIsInstance(session._eapol_events, deque)
        self.assertIsInstance(session._credentials, deque)
        self.assertEqual(session._dns_queries.maxlen, LiveDecryptionSession.MAX_ENTRIES)

    def test_bounded_deque_evicts_oldest(self):
        """When maxlen is exceeded, oldest entries should be evicted."""
        session = LiveDecryptionSession()
        # Override maxlen with a small value for testing
        from collections import deque
        session._dns_queries = deque(maxlen=3)
        for i in range(5):
            session._dns_queries.append({"query": f"test{i}.com"})
        # Only the last 3 should remain
        self.assertEqual(len(session._dns_queries), 3)
        self.assertEqual(session._dns_queries[0]["query"], "test2.com")
        self.assertEqual(session._dns_queries[2]["query"], "test4.com")

    # ─── Context Manager Tests ────────────────────────────────────────────────

    @patch("subprocess.Popen")
    @patch("os.path.exists")
    def test_context_manager(self, mock_exists, mock_popen):
        """Session should support context manager protocol."""
        mock_exists.side_effect = lambda p: p == "tshark"
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock()
        mock_popen.return_value = mock_proc

        with LiveDecryptionSession() as session:
            session.start("wlan0mon", psk="test", ssid="TestAP")
            self.assertTrue(session.running)

        mock_proc.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
