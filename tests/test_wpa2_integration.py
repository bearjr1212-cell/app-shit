"""
Integration tests for WPA2 module usage in orchestrator, cred_tester, and pmkid.

Tests verify that:
1. orchestrator.verify_credential returns True for correct password
2. cred_tester.test_wifi_password_native returns True for correct PSK
3. pmkid.compute_pmkid produces correct PMKID per IEEE 802.11-2020 spec
"""

import hashlib
import hmac
import struct
import pytest

from posframework.wpa2 import (
    derive_pmk,
    derive_ptk,
    extract_key_hierarchy,
    compute_eapol_mic,
    verify_eapol_mic,
    EAPOLKeyFrame,
    CipherSuite,
    KEY_INFO_TYPE_HMAC_SHA1,
    KEY_INFO_PAIRWISE,
    KEY_INFO_ACK,
    KEY_INFO_MIC,
    WPA2Handshake,
    HandshakeRole,
)
from posframework.pmkid import PMKIDCapture
from posframework.cred_tester import CredentialTester


# --- Test Vectors ---
# IEEE 802.11-2020 Annex J test vectors (simplified)
TEST_PASSPHRASE = "password"
TEST_SSID = "IEEE"
# Expected PMK for passphrase="password", SSID="IEEE" per Annex J.4
TEST_PMK_HEX = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"

TEST_AP_MAC = b'\x00\x0b\x86\xc2\xa4\x85'  # Example AP MAC
TEST_STA_MAC = b'\x00\x13\xce\x55\x98\xef'  # Example STA MAC


def _build_test_handshake_frames(passphrase, ssid, ap_mac, sta_mac):
    """
    Build a synthetic WPA2 4-way handshake (Msg1 + Msg2) for testing.

    Uses the WPA2Handshake state machine to generate valid frames
    with proper MICs.
    """
    # Derive PMK
    pmk = derive_pmk(passphrase, ssid)

    # Create authenticator and supplicant handshake state machines
    auth = WPA2Handshake(
        role=HandshakeRole.AUTHENTICATOR,
        own_mac=ap_mac,
        peer_mac=sta_mac,
        pmk=pmk,
        cipher=CipherSuite.CCMP,
    )
    supplicant = WPA2Handshake(
        role=HandshakeRole.SUPPLICANT,
        own_mac=sta_mac,
        peer_mac=ap_mac,
        pmk=pmk,
        cipher=CipherSuite.CCMP,
    )

    # Generate Msg1 (AP -> STA)
    msg1_bytes = auth.start_authenticator()

    # Supplicant processes Msg1 and generates Msg2
    msg2_bytes = supplicant.process_msg1(msg1_bytes)

    return msg1_bytes, msg2_bytes


class TestOrchestratorVerifyCredential:
    """Tests for AttackOrchestrator.verify_credential()."""

    def _make_orchestrator(self):
        """Create a minimal orchestrator for testing (no real interfaces)."""
        from unittest.mock import MagicMock, patch

        # Mock out heavy dependencies that need real wireless hardware
        with patch('posframework.orchestrator.ReconEngine'), \
             patch('posframework.orchestrator.DeauthEngine'), \
             patch('posframework.orchestrator.HandshakeCapture') as mock_hc, \
             patch('posframework.orchestrator.POSDatabase'), \
             patch('posframework.orchestrator.SignalTargeting'), \
             patch('posframework.orchestrator.get_event_bus'):

            from posframework.orchestrator import AttackOrchestrator

            orch = AttackOrchestrator(
                monitor_iface="wlan0mon",
                ap_iface="wlan1",
                test_credentials=False,  # Skip CredentialTester init
            )
            return orch

    def test_verify_correct_password(self):
        """verify_credential returns True for correct password with valid handshake."""
        orch = self._make_orchestrator()
        orch.target_bssid = "00:0b:86:c2:a4:85"

        # Build valid handshake frames
        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )

        # Mock the handshakes object to return the STA MAC
        from unittest.mock import MagicMock
        orch.handshakes = MagicMock()
        orch.handshakes._handshakes = {"00:13:ce:55:98:ef": {}}

        result = orch.verify_credential(TEST_SSID, TEST_PASSPHRASE, [msg1, msg2])
        assert result is True

    def test_verify_wrong_password(self):
        """verify_credential returns False for wrong password."""
        orch = self._make_orchestrator()
        orch.target_bssid = "00:0b:86:c2:a4:85"

        # Build handshake with correct password
        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )

        # Mock the handshakes object
        from unittest.mock import MagicMock
        orch.handshakes = MagicMock()
        orch.handshakes._handshakes = {"00:13:ce:55:98:ef": {}}

        # Try with wrong password
        result = orch.verify_credential(TEST_SSID, "wrongpassword", [msg1, msg2])
        assert result is False

    def test_verify_no_wpa2_module(self):
        """verify_credential returns False when WPA2 module is unavailable."""
        orch = self._make_orchestrator()

        import posframework.orchestrator as orch_module
        original = orch_module._HAS_WPA2
        try:
            orch_module._HAS_WPA2 = False
            result = orch.verify_credential("test", "password", [b'\x00' * 99])
            assert result is False
        finally:
            orch_module._HAS_WPA2 = original

    def test_verify_insufficient_frames(self):
        """verify_credential returns False with insufficient handshake frames."""
        orch = self._make_orchestrator()
        orch.target_bssid = "00:0b:86:c2:a4:85"

        result = orch.verify_credential(TEST_SSID, TEST_PASSPHRASE, [b'\x00' * 99])
        assert result is False


class TestCredTesterNative:
    """Tests for CredentialTester.test_wifi_password_native()."""

    def test_native_correct_password(self):
        """test_wifi_password_native returns True for correct PSK."""
        tester = CredentialTester("wlan0mon")

        # Build valid handshake
        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )

        # Provide frames as tuples with STA MAC
        sta_mac_str = "00:13:ce:55:98:ef"
        frames = [(msg1, sta_mac_str), (msg2, sta_mac_str)]

        result = tester.test_wifi_password_native(
            "00:0b:86:c2:a4:85", TEST_SSID, TEST_PASSPHRASE, frames
        )
        assert result is True

    def test_native_wrong_password(self):
        """test_wifi_password_native returns False for wrong password."""
        tester = CredentialTester("wlan0mon")

        # Build valid handshake with correct password
        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )

        sta_mac_str = "00:13:ce:55:98:ef"
        frames = [(msg1, sta_mac_str), (msg2, sta_mac_str)]

        result = tester.test_wifi_password_native(
            "00:0b:86:c2:a4:85", TEST_SSID, "wrongpassword", frames
        )
        assert result is False

    def test_native_no_frames(self):
        """test_wifi_password_native returns None when no frames provided."""
        tester = CredentialTester("wlan0mon")

        result = tester.test_wifi_password_native(
            "00:0b:86:c2:a4:85", TEST_SSID, TEST_PASSPHRASE, []
        )
        assert result is None

    def test_native_plain_bytes_no_sta_mac(self):
        """test_wifi_password_native returns None when STA MAC unavailable."""
        tester = CredentialTester("wlan0mon")

        # Provide frames as plain bytes (no STA MAC)
        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )

        # Plain bytes without STA MAC tuple format
        frames = [msg1, msg2]

        result = tester.test_wifi_password_native(
            "00:0b:86:c2:a4:85", TEST_SSID, TEST_PASSPHRASE, frames
        )
        assert result is None


class TestPMKIDCompute:
    """Tests for PMKIDCapture.compute_pmkid() and verify_pmkid()."""

    def test_compute_pmkid_format(self):
        """compute_pmkid returns 16 bytes."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)
        assert len(pmkid) == 16
        assert isinstance(pmkid, bytes)

    def test_compute_pmkid_deterministic(self):
        """compute_pmkid is deterministic for same inputs."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid1 = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)
        pmkid2 = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)
        assert pmkid1 == pmkid2

    def test_compute_pmkid_ieee_spec(self):
        """compute_pmkid matches IEEE 802.11-2020 formula: HMAC-SHA1-128(PMK, 'PMK Name' || MAC_AP || MAC_STA)."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)

        # Manually compute expected PMKID per spec
        data = b"PMK Name" + TEST_AP_MAC + TEST_STA_MAC
        expected = hmac.new(pmk, data, hashlib.sha1).digest()[:16]

        computed = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)
        assert computed == expected

    def test_compute_pmkid_different_passwords(self):
        """Different passwords produce different PMKIDs."""
        pmk1 = derive_pmk("password1", TEST_SSID)
        pmk2 = derive_pmk("password2", TEST_SSID)
        pmkid1 = PMKIDCapture.compute_pmkid(pmk1, TEST_AP_MAC, TEST_STA_MAC)
        pmkid2 = PMKIDCapture.compute_pmkid(pmk2, TEST_AP_MAC, TEST_STA_MAC)
        assert pmkid1 != pmkid2

    def test_compute_pmkid_string_macs(self):
        """compute_pmkid accepts string MAC addresses."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid1 = PMKIDCapture.compute_pmkid(pmk, "00:0b:86:c2:a4:85", "00:13:ce:55:98:ef")
        pmkid2 = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)
        assert pmkid1 == pmkid2

    def test_verify_pmkid_correct_password(self):
        """verify_pmkid returns True for the correct password."""
        from unittest.mock import patch

        cap = PMKIDCapture.__new__(PMKIDCapture)
        cap._lock = __import__('threading').Lock()
        cap._pmkids = {}

        # Compute and store a PMKID as if captured
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        bssid = "00:0b:86:c2:a4:85"
        client_mac = "00:13:ce:55:98:ef"
        cap._pmkids[(client_mac, bssid)] = {
            "pmkid": pmkid.hex(),
            "essid": TEST_SSID,
            "frame": None,
            "timestamp": 0,
        }

        result = cap.verify_pmkid(bssid, client_mac, TEST_PASSPHRASE, TEST_SSID)
        assert result is True

    def test_verify_pmkid_wrong_password(self):
        """verify_pmkid returns False for a wrong password."""
        cap = PMKIDCapture.__new__(PMKIDCapture)
        cap._lock = __import__('threading').Lock()
        cap._pmkids = {}

        # Store a PMKID computed with correct password
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        bssid = "00:0b:86:c2:a4:85"
        client_mac = "00:13:ce:55:98:ef"
        cap._pmkids[(client_mac, bssid)] = {
            "pmkid": pmkid.hex(),
            "essid": TEST_SSID,
            "frame": None,
            "timestamp": 0,
        }

        result = cap.verify_pmkid(bssid, client_mac, "wrongpassword", TEST_SSID)
        assert result is False

    def test_try_passwords_finds_correct(self):
        """try_passwords returns the correct password from a list."""
        cap = PMKIDCapture.__new__(PMKIDCapture)
        cap._lock = __import__('threading').Lock()
        cap._pmkids = {}

        # Store PMKID
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        bssid = "00:0b:86:c2:a4:85"
        client_mac = "00:13:ce:55:98:ef"
        cap._pmkids[(client_mac, bssid)] = {
            "pmkid": pmkid.hex(),
            "essid": TEST_SSID,
            "frame": None,
            "timestamp": 0,
        }

        passwords = ["wrong1", "wrong2", TEST_PASSPHRASE, "wrong3"]
        result = cap.try_passwords(bssid, passwords, TEST_SSID)
        assert result == TEST_PASSPHRASE

    def test_try_passwords_none_match(self):
        """try_passwords returns None when no password matches."""
        cap = PMKIDCapture.__new__(PMKIDCapture)
        cap._lock = __import__('threading').Lock()
        cap._pmkids = {}

        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        pmkid = PMKIDCapture.compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        bssid = "00:0b:86:c2:a4:85"
        client_mac = "00:13:ce:55:98:ef"
        cap._pmkids[(client_mac, bssid)] = {
            "pmkid": pmkid.hex(),
            "essid": TEST_SSID,
            "frame": None,
            "timestamp": 0,
        }

        passwords = ["wrong1", "wrong2", "wrong3"]
        result = cap.try_passwords(bssid, passwords, TEST_SSID)
        assert result is None


class TestPMKDerivation:
    """Test PMK derivation with known test vectors."""

    def test_pmk_ieee_annex_j(self):
        """Verify PMK matches IEEE 802.11-2020 Annex J.4 test vector."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        assert pmk.hex() == TEST_PMK_HEX

    def test_pmk_length(self):
        """PMK is always 32 bytes (256 bits)."""
        pmk = derive_pmk("anypassword", "AnySSID")
        assert len(pmk) == 32


class TestImports:
    """Verify all integration imports work correctly."""

    def test_orchestrator_import(self):
        """Import AttackOrchestrator without error."""
        from posframework.orchestrator import AttackOrchestrator
        assert AttackOrchestrator is not None

    def test_cred_tester_import(self):
        """Import CredentialTester without error."""
        from posframework.cred_tester import CredentialTester
        assert CredentialTester is not None

    def test_pmkid_import(self):
        """Import PMKIDCapture without error."""
        from posframework.pmkid import PMKIDCapture
        assert PMKIDCapture is not None

    def test_orchestrator_has_verify_credential(self):
        """AttackOrchestrator has verify_credential method."""
        from posframework.orchestrator import AttackOrchestrator
        assert hasattr(AttackOrchestrator, 'verify_credential')

    def test_cred_tester_has_native_method(self):
        """CredentialTester has test_wifi_password_native method."""
        from posframework.cred_tester import CredentialTester
        assert hasattr(CredentialTester, 'test_wifi_password_native')

    def test_pmkid_has_compute_pmkid(self):
        """PMKIDCapture has compute_pmkid method."""
        from posframework.pmkid import PMKIDCapture
        assert hasattr(PMKIDCapture, 'compute_pmkid')

    def test_pmkid_has_verify_pmkid(self):
        """PMKIDCapture has verify_pmkid method."""
        from posframework.pmkid import PMKIDCapture
        assert hasattr(PMKIDCapture, 'verify_pmkid')

    def test_pmkid_has_try_passwords(self):
        """PMKIDCapture has try_passwords method."""
        from posframework.pmkid import PMKIDCapture
        assert hasattr(PMKIDCapture, 'try_passwords')


class TestExtractHandshakePair:
    """Tests for the wpa2.extract_handshake_pair shared helper."""

    def test_extract_valid_pair(self):
        """extract_handshake_pair returns (msg1, msg2) for valid frames."""
        from posframework.wpa2 import extract_handshake_pair

        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )
        result = extract_handshake_pair([msg1, msg2])
        assert result is not None
        msg1_frame, msg2_frame = result
        assert msg1_frame.has_ack
        assert not msg1_frame.has_mic
        assert msg2_frame.has_mic
        assert not msg2_frame.has_ack

    def test_extract_returns_none_for_empty(self):
        """extract_handshake_pair returns None for empty list."""
        from posframework.wpa2 import extract_handshake_pair
        assert extract_handshake_pair([]) is None

    def test_extract_returns_none_for_only_msg1(self):
        """extract_handshake_pair returns None with only Msg1."""
        from posframework.wpa2 import extract_handshake_pair

        msg1, _msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )
        assert extract_handshake_pair([msg1]) is None

    def test_extract_returns_none_for_only_msg2(self):
        """extract_handshake_pair returns None with only Msg2."""
        from posframework.wpa2 import extract_handshake_pair

        _msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )
        assert extract_handshake_pair([msg2]) is None

    def test_extract_handles_tuples(self):
        """extract_handshake_pair works with (bytes, metadata) tuples."""
        from posframework.wpa2 import extract_handshake_pair

        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )
        # Wrap in tuples like cred_tester uses
        frames = [(msg1, "00:13:ce:55:98:ef"), (msg2, "00:13:ce:55:98:ef")]
        result = extract_handshake_pair(frames)
        assert result is not None

    def test_extract_ignores_invalid_frames(self):
        """extract_handshake_pair skips unparseable data."""
        from posframework.wpa2 import extract_handshake_pair

        msg1, msg2 = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC
        )
        # Include garbage data that won't parse
        frames = [b'\x00' * 10, msg1, b'\xff' * 50, msg2]
        result = extract_handshake_pair(frames)
        assert result is not None


class TestDetectCipherFromFrame:
    """Tests for wpa2.detect_cipher_from_frame."""

    def test_detect_ccmp(self):
        """Key descriptor version 2 detects CCMP."""
        from posframework.wpa2 import detect_cipher_from_frame, CipherSuite

        frame = EAPOLKeyFrame()
        # Version 2 = HMAC-SHA1 = CCMP
        frame.key_info = KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_PAIRWISE | KEY_INFO_MIC
        assert detect_cipher_from_frame(frame) == CipherSuite.CCMP

    def test_detect_tkip(self):
        """Key descriptor version 1 detects TKIP."""
        from posframework.wpa2 import detect_cipher_from_frame, CipherSuite

        frame = EAPOLKeyFrame()
        # Version 1 = HMAC-MD5 = TKIP
        from posframework.wpa2 import KEY_INFO_TYPE_HMAC_MD5
        frame.key_info = KEY_INFO_TYPE_HMAC_MD5 | KEY_INFO_PAIRWISE | KEY_INFO_MIC
        assert detect_cipher_from_frame(frame) == CipherSuite.TKIP

    def test_detect_defaults_to_ccmp(self):
        """Unknown key descriptor version defaults to CCMP."""
        from posframework.wpa2 import detect_cipher_from_frame, CipherSuite

        frame = EAPOLKeyFrame()
        # Version 3 = AES-CMAC, still uses CCMP-length PTK
        frame.key_info = 0x0003 | KEY_INFO_PAIRWISE | KEY_INFO_MIC
        assert detect_cipher_from_frame(frame) == CipherSuite.CCMP


class TestTryPasswordsIterator:
    """Tests for pmkid.try_passwords generator handling."""

    def test_try_passwords_with_generator(self):
        """try_passwords works correctly when passed a generator (not exhausted)."""
        from unittest.mock import MagicMock, patch

        capture = PMKIDCapture.__new__(PMKIDCapture)
        capture._lock = __import__('threading').Lock()
        capture._pmkids = {
            ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"): {
                "pmkid": "deadbeef" * 4,
                "essid": "TestNet",
            }
        }

        # Create a generator that would be exhausted by list()
        def password_gen():
            yield "wrong1"
            yield "wrong2"

        with patch.object(capture, 'verify_pmkid', return_value=False):
            result = capture.try_passwords(
                "11:22:33:44:55:66", password_gen(), "TestNet"
            )

        # Should return None (no match), but crucially should have
        # iterated all passwords (not exhausted by len())
        assert result is None

    def test_try_passwords_finds_match_from_generator(self):
        """try_passwords returns matching password from a generator."""
        from unittest.mock import MagicMock, patch

        capture = PMKIDCapture.__new__(PMKIDCapture)
        capture._lock = __import__('threading').Lock()
        capture._pmkids = {
            ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"): {
                "pmkid": "deadbeef" * 4,
                "essid": "TestNet",
            }
        }

        def password_gen():
            yield "wrong"
            yield "correct"
            yield "extra"

        def mock_verify(bssid, client_mac, password, ssid):
            return password == "correct"

        with patch.object(capture, 'verify_pmkid', side_effect=mock_verify):
            result = capture.try_passwords(
                "11:22:33:44:55:66", password_gen(), "TestNet"
            )

        assert result == "correct"
