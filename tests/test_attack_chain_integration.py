"""
Integration tests for WPA2 module usage in attack_chain.py and autopwn_engine.py.

Tests verify that:
1. PMKIDAttack.verify_pmkid_candidate returns True for correct password
2. DeauthHandshakeAttack.validate_handshake verifies correct password
3. AutoPwnEngine._verify_credential_native performs native MIC verification
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
    KEY_INFO_SECURE,
    WPA2Handshake,
    HandshakeRole,
)
from posframework.attack_chain import PMKIDAttack, DeauthHandshakeAttack


# --- Test Vectors ---
TEST_PASSPHRASE = "password"
TEST_SSID = "IEEE"
TEST_PMK_HEX = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"

TEST_AP_MAC = b'\x00\x0b\x86\xc2\xa4\x85'
TEST_STA_MAC = b'\x00\x13\xce\x55\x98\xef'

TEST_AP_MAC_STR = "00:0b:86:c2:a4:85"
TEST_STA_MAC_STR = "00:13:ce:55:98:ef"


def _compute_pmkid(pmk: bytes, ap_mac: bytes, sta_mac: bytes) -> bytes:
    """Compute PMKID per IEEE 802.11-2020."""
    data = b"PMK Name" + ap_mac + sta_mac
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]


def _build_test_handshake_frames(passphrase, ssid, ap_mac, sta_mac):
    """
    Build a synthetic WPA2 4-way handshake (Msg1 + Msg2) for testing.

    Uses the WPA2Handshake state machine to generate valid frames
    with proper MICs.
    """
    pmk = derive_pmk(passphrase, ssid)

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


class TestPMKIDAttackVerification:
    """Tests for PMKIDAttack.verify_pmkid_candidate()."""

    def test_verify_correct_password(self):
        """verify_pmkid_candidate returns True for the correct password."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        expected_pmkid = _compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        attack = PMKIDAttack()
        result = attack.verify_pmkid_candidate(
            pmkid_hex=expected_pmkid.hex(),
            ap_mac=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            ssid=TEST_SSID,
            password=TEST_PASSPHRASE,
        )
        assert result is True

    def test_verify_wrong_password(self):
        """verify_pmkid_candidate returns False for a wrong password."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        expected_pmkid = _compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        attack = PMKIDAttack()
        result = attack.verify_pmkid_candidate(
            pmkid_hex=expected_pmkid.hex(),
            ap_mac=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            ssid=TEST_SSID,
            password="wrong_password",
        )
        assert result is False

    def test_verify_different_ssid(self):
        """verify_pmkid_candidate returns False when SSID differs."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        expected_pmkid = _compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        attack = PMKIDAttack()
        result = attack.verify_pmkid_candidate(
            pmkid_hex=expected_pmkid.hex(),
            ap_mac=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            ssid="DifferentSSID",
            password=TEST_PASSPHRASE,
        )
        assert result is False

    def test_verify_pmkid_known_vector(self):
        """Verify PMKID computation matches known PMK."""
        pmk = bytes.fromhex(TEST_PMK_HEX)
        expected_pmkid = _compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        # Using the known passphrase/SSID that produces TEST_PMK_HEX
        attack = PMKIDAttack()
        result = attack.verify_pmkid_candidate(
            pmkid_hex=expected_pmkid.hex(),
            ap_mac=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            ssid=TEST_SSID,
            password=TEST_PASSPHRASE,
        )
        assert result is True

    def test_verify_with_hyphen_separated_mac(self):
        """verify_pmkid_candidate handles hyphen-separated MACs."""
        pmk = derive_pmk(TEST_PASSPHRASE, TEST_SSID)
        expected_pmkid = _compute_pmkid(pmk, TEST_AP_MAC, TEST_STA_MAC)

        attack = PMKIDAttack()
        result = attack.verify_pmkid_candidate(
            pmkid_hex=expected_pmkid.hex(),
            ap_mac="00-0b-86-c2-a4-85",
            sta_mac="00-13-ce-55-98-ef",
            ssid=TEST_SSID,
            password=TEST_PASSPHRASE,
        )
        assert result is True

    def test_verify_invalid_pmkid_hex(self):
        """verify_pmkid_candidate returns False for invalid hex."""
        attack = PMKIDAttack()
        result = attack.verify_pmkid_candidate(
            pmkid_hex="invalid_hex_string!",
            ap_mac=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            ssid=TEST_SSID,
            password=TEST_PASSPHRASE,
        )
        assert result is False


class TestDeauthHandshakeValidation:
    """Tests for DeauthHandshakeAttack.validate_handshake()."""

    def test_validate_correct_password(self):
        """validate_handshake returns True for correct password."""
        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[msg1_bytes, msg2_bytes],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=TEST_PASSPHRASE,
            ssid=TEST_SSID,
        )
        assert result is True

    def test_validate_wrong_password(self):
        """validate_handshake returns False for wrong password."""
        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[msg1_bytes, msg2_bytes],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password="wrong_password_123",
            ssid=TEST_SSID,
        )
        assert result is False

    def test_validate_wrong_ssid(self):
        """validate_handshake returns False when SSID is wrong."""
        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[msg1_bytes, msg2_bytes],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=TEST_PASSPHRASE,
            ssid="WrongSSID",
        )
        assert result is False

    def test_validate_incomplete_handshake_msg1_only(self):
        """validate_handshake returns False with only Msg1 (no Msg2)."""
        msg1_bytes, _ = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[msg1_bytes],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=TEST_PASSPHRASE,
            ssid=TEST_SSID,
        )
        assert result is False

    def test_validate_empty_packets(self):
        """validate_handshake returns False with empty packet list."""
        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=TEST_PASSPHRASE,
            ssid=TEST_SSID,
        )
        assert result is False

    def test_validate_garbage_data(self):
        """validate_handshake returns False for non-EAPOL data."""
        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[b'\x00' * 50, b'\xff' * 100],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=TEST_PASSPHRASE,
            ssid=TEST_SSID,
        )
        assert result is False

    def test_validate_with_extra_frames(self):
        """validate_handshake works when extra frames are present."""
        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        # Add some noise frames
        noise = b'\x00' * 50
        attack = DeauthHandshakeAttack()
        result = attack.validate_handshake(
            captured_packets=[noise, msg1_bytes, noise, msg2_bytes, noise],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=TEST_PASSPHRASE,
            ssid=TEST_SSID,
        )
        assert result is True

    def test_validate_different_passphrase_ssid_combo(self):
        """validate_handshake works with different passphrase/SSID pairs."""
        passphrase = "MySecureWiFi2024!"
        ssid = "HomeNetwork"

        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            passphrase, ssid, TEST_AP_MAC, TEST_STA_MAC,
        )

        attack = DeauthHandshakeAttack()

        # Correct password
        result = attack.validate_handshake(
            captured_packets=[msg1_bytes, msg2_bytes],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password=passphrase,
            ssid=ssid,
        )
        assert result is True

        # Wrong password
        result = attack.validate_handshake(
            captured_packets=[msg1_bytes, msg2_bytes],
            bssid=TEST_AP_MAC_STR,
            sta_mac=TEST_STA_MAC_STR,
            password="WrongPassword",
            ssid=ssid,
        )
        assert result is False


class TestAutoPwnEngineNativeVerification:
    """Tests for AutoPwnEngine._verify_credential_native()."""

    def _make_engine(self):
        """Create a minimal AutoPwnEngine for testing."""
        from unittest.mock import MagicMock, patch

        with patch('posframework.autopwn_engine.get_event_bus') as mock_bus, \
             patch('posframework.autopwn_engine.SessionManager'), \
             patch('posframework.autopwn_engine.TargetAnalyzer'), \
             patch('posframework.autopwn_engine.AttackChain'):
            mock_bus.return_value = MagicMock()
            from posframework.autopwn_engine import AutoPwnEngine, AutoPwnConfig
            engine = AutoPwnEngine(config=AutoPwnConfig())
            return engine

    def _make_target(self, bssid, ssid, client_mac=None):
        """Create a mock target object."""
        from unittest.mock import MagicMock
        target = MagicMock()
        target.bssid = bssid
        target.ssid = ssid
        target.client_mac = client_mac
        target.id = "test-target-001"
        return target

    def test_verify_correct_credential(self):
        """_verify_credential_native returns True for correct password."""
        engine = self._make_engine()

        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        target = self._make_target(
            bssid=TEST_AP_MAC_STR,
            ssid=TEST_SSID,
            client_mac=TEST_STA_MAC_STR,
        )

        result = engine._verify_credential_native(
            target=target,
            password=TEST_PASSPHRASE,
            handshake_frames=[msg1_bytes, msg2_bytes],
        )
        assert result is True

    def test_verify_wrong_credential(self):
        """_verify_credential_native returns False for wrong password."""
        engine = self._make_engine()

        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        target = self._make_target(
            bssid=TEST_AP_MAC_STR,
            ssid=TEST_SSID,
            client_mac=TEST_STA_MAC_STR,
        )

        result = engine._verify_credential_native(
            target=target,
            password="definitely_wrong",
            handshake_frames=[msg1_bytes, msg2_bytes],
        )
        assert result is False

    def test_verify_missing_sta_mac(self):
        """_verify_credential_native returns False when STA MAC is missing."""
        engine = self._make_engine()

        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        target = self._make_target(
            bssid=TEST_AP_MAC_STR,
            ssid=TEST_SSID,
            client_mac=None,
        )
        # Also remove fallback attribute
        target.sta_mac = None

        result = engine._verify_credential_native(
            target=target,
            password=TEST_PASSPHRASE,
            handshake_frames=[msg1_bytes, msg2_bytes],
        )
        assert result is False

    def test_verify_empty_handshake_frames(self):
        """_verify_credential_native returns False with no frames."""
        engine = self._make_engine()

        target = self._make_target(
            bssid=TEST_AP_MAC_STR,
            ssid=TEST_SSID,
            client_mac=TEST_STA_MAC_STR,
        )

        result = engine._verify_credential_native(
            target=target,
            password=TEST_PASSPHRASE,
            handshake_frames=[],
        )
        assert result is False

    def test_verify_incomplete_handshake(self):
        """_verify_credential_native returns False with only Msg1."""
        engine = self._make_engine()

        msg1_bytes, _ = _build_test_handshake_frames(
            TEST_PASSPHRASE, TEST_SSID, TEST_AP_MAC, TEST_STA_MAC,
        )

        target = self._make_target(
            bssid=TEST_AP_MAC_STR,
            ssid=TEST_SSID,
            client_mac=TEST_STA_MAC_STR,
        )

        result = engine._verify_credential_native(
            target=target,
            password=TEST_PASSPHRASE,
            handshake_frames=[msg1_bytes],
        )
        assert result is False

    def test_verify_different_network(self):
        """_verify_credential_native works with different network parameters."""
        engine = self._make_engine()

        passphrase = "ComplexP@ss123"
        ssid = "CorporateWiFi"
        ap_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        sta_mac = b'\x11\x22\x33\x44\x55\x66'

        msg1_bytes, msg2_bytes = _build_test_handshake_frames(
            passphrase, ssid, ap_mac, sta_mac,
        )

        target = self._make_target(
            bssid="aa:bb:cc:dd:ee:ff",
            ssid=ssid,
            client_mac="11:22:33:44:55:66",
        )

        # Correct password
        result = engine._verify_credential_native(
            target=target,
            password=passphrase,
            handshake_frames=[msg1_bytes, msg2_bytes],
        )
        assert result is True

        # Wrong password
        result = engine._verify_credential_native(
            target=target,
            password="WrongPassword",
            handshake_frames=[msg1_bytes, msg2_bytes],
        )
        assert result is False


class TestImports:
    """Verify that all imports work correctly."""

    def test_attack_chain_imports(self):
        """PMKIDAttack and DeauthHandshakeAttack can be imported."""
        from posframework.attack_chain import PMKIDAttack, DeauthHandshakeAttack
        assert PMKIDAttack is not None
        assert DeauthHandshakeAttack is not None

    def test_autopwn_engine_imports(self):
        """AutoPwnEngine can be imported."""
        from posframework.autopwn_engine import AutoPwnEngine
        assert AutoPwnEngine is not None

    def test_pmkid_attack_has_verify_method(self):
        """PMKIDAttack has verify_pmkid_candidate method."""
        attack = PMKIDAttack()
        assert hasattr(attack, 'verify_pmkid_candidate')
        assert callable(attack.verify_pmkid_candidate)

    def test_deauth_attack_has_validate_method(self):
        """DeauthHandshakeAttack has validate_handshake method."""
        attack = DeauthHandshakeAttack()
        assert hasattr(attack, 'validate_handshake')
        assert callable(attack.validate_handshake)
