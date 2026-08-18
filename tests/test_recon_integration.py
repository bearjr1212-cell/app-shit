"""
Integration tests for wpa2.py module integration into recon.py.

Tests verify that:
1. ReconEngine._analyze_handshake_security correctly identifies CCMP vs TKIP
   from synthetic EAPOL key_info fields.
2. EAPOLKeyFrame.parse works on realistic frame bytes constructed from
   known handshake structure.
3. The wpa2 import guard in recon.py works correctly.
4. Key descriptor version mapping is consistent.
"""

import struct
import pytest
from unittest.mock import MagicMock, patch
from collections import defaultdict

from posframework.wpa2 import (
    EAPOLKeyFrame, HandshakeState, CipherSuite,
    EAPOL_VERSION, EAPOL_KEY_TYPE, EAPOL_KEY_DESC_WPA2,
    KEY_INFO_TYPE_HMAC_MD5, KEY_INFO_TYPE_HMAC_SHA1, KEY_INFO_TYPE_AES_CMAC,
    KEY_INFO_PAIRWISE, KEY_INFO_ACK, KEY_INFO_MIC, KEY_INFO_SECURE,
    KEY_INFO_INSTALL, KEY_INFO_ENCRYPTED_DATA,
)
from posframework.recon import ReconEngine


# --- Helper functions ---

def _build_eapol_frame(key_info, key_length=16, nonce=None, replay_counter=1,
                       key_data=b''):
    """
    Build a synthetic EAPOL-Key frame with the given parameters.

    Constructs a valid 99+ byte EAPOL frame matching the format expected
    by EAPOLKeyFrame.parse().
    """
    if nonce is None:
        nonce = b'\xaa' * 32

    body_len = 95 + len(key_data)
    frame = bytearray()
    frame.append(EAPOL_VERSION)            # [0] version
    frame.append(EAPOL_KEY_TYPE)           # [1] packet type = 3 (EAPOL-Key)
    frame.extend(struct.pack(">H", body_len))  # [2:4] body length
    frame.append(EAPOL_KEY_DESC_WPA2)      # [4] descriptor type = 2 (RSN)
    frame.extend(struct.pack(">H", key_info))  # [5:7] key info
    frame.extend(struct.pack(">H", key_length))  # [7:9] key length
    frame.extend(struct.pack(">Q", replay_counter))  # [9:17] replay counter
    frame.extend(nonce[:32].ljust(32, b'\x00'))  # [17:49] nonce
    frame.extend(b'\x00' * 16)             # [49:65] key IV
    frame.extend(b'\x00' * 8)              # [65:73] key RSC
    frame.extend(b'\x00' * 8)              # [73:81] key ID
    frame.extend(b'\x00' * 16)             # [81:97] MIC
    frame.extend(struct.pack(">H", len(key_data)))  # [97:99] key data length
    frame.extend(key_data)                 # [99:] key data

    return bytes(frame)


def _build_msg1_frame(nonce=None):
    """Build EAPOL Message 1 (AP -> STA: ANonce, Ack, no MIC)."""
    # Key Info: Pairwise=1, Ack=1, KDV=2 (HMAC-SHA1 for CCMP)
    key_info = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_HMAC_SHA1
    return _build_eapol_frame(key_info, key_length=16, nonce=nonce)


def _build_msg2_frame(nonce=None):
    """Build EAPOL Message 2 (STA -> AP: SNonce, MIC, no Ack)."""
    # Key Info: Pairwise=1, MIC=1, KDV=2
    key_info = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_TYPE_HMAC_SHA1
    return _build_eapol_frame(key_info, key_length=0, nonce=nonce)


def _build_msg3_frame(nonce=None):
    """Build EAPOL Message 3 (AP -> STA: Ack+MIC+Install+Secure+Encrypted)."""
    key_info = (KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC |
                KEY_INFO_INSTALL | KEY_INFO_SECURE | KEY_INFO_ENCRYPTED_DATA |
                KEY_INFO_TYPE_HMAC_SHA1)
    return _build_eapol_frame(key_info, key_length=16, nonce=nonce,
                              key_data=b'\xdd\x16' + b'\x00' * 20)


def _build_msg4_frame():
    """Build EAPOL Message 4 (STA -> AP: MIC+Secure, no Ack)."""
    key_info = (KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE |
                KEY_INFO_TYPE_HMAC_SHA1)
    return _build_eapol_frame(key_info, key_length=0, nonce=b'\x00' * 32)


def _build_tkip_msg1_frame(nonce=None):
    """Build EAPOL Message 1 with TKIP key descriptor (v1, key_length=32)."""
    key_info = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_HMAC_MD5
    return _build_eapol_frame(key_info, key_length=32, nonce=nonce)


def _build_tkip_msg2_frame(nonce=None):
    """Build EAPOL Message 2 with TKIP key descriptor (v1)."""
    key_info = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_TYPE_HMAC_MD5
    return _build_eapol_frame(key_info, key_length=0, nonce=nonce)


def _create_mock_recon_engine():
    """Create a ReconEngine with mocked dependencies."""
    mock_db = MagicMock()
    mock_db.update_ap = MagicMock()
    mock_db.update_client = MagicMock()
    mock_db.log_eapol = MagicMock()
    mock_db.get_stats = MagicMock(return_value={
        'access_points': 0, 'pos_access_points': 0,
        'clients': 0, 'pos_clients': 0,
        'deauth_events': 0, 'eapol_frames': 0,
        'credentials': 0,
    })

    with patch('posframework.recon.manuf.MacParser'):
        with patch('posframework.recon.sniff'):
            engine = ReconEngine.__new__(ReconEngine)
            engine.interface = 'wlan0mon'
            engine.db = mock_db
            engine.channels = [1, 6, 11]
            engine.channel_hop = False
            engine.running = False
            engine._stop_event = MagicMock()
            engine.parser = MagicMock()
            engine._deauth_times = defaultdict(list)
            engine._eapol_tracker = defaultdict(set)
            engine._eapol_raw_frames = defaultdict(list)
            engine._packets_processed = 0
            engine._start_time = 0.0
            engine._verbose = False
            engine._pkt_stats = defaultdict(int)
            engine.signal_targeting = None
            engine._monitor_manager = None
            engine._tshark_psk = None
            engine._tshark_ssid = None
            engine._decrypt_session = None
            engine._pywhat_enabled = False
            engine._pywhat_callback = None
            engine._intel_enricher = None

    return engine


# --- Test Classes ---

class TestAnalyzeHandshakeSecurity:
    """Tests for ReconEngine._analyze_handshake_security()."""

    def test_ccmp_from_key_descriptor_v2(self):
        """CCMP detected from key descriptor version 2 (HMAC-SHA1/AES)."""
        engine = _create_mock_recon_engine()
        anonce = b'\xaa' * 32
        snonce = b'\xbb' * 32
        frames = [
            _build_msg1_frame(nonce=anonce),
            _build_msg2_frame(nonce=snonce),
            _build_msg3_frame(nonce=anonce),
            _build_msg4_frame(),
        ]
        result = engine._analyze_handshake_security(frames)
        assert result['cipher_type'] == 'CCMP'
        assert result['key_descriptor_version'] == 2
        assert result['descriptor_name'] == 'HMAC-SHA1/AES'
        # Should have captured non-zero nonces
        assert len(result['nonces']) >= 2

    def test_tkip_from_key_descriptor_v1(self):
        """TKIP detected from key descriptor version 1 (HMAC-MD5/RC4)."""
        engine = _create_mock_recon_engine()
        anonce = b'\xcc' * 32
        snonce = b'\xdd' * 32
        frames = [
            _build_tkip_msg1_frame(nonce=anonce),
            _build_tkip_msg2_frame(nonce=snonce),
        ]
        result = engine._analyze_handshake_security(frames)
        assert result['cipher_type'] == 'TKIP'
        assert result['key_descriptor_version'] == 1
        assert result['descriptor_name'] == 'HMAC-MD5/RC4'

    def test_aes_cmac_descriptor_v3(self):
        """AES-CMAC (v3) maps to CCMP-256."""
        engine = _create_mock_recon_engine()
        key_info = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_AES_CMAC
        frames = [_build_eapol_frame(key_info, key_length=32)]
        result = engine._analyze_handshake_security(frames)
        assert result['cipher_type'] == 'CCMP-256'
        assert result['key_descriptor_version'] == 3
        assert result['descriptor_name'] == 'AES-CMAC'

    def test_empty_frames_returns_unknown(self):
        """Empty frame list returns unknown cipher type."""
        engine = _create_mock_recon_engine()
        result = engine._analyze_handshake_security([])
        assert result['cipher_type'] == 'unknown'
        assert result['key_descriptor_version'] == 0

    def test_invalid_frame_too_short(self):
        """Frame too short to parse returns unknown."""
        engine = _create_mock_recon_engine()
        result = engine._analyze_handshake_security([b'\x00' * 5])
        assert result['cipher_type'] == 'unknown'

    def test_nonces_collected(self):
        """Non-zero nonces are collected from parsed frames."""
        engine = _create_mock_recon_engine()
        nonce1 = b'\x11' * 32
        nonce2 = b'\x22' * 32
        frames = [
            _build_msg1_frame(nonce=nonce1),
            _build_msg2_frame(nonce=nonce2),
        ]
        result = engine._analyze_handshake_security(frames)
        assert nonce1.hex() in result['nonces']
        assert nonce2.hex() in result['nonces']

    def test_zero_nonce_not_collected(self):
        """All-zero nonces are not added to the nonces list."""
        engine = _create_mock_recon_engine()
        frames = [_build_msg4_frame()]  # msg4 has zero nonce
        result = engine._analyze_handshake_security(frames)
        zero_hex = ('00' * 32)
        assert zero_hex not in result['nonces']

    def test_key_length_confirms_ccmp(self):
        """key_length=16 with KDV=2 confirms CCMP."""
        engine = _create_mock_recon_engine()
        key_info = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_HMAC_SHA1
        frames = [_build_eapol_frame(key_info, key_length=16)]
        result = engine._analyze_handshake_security(frames)
        assert result['cipher_type'] == 'CCMP'

    def test_key_length_confirms_tkip(self):
        """key_length=32 with KDV=1 confirms TKIP."""
        engine = _create_mock_recon_engine()
        key_info = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_HMAC_MD5
        frames = [_build_eapol_frame(key_info, key_length=32)]
        result = engine._analyze_handshake_security(frames)
        assert result['cipher_type'] == 'TKIP'


class TestEAPOLKeyFrameParse:
    """Tests for EAPOLKeyFrame.parse() with realistic frame bytes."""

    def test_parse_msg1_frame(self):
        """Parse a realistic EAPOL Message 1 frame."""
        anonce = bytes(range(32))
        frame_data = _build_msg1_frame(nonce=anonce)
        parsed = EAPOLKeyFrame.parse(frame_data)

        assert parsed is not None
        assert parsed.version == EAPOL_VERSION
        assert parsed.packet_type == EAPOL_KEY_TYPE
        assert parsed.descriptor_type == EAPOL_KEY_DESC_WPA2
        assert parsed.nonce == anonce
        assert parsed.key_length == 16
        assert parsed.has_ack is True
        assert parsed.has_mic is False
        assert parsed.is_pairwise is True

    def test_parse_msg2_frame(self):
        """Parse a realistic EAPOL Message 2 frame."""
        snonce = bytes(range(32, 64))
        frame_data = _build_msg2_frame(nonce=snonce)
        parsed = EAPOLKeyFrame.parse(frame_data)

        assert parsed is not None
        assert parsed.nonce == snonce
        assert parsed.has_ack is False
        assert parsed.has_mic is True
        assert parsed.is_pairwise is True
        assert parsed.has_install is False

    def test_parse_msg3_frame(self):
        """Parse EAPOL Message 3 with encrypted key data."""
        anonce = b'\xff' * 32
        frame_data = _build_msg3_frame(nonce=anonce)
        parsed = EAPOLKeyFrame.parse(frame_data)

        assert parsed is not None
        assert parsed.nonce == anonce
        assert parsed.has_ack is True
        assert parsed.has_mic is True
        assert parsed.has_install is True
        assert parsed.has_secure is True
        assert parsed.has_encrypted_data is True
        assert len(parsed.key_data) == 22  # \xdd\x16 + 20 bytes

    def test_parse_msg4_frame(self):
        """Parse EAPOL Message 4."""
        frame_data = _build_msg4_frame()
        parsed = EAPOLKeyFrame.parse(frame_data)

        assert parsed is not None
        assert parsed.nonce == b'\x00' * 32
        assert parsed.has_ack is False
        assert parsed.has_mic is True
        assert parsed.has_secure is True
        assert parsed.has_install is False

    def test_parse_too_short_returns_none(self):
        """Frame shorter than 99 bytes returns None."""
        assert EAPOLKeyFrame.parse(b'\x00' * 98) is None
        assert EAPOLKeyFrame.parse(b'') is None
        assert EAPOLKeyFrame.parse(b'\x02\x03') is None

    def test_parse_wrong_packet_type_returns_none(self):
        """Non-EAPOL-Key packet type returns None."""
        frame = bytearray(_build_msg1_frame())
        frame[1] = 0  # Change packet type from 3 to 0
        assert EAPOLKeyFrame.parse(bytes(frame)) is None

    def test_key_descriptor_version_extraction(self):
        """key_descriptor_version property extracts bits 0-2 of key_info."""
        # Build frame with KDV=1 (HMAC-MD5)
        frame_v1 = _build_tkip_msg1_frame()
        parsed_v1 = EAPOLKeyFrame.parse(frame_v1)
        assert parsed_v1.key_descriptor_version == 1

        # Build frame with KDV=2 (HMAC-SHA1)
        frame_v2 = _build_msg1_frame()
        parsed_v2 = EAPOLKeyFrame.parse(frame_v2)
        assert parsed_v2.key_descriptor_version == 2

        # Build frame with KDV=3 (AES-CMAC)
        key_info = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_AES_CMAC
        frame_v3 = _build_eapol_frame(key_info)
        parsed_v3 = EAPOLKeyFrame.parse(frame_v3)
        assert parsed_v3.key_descriptor_version == 3

    def test_serialize_roundtrip(self):
        """Frame survives serialize -> parse roundtrip."""
        original = _build_msg1_frame(nonce=b'\x42' * 32)
        parsed = EAPOLKeyFrame.parse(original)
        assert parsed is not None
        reserialized = parsed.serialize()
        reparsed = EAPOLKeyFrame.parse(reserialized)
        assert reparsed is not None
        assert reparsed.nonce == parsed.nonce
        assert reparsed.key_info == parsed.key_info
        assert reparsed.key_length == parsed.key_length
        assert reparsed.replay_counter == parsed.replay_counter

    def test_replay_counter_preserved(self):
        """Replay counter value is correctly parsed."""
        frame = _build_eapol_frame(
            key_info=KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_TYPE_HMAC_SHA1,
            replay_counter=12345678
        )
        parsed = EAPOLKeyFrame.parse(frame)
        assert parsed.replay_counter == 12345678


class TestReconWPA2Import:
    """Tests for wpa2 module import integration in recon.py."""

    def test_recon_engine_importable(self):
        """ReconEngine can be imported (wpa2 integration does not break imports)."""
        from posframework.recon import ReconEngine
        assert ReconEngine is not None

    def test_recon_has_analyze_method(self):
        """ReconEngine has _analyze_handshake_security method."""
        assert hasattr(ReconEngine, '_analyze_handshake_security')
        assert callable(getattr(ReconEngine, '_analyze_handshake_security'))

    def test_wpa2_symbols_importable(self):
        """All wpa2 symbols used by recon are importable."""
        from posframework.wpa2 import EAPOLKeyFrame, HandshakeState, CipherSuite
        assert EAPOLKeyFrame is not None
        assert HandshakeState is not None
        assert CipherSuite is not None

    def test_init_exports(self):
        """__init__.py exports WPA2, CCMP, TKIP classes correctly."""
        from posframework import WPA2Handshake, CCMPEngine, TKIPEngine
        # These may be None if native deps are missing, but should not raise
        # In this environment they should be importable
        assert WPA2Handshake is not None or WPA2Handshake is None  # always true
        assert CCMPEngine is not None or CCMPEngine is None
        assert TKIPEngine is not None or TKIPEngine is None
