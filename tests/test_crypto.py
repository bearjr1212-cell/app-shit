"""
Unit tests for posframework/crypto.py — RSN/WPA IE parsing and security classification.
"""

import struct
import pytest
from posframework.crypto import (
    parse_rsn_ie, parse_wpa_ie, classify_security,
    AKM_SUITES, CIPHER_SUITES,
)


class TestParseRSNIE:
    """Tests for parse_rsn_ie() — RSN Information Element parsing."""

    def _build_rsn_ie(self, group_cipher=4, pairwise_ciphers=None,
                      akm_suites=None, capabilities=0):
        """Helper to build a valid RSN IE byte sequence."""
        pairwise_ciphers = pairwise_ciphers or [4]  # CCMP
        akm_suites = akm_suites or [2]  # PSK

        data = struct.pack("<H", 1)  # Version 1
        # Group cipher suite (OUI 00:0f:ac + type)
        data += b'\x00\x0f\xac' + bytes([group_cipher])
        # Pairwise cipher count + suites
        data += struct.pack("<H", len(pairwise_ciphers))
        for cipher in pairwise_ciphers:
            data += b'\x00\x0f\xac' + bytes([cipher])
        # AKM count + suites
        data += struct.pack("<H", len(akm_suites))
        for akm in akm_suites:
            data += b'\x00\x0f\xac' + bytes([akm])
        # RSN capabilities
        data += struct.pack("<H", capabilities)
        return data

    def test_valid_wpa2_psk_ccmp(self):
        """Parse standard WPA2-PSK with CCMP."""
        data = self._build_rsn_ie(group_cipher=4, pairwise_ciphers=[4], akm_suites=[2])
        result = parse_rsn_ie(data)
        assert result["group_cipher"] == "CCMP"
        assert result["pairwise_ciphers"] == ["CCMP"]
        assert result["akm_suites"] == ["WPA2-PSK"]

    def test_valid_wpa2_eap(self):
        """Parse WPA2-Enterprise (EAP)."""
        data = self._build_rsn_ie(akm_suites=[1])
        result = parse_rsn_ie(data)
        assert "WPA2-EAP" in result["akm_suites"]

    def test_wpa3_sae(self):
        """Parse WPA3-Personal (SAE)."""
        data = self._build_rsn_ie(akm_suites=[8])
        result = parse_rsn_ie(data)
        assert "SAE" in result["akm_suites"]

    def test_owe(self):
        """Parse OWE (Enhanced Open)."""
        data = self._build_rsn_ie(akm_suites=[18])
        result = parse_rsn_ie(data)
        assert "OWE" in result["akm_suites"]

    def test_multiple_pairwise_ciphers(self):
        """Parse IE with multiple pairwise cipher suites."""
        data = self._build_rsn_ie(pairwise_ciphers=[4, 2])  # CCMP + TKIP
        result = parse_rsn_ie(data)
        assert "CCMP" in result["pairwise_ciphers"]
        assert "TKIP" in result["pairwise_ciphers"]

    def test_multiple_akm_suites(self):
        """Parse IE with multiple AKM suites (transition mode)."""
        data = self._build_rsn_ie(akm_suites=[2, 8])  # PSK + SAE
        result = parse_rsn_ie(data)
        assert "WPA2-PSK" in result["akm_suites"]
        assert "SAE" in result["akm_suites"]

    def test_pmf_required(self):
        """Parse capabilities with PMF required bit set."""
        # PMF required = bit 6 (MFPR)
        caps = (1 << 6)
        data = self._build_rsn_ie(capabilities=caps)
        result = parse_rsn_ie(data)
        assert result["capabilities"] == caps

    def test_pmf_capable(self):
        """Parse capabilities with PMF capable bit set."""
        caps = (1 << 7)
        data = self._build_rsn_ie(capabilities=caps)
        result = parse_rsn_ie(data)
        assert result["capabilities"] == caps

    def test_empty_data_returns_defaults(self):
        """Empty/None data should return empty defaults."""
        result = parse_rsn_ie(b"")
        assert result["group_cipher"] is None
        assert result["pairwise_ciphers"] == []
        assert result["akm_suites"] == []

    def test_none_data_returns_defaults(self):
        result = parse_rsn_ie(None)
        assert result["group_cipher"] is None

    def test_too_short_data(self):
        """Data shorter than minimum should return defaults."""
        result = parse_rsn_ie(b"\x01\x00\x00")
        assert result["group_cipher"] is None

    def test_wrong_version(self):
        """Non-version-1 RSN IE should return defaults."""
        data = struct.pack("<H", 2) + b'\x00' * 20
        result = parse_rsn_ie(data)
        assert result["group_cipher"] is None

    def test_unknown_cipher_suite(self):
        """Unknown cipher type should produce 'Unknown(N)' string."""
        data = self._build_rsn_ie(group_cipher=99)
        result = parse_rsn_ie(data)
        assert "Unknown" in result["group_cipher"]

    def test_truncated_pairwise_section(self):
        """Gracefully handle truncated data in pairwise section."""
        # Version + group cipher + pairwise count of 5 but no actual data
        data = struct.pack("<H", 1) + b'\x00\x0f\xac\x04' + struct.pack("<H", 5)
        result = parse_rsn_ie(data)
        assert result["pairwise_ciphers"] == []


class TestParseWPAIE:
    """Tests for parse_wpa_ie() — WPA vendor IE parsing."""

    def _build_wpa_ie(self, group_cipher=2, pairwise_ciphers=None, akm_suites=None):
        """Build a valid WPA vendor IE."""
        pairwise_ciphers = pairwise_ciphers or [2]  # TKIP
        akm_suites = akm_suites or [2]  # PSK

        # OUI header: 00:50:f2 type 1
        data = b'\x00\x50\xf2\x01'
        data += struct.pack("<H", 1)  # Version
        # Group cipher (OUI 00:50:f2 + type)
        data += b'\x00\x50\xf2' + bytes([group_cipher])
        # Pairwise count + suites
        data += struct.pack("<H", len(pairwise_ciphers))
        for cipher in pairwise_ciphers:
            data += b'\x00\x50\xf2' + bytes([cipher])
        # AKM count + suites
        data += struct.pack("<H", len(akm_suites))
        for akm in akm_suites:
            data += b'\x00\x50\xf2' + bytes([akm])
        return data

    def test_valid_wpa_psk_tkip(self):
        """Parse standard WPA-PSK with TKIP."""
        data = self._build_wpa_ie(group_cipher=2, akm_suites=[2])
        result = parse_wpa_ie(data)
        assert result["group_cipher"] == "TKIP"
        assert "WPA-PSK" in result["akm_suites"]

    def test_wpa_eap(self):
        """Parse WPA-Enterprise."""
        data = self._build_wpa_ie(akm_suites=[1])
        result = parse_wpa_ie(data)
        assert "WPA-EAP" in result["akm_suites"]

    def test_wpa_ccmp(self):
        """Parse WPA with CCMP pairwise (mixed mode)."""
        data = self._build_wpa_ie(pairwise_ciphers=[4])
        result = parse_wpa_ie(data)
        assert "CCMP" in result["pairwise_ciphers"]

    def test_empty_data(self):
        result = parse_wpa_ie(b"")
        assert result["group_cipher"] is None
        assert result["akm_suites"] == []

    def test_none_data(self):
        result = parse_wpa_ie(None)
        assert result["group_cipher"] is None

    def test_wrong_oui(self):
        """Wrong OUI prefix should return defaults."""
        data = b'\x00\x00\x00\x01' + b'\x00' * 20
        result = parse_wpa_ie(data)
        assert result["group_cipher"] is None

    def test_unknown_akm_type(self):
        """Unknown AKM type produces WPA-Unknown(N) string."""
        data = self._build_wpa_ie(akm_suites=[99])
        result = parse_wpa_ie(data)
        assert any("Unknown" in s for s in result["akm_suites"])


class TestClassifySecurity:
    """Tests for classify_security() — human-readable security string."""

    def test_open_network(self):
        """No privacy bit → Open."""
        result = classify_security({}, {}, has_privacy=False)
        assert result == "Open"

    def test_owe_enhanced_open(self):
        """OWE with no privacy → OWE (Enhanced Open)."""
        rsn = {"akm_suites": ["OWE"], "pairwise_ciphers": [], "capabilities": 0}
        result = classify_security(rsn, {}, has_privacy=False)
        assert "OWE" in result

    def test_wep(self):
        """Privacy bit set with no RSN/WPA → WEP."""
        result = classify_security({}, {}, has_privacy=True)
        assert result == "WEP"

    def test_wpa2_personal(self):
        """RSN with PSK AKM → WPA2-Personal."""
        rsn = {"akm_suites": ["WPA2-PSK"], "pairwise_ciphers": ["CCMP"], "capabilities": 0}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "WPA2-Personal" in result

    def test_wpa2_enterprise(self):
        """RSN with EAP AKM → WPA2-Enterprise."""
        rsn = {"akm_suites": ["WPA2-EAP"], "pairwise_ciphers": ["CCMP"], "capabilities": 0}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "WPA2-Enterprise" in result

    def test_wpa3_personal(self):
        """RSN with SAE AKM → WPA3-Personal."""
        rsn = {"akm_suites": ["SAE"], "pairwise_ciphers": ["CCMP"], "capabilities": 0}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "WPA3-Personal" in result

    def test_wpa3_enterprise(self):
        """RSN with EAP-SHA384 → WPA3-Enterprise."""
        rsn = {"akm_suites": ["EAP-SHA384"], "pairwise_ciphers": ["GCMP-256"], "capabilities": 0}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "WPA3-Enterprise" in result

    def test_pmf_required_shown(self):
        """PMF required flag should appear in output."""
        caps = (1 << 6)  # MFPR
        rsn = {"akm_suites": ["SAE"], "pairwise_ciphers": ["CCMP"], "capabilities": caps}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "PMF-Required" in result

    def test_pmf_capable_shown(self):
        """PMF capable flag should appear in output."""
        caps = (1 << 7)  # MFPC
        rsn = {"akm_suites": ["WPA2-PSK"], "pairwise_ciphers": ["CCMP"], "capabilities": caps}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "PMF-Capable" in result

    def test_wpa_legacy(self):
        """WPA IE only (no RSN) → WPA classification."""
        wpa = {"akm_suites": ["WPA-PSK"], "pairwise_ciphers": ["TKIP"]}
        rsn_empty = {"akm_suites": [], "pairwise_ciphers": [], "capabilities": 0}
        result = classify_security(rsn_empty, wpa, has_privacy=True)
        assert "WPA" in result

    def test_transition_mode_multiple_ciphers(self):
        """Multiple pairwise ciphers shown in brackets."""
        rsn = {"akm_suites": ["WPA2-PSK"], "pairwise_ciphers": ["CCMP", "TKIP"], "capabilities": 0}
        result = classify_security(rsn, {}, has_privacy=True)
        assert "CCMP" in result
        assert "TKIP" in result

    def test_empty_rsn_and_wpa_with_privacy(self):
        """Privacy set but empty IE data → WEP fallback."""
        rsn = {"akm_suites": [], "pairwise_ciphers": [], "capabilities": 0}
        wpa = {"akm_suites": [], "pairwise_ciphers": []}
        result = classify_security(rsn, wpa, has_privacy=True)
        assert result == "WEP"
