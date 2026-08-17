"""
Unit tests for posframework/intel.py — POS vendor and SSID intelligence matching.
"""

import pytest
from posframework.intel import is_pos_vendor, is_pos_ssid, POS_VENDORS, POS_SSID_PATTERNS


class TestIsPosVendor:
    """Tests for is_pos_vendor() — OUI vendor string matching."""

    # ─── Positive cases: known POS vendors ─────────────────────────────────

    @pytest.mark.parametrize("vendor", [
        "Verifone",
        "VERIFONE",
        "verifone",
        "Ingenico",
        "PAX",
        "NCR",
        "Square",
        "Clover Network",
        "Epson",
        "Zebra Technologies",
        "Cisco Meraki",
        "Aruba",
        "Honeywell",
        "MagTek",
    ])
    def test_known_pos_vendors(self, vendor):
        """Known POS vendor strings should match."""
        assert is_pos_vendor(vendor) is True

    @pytest.mark.parametrize("vendor", [
        "Verifone Inc.",
        "Device by Ingenico Group",
        "NCR Corporation Model X",
        "Hewlett Packard Enterprise AP",
        "Cisco Meraki MR42",
    ])
    def test_vendor_substring_match(self, vendor):
        """Vendor string containing a POS keyword should match."""
        assert is_pos_vendor(vendor) is True

    # ─── Negative cases: non-POS vendors ───────────────────────────────────

    @pytest.mark.parametrize("vendor", [
        "Apple",
        "Samsung Electronics",
        "Intel Corporate",
        "Realtek Semiconductor",
        "Qualcomm",
        "TP-Link Technologies",
        "Netgear",
        "Dell Inc.",
        "Lenovo",
        "",
    ])
    def test_non_pos_vendors(self, vendor):
        """Non-POS vendor strings should not match."""
        assert is_pos_vendor(vendor) is False

    # ─── Edge cases ────────────────────────────────────────────────────────

    def test_empty_string(self):
        assert is_pos_vendor("") is False

    def test_none_raises(self):
        """None input should raise TypeError (not silently pass)."""
        with pytest.raises(TypeError):
            is_pos_vendor(None)

    def test_case_insensitive(self):
        """Matching should be case-insensitive."""
        assert is_pos_vendor("VERIFONE") is True
        assert is_pos_vendor("verifone") is True
        assert is_pos_vendor("VeRiFoNe") is True

    def test_all_vendors_in_frozenset_match(self):
        """Every vendor in the POS_VENDORS frozenset should match."""
        for vendor in POS_VENDORS:
            assert is_pos_vendor(vendor) is True, f"Failed for: {vendor}"


class TestIsPosSSID:
    """Tests for is_pos_ssid() — SSID pattern detection."""

    # ─── Positive cases: known POS SSID patterns ──────────────────────────

    @pytest.mark.parametrize("ssid", [
        "POS-Terminal-1",
        "Store-Register-3",
        "payment-gateway",
        "KIOSK_LOBBY",
        "retail-wifi",
        "MicrosNet",
        "Toast-Kitchen",
        "Clover-Register",
        "Square-POS",
        "BackOffice-Net",
        "BOH-Kitchen",
        "FOH-Front",
        "ATM-Lobby",
        "pump-controller",
        "self-checkout-4",
        "lane-12",
        "till-register",
        "pinpad-secure",
    ])
    def test_known_pos_ssids(self, ssid):
        """SSIDs matching POS patterns should be detected."""
        assert is_pos_ssid(ssid) is True

    # ─── Negative cases: non-POS SSIDs ────────────────────────────────────

    @pytest.mark.parametrize("ssid", [
        "HomeNetwork",
        "linksys",
        "NETGEAR-5G",
        "iPhone_Hotspot",
        "CoffeeShop_Guest",
        "Airport_Free_WiFi",
        "eduroam",
        "xfinitywifi",
        "MySpectrumWiFi",
    ])
    def test_non_pos_ssids(self, ssid):
        """Regular SSIDs should not match POS patterns."""
        assert is_pos_ssid(ssid) is False

    # ─── Edge cases ────────────────────────────────────────────────────────

    def test_empty_string_returns_false(self):
        """Empty SSID should return False."""
        assert is_pos_ssid("") is False

    def test_none_returns_false(self):
        """None SSID should return False (handled gracefully)."""
        assert is_pos_ssid(None) is False

    def test_case_insensitive(self):
        """SSID matching should be case-insensitive."""
        assert is_pos_ssid("POS-Terminal") is True
        assert is_pos_ssid("pos-terminal") is True
        assert is_pos_ssid("PoS-Terminal") is True

    def test_all_patterns_matchable(self):
        """Every pattern in POS_SSID_PATTERNS should match when used as SSID."""
        for pattern in POS_SSID_PATTERNS:
            # Use the pattern as a prefix to an SSID
            ssid = f"{pattern}network"
            assert is_pos_ssid(ssid) is True, f"Pattern '{pattern}' not matched in SSID '{ssid}'"

    def test_partial_match_within_ssid(self):
        """Pattern can appear anywhere in the SSID."""
        assert is_pos_ssid("company-pos-network") is True
        assert is_pos_ssid("wifi-terminal-secure") is True

    def test_very_long_ssid(self):
        """Long SSIDs should still be processed."""
        long_ssid = "a" * 100 + "terminal" + "b" * 100
        assert is_pos_ssid(long_ssid) is True

    def test_whitespace_only(self):
        """Whitespace-only SSID should not match."""
        assert is_pos_ssid("   ") is False
