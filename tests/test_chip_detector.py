"""
Unit Tests for Chip Detection and Monitor Method Selection

Tests chip detection from various driver names, monitor method selection
for different chipsets, fallback behavior when primary method fails,
and state tracking during the enable/disable lifecycle.
"""

import os
import signal
import subprocess
import unittest
from unittest.mock import MagicMock, mock_open, patch, call

# Import the modules under test
from posframework.chip_detector import (
    ChipDetector,
    ChipInfo,
    MonitorMethod,
    MonitorMethodSelector,
)
from posframework.monitor_manager import (
    EnhancedMonitorManager,
    MonitorState,
)


# ─── ChipDetector Tests ──────────────────────────────────────────────────────


class TestChipDetector(unittest.TestCase):
    """Tests for ChipDetector class across all 6 detection sources."""

    def setUp(self):
        self.detector = ChipDetector()

    # ─── Source 1: sysfs driver symlink ───────────────────────────────────────

    @patch("os.path.islink")
    @patch("os.readlink")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_sysfs_driver(self, mock_readlink, mock_islink):
        """Test driver detection from /sys/class/net/<iface>/device/driver."""
        mock_islink.return_value = True
        mock_readlink.return_value = "/sys/bus/pci/drivers/iwlwifi"

        info = ChipInfo()
        self.detector._detect_from_sysfs_driver("wlan0", info)

        self.assertEqual(info.driver, "iwlwifi")

    @patch("os.path.islink")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_sysfs_driver_no_link(self, mock_islink):
        """Test graceful handling when driver symlink does not exist."""
        mock_islink.return_value = False

        info = ChipInfo()
        self.detector._detect_from_sysfs_driver("wlan0", info)

        self.assertEqual(info.driver, "")

    # ─── Source 2: sysfs uevent ───────────────────────────────────────────────

    @patch("os.path.isfile")
    @patch("builtins.open", mock_open(read_data="PCI_ID=8086:24FD\nDRIVER=iwlwifi\nSUBSYSTEM=pci\n"))
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_sysfs_uevent_pci(self, mock_isfile):
        """Test PCI ID detection from uevent."""
        mock_isfile.return_value = True

        info = ChipInfo()
        self.detector._detect_from_sysfs_uevent("wlan0", info)

        self.assertEqual(info.vendor_id, "8086")
        self.assertEqual(info.product_id, "24FD")
        self.assertEqual(info.bus_type, "pci")
        self.assertEqual(info.driver, "iwlwifi")

    @patch("os.path.isfile")
    @patch("builtins.open", mock_open(read_data="PRODUCT=0bda/8812/0\nSUBSYSTEM=usb\n"))
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_sysfs_uevent_usb(self, mock_isfile):
        """Test USB product ID detection from uevent."""
        mock_isfile.return_value = True

        info = ChipInfo()
        self.detector._detect_from_sysfs_uevent("wlan0", info)

        self.assertEqual(info.vendor_id, "0bda")
        self.assertEqual(info.product_id, "8812")
        self.assertEqual(info.bus_type, "usb")

    @patch("os.path.isfile")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_sysfs_uevent_missing(self, mock_isfile):
        """Test handling of missing uevent file."""
        mock_isfile.return_value = False

        info = ChipInfo()
        self.detector._detect_from_sysfs_uevent("wlan0", info)

        self.assertEqual(info.vendor_id, "")
        self.assertEqual(info.product_id, "")

    # ─── Source 3: lspci ──────────────────────────────────────────────────────

    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_lspci(self):
        """Test model detection from lspci -k output."""
        lspci_output = (
            "02:00.0 Network controller: Intel Corporation Wireless 8265\n"
            "\tSubsystem: Intel Corporation Dual Band Wireless-AC 8265\n"
            "\tKernel driver in use: iwlwifi\n"
            "\tKernel modules: iwlwifi\n"
        )
        self.detector._lspci_cache = lspci_output

        info = ChipInfo(driver="iwlwifi")
        self.detector._detect_from_lspci("wlan0", info)

        self.assertEqual(info.model, "Intel Corporation Wireless 8265")
        self.assertEqual(info.bus_type, "pci")

    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_lspci_no_match(self):
        """Test lspci with no matching wireless device."""
        self.detector._lspci_cache = "00:1f.3 Audio device: Intel HD Audio\n"

        info = ChipInfo(driver="ath9k")
        self.detector._detect_from_lspci("wlan0", info)

        self.assertEqual(info.model, "")

    # ─── Source 4: lsusb ──────────────────────────────────────────────────────

    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_lsusb(self):
        """Test device description detection from lsusb output."""
        lsusb_output = (
            "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
            "Bus 001 Device 003: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU\n"
        )
        self.detector._lsusb_cache = lsusb_output

        info = ChipInfo(vendor_id="0bda", product_id="8812", bus_type="usb")
        self.detector._detect_from_lsusb("wlan0", info)

        self.assertEqual(info.model, "Realtek Semiconductor Corp. RTL8812AU")

    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_lsusb_skips_pci(self):
        """Test that lsusb is skipped for PCI devices."""
        self.detector._lsusb_cache = "Bus 001 Device 003: ID 0bda:8812 Realtek\n"

        info = ChipInfo(vendor_id="0bda", product_id="8812", bus_type="pci")
        self.detector._detect_from_lsusb("wlan0", info)

        # Model should not be set because bus_type is pci
        self.assertEqual(info.model, "")

    # ─── Source 5: ethtool ────────────────────────────────────────────────────

    @patch("subprocess.run")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_ethtool(self, mock_run):
        """Test driver/firmware detection from ethtool -i."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "driver: ath9k\n"
                "version: 5.15.0\n"
                "firmware-version: N/A\n"
                "bus-info: 0000:03:00.0\n"
            ),
        )

        info = ChipInfo()
        self.detector._detect_from_ethtool("wlan0", info)

        self.assertEqual(info.driver, "ath9k")
        self.assertEqual(info.firmware_version, "N/A")
        self.assertEqual(info.bus_type, "pci")

    @patch("subprocess.run")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_ethtool_usb_bus(self, mock_run):
        """Test USB bus detection from ethtool bus-info."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "driver: rtl88xxau\n"
                "version: 5.6.4.2\n"
                "firmware-version: \n"
                "bus-info: usb-0000:00:14.0-1\n"
            ),
        )

        info = ChipInfo()
        self.detector._detect_from_ethtool("wlan0", info)

        self.assertEqual(info.driver, "rtl88xxau")
        self.assertEqual(info.bus_type, "usb")

    @patch("subprocess.run")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_ethtool_not_found(self, mock_run):
        """Test graceful handling when ethtool is not installed."""
        mock_run.side_effect = FileNotFoundError("ethtool not found")

        info = ChipInfo()
        self.detector._detect_from_ethtool("wlan0", info)

        self.assertEqual(info.driver, "")

    # ─── Source 6: iw dev/phy ─────────────────────────────────────────────────

    @patch("subprocess.run")
    @patch("os.path.isfile")
    @patch("os.path.islink")
    @patch("posframework.chip_detector.IS_LINUX", True)
    def test_detect_from_iw(self, mock_islink, mock_isfile, mock_run):
        """Test supported modes detection from iw phy info."""
        mock_isfile.return_value = False
        mock_islink.return_value = False

        # First call: iw dev wlan0 info
        iw_dev_result = MagicMock(
            returncode=0,
            stdout="Interface wlan0\n\twiphy 0\n\ttype managed\n",
        )
        # Second call: iw phy phy0 info
        iw_phy_result = MagicMock(
            returncode=0,
            stdout=(
                "Wiphy phy0\n"
                "\tSupported interface modes:\n"
                "\t\t * managed\n"
                "\t\t * AP\n"
                "\t\t * monitor\n"
                "\t\t * mesh point\n"
                "\tBand 1:\n"
            ),
        )
        mock_run.side_effect = [iw_dev_result, iw_phy_result]

        info = ChipInfo()
        self.detector._detect_from_iw("wlan0", info)

        self.assertIn("managed", info.supported_modes)
        self.assertIn("AP", info.supported_modes)
        self.assertIn("monitor", info.supported_modes)
        self.assertIn("mesh point", info.supported_modes)

    # ─── Full detect() integration ────────────────────────────────────────────

    @patch("posframework.chip_detector.IS_LINUX", True)
    @patch("os.path.islink")
    @patch("os.readlink")
    @patch("os.path.isfile")
    @patch("subprocess.run")
    def test_full_detect_intel(self, mock_run, mock_isfile, mock_readlink, mock_islink):
        """Test full detection pipeline for an Intel chipset."""
        # sysfs driver symlink
        def islink_side_effect(path):
            if "device/driver" in path:
                return True
            return False

        mock_islink.side_effect = islink_side_effect
        mock_readlink.return_value = "/sys/bus/pci/drivers/iwlwifi"
        mock_isfile.return_value = False

        # subprocess calls: ethtool, iw dev, iw phy, lspci, lsusb
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

        info = self.detector.detect("wlan0")

        self.assertEqual(info.driver, "iwlwifi")
        self.assertEqual(info.vendor, "Intel")
        self.assertTrue(info.injection_support)

    # ─── Vendor from driver ───────────────────────────────────────────────────

    def test_vendor_from_driver_intel(self):
        """Test Intel vendor detection from iwlwifi driver."""
        self.assertEqual(self.detector._vendor_from_driver("iwlwifi"), "Intel")

    def test_vendor_from_driver_atheros(self):
        """Test Atheros vendor detection from ath9k driver."""
        self.assertEqual(self.detector._vendor_from_driver("ath9k"), "Atheros")

    def test_vendor_from_driver_realtek(self):
        """Test Realtek vendor detection from rtl88xxau driver."""
        self.assertEqual(self.detector._vendor_from_driver("rtl88xxau"), "Realtek")

    def test_vendor_from_driver_mediatek(self):
        """Test MediaTek vendor detection from mt76x2u driver."""
        self.assertEqual(self.detector._vendor_from_driver("mt76x2u"), "MediaTek")

    def test_vendor_from_driver_ralink(self):
        """Test Ralink vendor detection from rt2800usb driver."""
        self.assertEqual(self.detector._vendor_from_driver("rt2800usb"), "Ralink")

    def test_vendor_from_driver_broadcom(self):
        """Test Broadcom vendor detection from brcmfmac driver."""
        self.assertEqual(self.detector._vendor_from_driver("brcmfmac"), "Broadcom")

    def test_vendor_from_driver_unknown(self):
        """Test unknown vendor for unrecognized driver."""
        self.assertEqual(self.detector._vendor_from_driver("somedriver"), "Unknown")

    # ─── Injection support ────────────────────────────────────────────────────

    def test_injection_support_ath9k(self):
        """Test injection support detection for ath9k."""
        self.assertTrue(self.detector._check_injection_support("ath9k"))

    def test_injection_support_iwlwifi(self):
        """Test injection support detection for iwlwifi."""
        self.assertTrue(self.detector._check_injection_support("iwlwifi"))

    def test_injection_support_unknown(self):
        """Test no injection support for unknown driver."""
        self.assertFalse(self.detector._check_injection_support("unknown_driver"))


# ─── MonitorMethodSelector Tests ──────────────────────────────────────────────


class TestMonitorMethodSelector(unittest.TestCase):
    """Tests for MonitorMethodSelector class."""

    def setUp(self):
        self.selector = MonitorMethodSelector()

    def test_ath9k_prefers_airmon(self):
        """ath9k should prefer airmon-ng method."""
        chip = ChipInfo(driver="ath9k")
        methods = self.selector.select(chip)

        self.assertTrue(len(methods) > 0)
        self.assertEqual(methods[0].name, "airmon-ng")

    def test_ath9k_htc_prefers_airmon(self):
        """ath9k_htc should prefer airmon-ng method."""
        chip = ChipInfo(driver="ath9k_htc")
        methods = self.selector.select(chip)

        self.assertEqual(methods[0].name, "airmon-ng")

    def test_iwlwifi_prefers_iw(self):
        """iwlwifi should prefer standard iw method."""
        chip = ChipInfo(driver="iwlwifi")
        methods = self.selector.select(chip)

        self.assertTrue(len(methods) > 0)
        self.assertEqual(methods[0].name, "iw")

    def test_mt76_prefers_iw(self):
        """mt76x2u should prefer standard iw method."""
        chip = ChipInfo(driver="mt76x2u")
        methods = self.selector.select(chip)

        self.assertEqual(methods[0].name, "iw")

    def test_rtl88xxau_prefers_driver(self):
        """rtl88xxau should prefer driver-specific method."""
        chip = ChipInfo(driver="rtl88xxau")
        methods = self.selector.select(chip)

        self.assertTrue(len(methods) > 0)
        self.assertEqual(methods[0].name, "driver")

    def test_88XXau_prefers_driver(self):
        """88XXau should prefer driver-specific method."""
        chip = ChipInfo(driver="88XXau")
        methods = self.selector.select(chip)

        self.assertEqual(methods[0].name, "driver")

    def test_unknown_driver_defaults_to_iw(self):
        """Unknown drivers should default to iw as safest option."""
        chip = ChipInfo(driver="some_unknown_driver")
        methods = self.selector.select(chip)

        self.assertEqual(methods[0].name, "iw")

    def test_all_methods_have_fallbacks(self):
        """All selections should provide fallback methods."""
        drivers = ["ath9k", "iwlwifi", "rtl88xxau", "unknown"]
        for driver in drivers:
            chip = ChipInfo(driver=driver)
            methods = self.selector.select(chip)
            self.assertGreaterEqual(
                len(methods), 2,
                f"Driver '{driver}' should have at least 2 methods (primary + fallback)"
            )

    def test_methods_have_decreasing_priority(self):
        """Methods should be ordered by decreasing priority."""
        chip = ChipInfo(driver="ath9k")
        methods = self.selector.select(chip)

        for i in range(len(methods) - 1):
            self.assertGreater(
                methods[i].priority, methods[i + 1].priority,
                "Methods should have strictly decreasing priority"
            )

    def test_get_primary_method(self):
        """get_primary_method should return the top method name."""
        chip = ChipInfo(driver="ath9k")
        self.assertEqual(self.selector.get_primary_method(chip), "airmon-ng")

        chip = ChipInfo(driver="iwlwifi")
        self.assertEqual(self.selector.get_primary_method(chip), "iw")

        chip = ChipInfo(driver="rtl88xxau")
        self.assertEqual(self.selector.get_primary_method(chip), "driver")

    def test_rt2800usb_prefers_airmon(self):
        """rt2800usb (Ralink) should prefer airmon-ng."""
        chip = ChipInfo(driver="rt2800usb")
        methods = self.selector.select(chip)
        self.assertEqual(methods[0].name, "airmon-ng")

    def test_brcmfmac_prefers_iw(self):
        """brcmfmac (Broadcom) should prefer standard iw."""
        chip = ChipInfo(driver="brcmfmac")
        methods = self.selector.select(chip)
        self.assertEqual(methods[0].name, "iw")


# ─── EnhancedMonitorManager Tests ────────────────────────────────────────────


class TestEnhancedMonitorManager(unittest.TestCase):
    """Tests for EnhancedMonitorManager with mocked subprocess calls."""

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_cleanup_registered_on_init(self, mock_getsignal, mock_signal):
        """Test that atexit and signal handlers are registered on init."""
        mock_getsignal.return_value = signal.SIG_DFL

        manager = EnhancedMonitorManager("wlan0", auto_cleanup=True)

        self.assertTrue(manager._cleanup_registered)
        # Signal handlers should be set for SIGINT and SIGTERM
        self.assertTrue(mock_signal.called)

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_no_cleanup_when_disabled(self, mock_getsignal, mock_signal):
        """Test that cleanup is not registered when auto_cleanup=False."""
        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)

        self.assertFalse(manager._cleanup_registered)

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("subprocess.run")
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_enable_monitor_mode_iw_success(self, mock_getsignal, mock_signal, mock_run):
        """Test successful monitor mode enable via iw method."""
        mock_getsignal.return_value = signal.SIG_DFL

        # Mock all subprocess calls to succeed
        def run_side_effect(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            # For iw dev info, return monitor type after setting
            if cmd == ["iw", "dev", "wlan0mon", "info"]:
                result.stdout = "Interface wlan0mon\n\ttype monitor\n"
            elif cmd == ["ip", "link", "show", "wlan0"]:
                result.stdout = "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
            return result

        mock_run.side_effect = run_side_effect

        # Mock chip detection to return a simple iwlwifi chip
        with patch.object(ChipDetector, "detect") as mock_detect:
            mock_detect.return_value = ChipInfo(driver="iwlwifi", vendor="Intel")

            manager = EnhancedMonitorManager("wlan0", retry_count=1)
            success = manager.enable_monitor_mode()

            self.assertTrue(success)
            self.assertTrue(manager.state.monitor_active)
            self.assertEqual(manager.state.method_used, "iw")

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("subprocess.run")
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_enable_fallback_on_primary_failure(self, mock_getsignal, mock_signal, mock_run):
        """Test fallback to secondary method when primary fails."""
        mock_getsignal.return_value = signal.SIG_DFL

        call_count = {"n": 0}

        def run_side_effect(cmd, **kwargs):
            call_count["n"] += 1
            result = MagicMock()
            result.stderr = ""
            result.stdout = ""

            # First method (iw) fails: the 'iw set type monitor' command fails
            if cmd == ["iw", "dev", "wlan0", "set", "type", "monitor"]:
                result.returncode = 1
                result.stderr = "Operation not supported"
                return result

            # Second method (airmon-ng) succeeds
            if cmd == ["airmon-ng", "start", "wlan0"]:
                result.returncode = 0
                result.stdout = "monitor mode enabled on wlan0mon"
                return result

            # Verify monitor mode
            if cmd == ["iw", "dev", "wlan0mon", "info"]:
                result.returncode = 0
                result.stdout = "Interface wlan0mon\n\ttype monitor\n"
                return result

            if cmd == ["ip", "link", "show", "wlan0"]:
                result.returncode = 0
                result.stdout = "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
                return result

            # Default: succeed
            result.returncode = 0
            return result

        mock_run.side_effect = run_side_effect

        with patch.object(ChipDetector, "detect") as mock_detect:
            mock_detect.return_value = ChipInfo(driver="iwlwifi", vendor="Intel")

            manager = EnhancedMonitorManager("wlan0", retry_count=1)
            success = manager.enable_monitor_mode()

            self.assertTrue(success)
            self.assertEqual(manager.state.method_used, "airmon-ng")

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("subprocess.run")
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_disable_monitor_mode(self, mock_getsignal, mock_signal, mock_run):
        """Test disabling monitor mode restores interface."""
        mock_getsignal.return_value = signal.SIG_DFL
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )

        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)
        # Manually set state as if monitor is active
        manager.state.monitor_active = True
        manager.state.method_used = "iw"
        manager.state.current_name = "wlan0mon"
        manager.state.original_name = "wlan0"
        manager.state.original_mac = "aa:bb:cc:dd:ee:ff"

        success = manager.disable_monitor_mode()

        self.assertTrue(success)
        self.assertFalse(manager.state.monitor_active)
        self.assertEqual(manager.state.current_name, "wlan0")

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("subprocess.run")
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_set_channel(self, mock_getsignal, mock_signal, mock_run):
        """Test channel setting on monitor interface."""
        mock_getsignal.return_value = signal.SIG_DFL
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)
        manager.state.current_name = "wlan0mon"
        manager.state.monitor_active = True

        success = manager.set_channel(6)

        self.assertTrue(success)
        self.assertEqual(manager.state.channel, 6)
        mock_run.assert_called_with(
            ["iw", "dev", "wlan0mon", "set", "channel", "6"],
            capture_output=True, text=True, timeout=5
        )

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_get_status(self, mock_getsignal, mock_signal):
        """Test get_status returns a dict of the current state."""
        mock_getsignal.return_value = signal.SIG_DFL

        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)
        manager.state.monitor_active = True
        manager.state.method_used = "iw"
        manager.state.current_name = "wlan0mon"
        manager.state.channel = 11

        status = manager.get_status()

        self.assertIsInstance(status, dict)
        self.assertTrue(status["monitor_active"])
        self.assertEqual(status["method_used"], "iw")
        self.assertEqual(status["current_name"], "wlan0mon")
        self.assertEqual(status["channel"], 11)

    @patch("posframework.monitor_manager.IS_LINUX", False)
    def test_enable_on_non_linux(self):
        """Test that enable returns False on non-Linux systems."""
        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)
        success = manager.enable_monitor_mode()
        self.assertFalse(success)

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("subprocess.run")
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_all_methods_fail(self, mock_getsignal, mock_signal, mock_run):
        """Test behavior when all methods fail."""
        mock_getsignal.return_value = signal.SIG_DFL

        # All subprocess calls fail
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="Operation failed"
        )

        with patch.object(ChipDetector, "detect") as mock_detect:
            mock_detect.return_value = ChipInfo(driver="iwlwifi", vendor="Intel")

            manager = EnhancedMonitorManager("wlan0", retry_count=1)
            success = manager.enable_monitor_mode()

            self.assertFalse(success)
            self.assertFalse(manager.state.monitor_active)
            self.assertIn("All methods failed", manager.state.errors)

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("subprocess.run")
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_cleanup_restores_interface(self, mock_getsignal, mock_signal, mock_run):
        """Test cleanup() restores interface when monitor is active."""
        mock_getsignal.return_value = signal.SIG_DFL
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)
        manager.state.monitor_active = True
        manager.state.method_used = "iw"
        manager.state.current_name = "wlan0mon"
        manager.state.original_name = "wlan0"

        manager.cleanup()

        self.assertFalse(manager.state.monitor_active)

    @patch("posframework.monitor_manager.IS_LINUX", True)
    @patch("signal.signal")
    @patch("signal.getsignal")
    def test_cleanup_noop_when_not_active(self, mock_getsignal, mock_signal):
        """Test cleanup() is a no-op when monitor mode is not active."""
        mock_getsignal.return_value = signal.SIG_DFL

        manager = EnhancedMonitorManager("wlan0", auto_cleanup=False)
        manager.state.monitor_active = False

        # Should not raise or do anything
        manager.cleanup()
        self.assertFalse(manager.state.monitor_active)


# ─── MonitorState Tests ───────────────────────────────────────────────────────


class TestMonitorState(unittest.TestCase):
    """Tests for MonitorState dataclass."""

    def test_to_dict(self):
        """Test state serialization to dict."""
        state = MonitorState(
            original_name="wlan0",
            current_name="wlan0mon",
            original_mode="managed",
            original_mac="aa:bb:cc:dd:ee:ff",
            monitor_active=True,
            method_used="iw",
            channel=6,
        )

        d = state.to_dict()

        self.assertEqual(d["original_name"], "wlan0")
        self.assertEqual(d["current_name"], "wlan0mon")
        self.assertEqual(d["monitor_active"], True)
        self.assertEqual(d["method_used"], "iw")
        self.assertEqual(d["channel"], 6)

    def test_default_state(self):
        """Test default state values."""
        state = MonitorState()

        self.assertEqual(state.original_name, "")
        self.assertFalse(state.monitor_active)
        self.assertEqual(state.errors, [])


# ─── ChipInfo Tests ───────────────────────────────────────────────────────────


class TestChipInfo(unittest.TestCase):
    """Tests for ChipInfo dataclass."""

    def test_family_property(self):
        """Test family returns lowercase driver name."""
        info = ChipInfo(driver="iwlwifi")
        self.assertEqual(info.family, "iwlwifi")

    def test_family_unknown_when_no_driver(self):
        """Test family returns 'unknown' when no driver set."""
        info = ChipInfo()
        self.assertEqual(info.family, "unknown")

    def test_summary_output(self):
        """Test summary produces a readable string."""
        info = ChipInfo(
            driver="ath9k",
            vendor="Atheros",
            model="AR9285",
            bus_type="pci",
            injection_support=True,
        )
        summary = info.summary()
        self.assertIn("Atheros", summary)
        self.assertIn("ath9k", summary)
        self.assertIn("AR9285", summary)
        self.assertIn("pci", summary)
        self.assertIn("yes", summary)


if __name__ == "__main__":
    unittest.main()
