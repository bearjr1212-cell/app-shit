"""
Automatic WiFi Chip Detection & Monitor Method Selection

Probes multiple system sources to identify the wireless chipset, then selects
the optimal monitor mode method for that chip family.

Detection Sources:
    1. /sys/class/net/<iface>/device/driver symlink (kernel driver name)
    2. /sys/class/net/<iface>/device/uevent (PCI/USB vendor:product IDs)
    3. lspci -k output (PCI wireless devices)
    4. lsusb output (USB wireless adapters)
    5. ethtool -i <iface> (driver/firmware info)
    6. iw dev/phy info (capabilities, supported modes)
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import IS_LINUX, IS_WINDOWS, log


# ─── Data Models ──────────────────────────────────────────────────────────────


@dataclass
class ChipInfo:
    """Complete representation of a detected wireless chipset."""
    driver: str = ""
    vendor: str = ""                  # Intel, Broadcom, Atheros, Realtek, MediaTek, Ralink
    model: str = ""
    bus_type: str = ""                # pci, usb, sdio
    vendor_id: str = ""
    product_id: str = ""
    firmware_version: str = ""
    supported_modes: List[str] = field(default_factory=list)
    injection_support: bool = False

    @property
    def family(self) -> str:
        """Return the chip family identifier (driver-based grouping)."""
        return self.driver.lower() if self.driver else "unknown"

    def summary(self) -> str:
        """Human-readable summary of the chip info."""
        parts = []
        if self.vendor:
            parts.append(f"Vendor: {self.vendor}")
        if self.model:
            parts.append(f"Model: {self.model}")
        if self.driver:
            parts.append(f"Driver: {self.driver}")
        if self.bus_type:
            parts.append(f"Bus: {self.bus_type}")
        if self.vendor_id and self.product_id:
            parts.append(f"ID: {self.vendor_id}:{self.product_id}")
        if self.firmware_version:
            parts.append(f"FW: {self.firmware_version}")
        if self.supported_modes:
            parts.append(f"Modes: {', '.join(self.supported_modes)}")
        parts.append(f"Injection: {'yes' if self.injection_support else 'no'}")
        return " | ".join(parts)


@dataclass
class MonitorMethod:
    """
    A monitor mode activation method with priority and command info.

    Note: commands_up and commands_down are informational reference commands
    showing what each method would execute. The actual interface name is
    substituted at runtime by EnhancedMonitorManager, which dispatches on
    method.name and uses the live interface state directly. These fields
    serve as documentation for debugging and logging.
    """
    name: str                         # 'airmon-ng', 'iw', 'driver'
    priority: int = 0                 # Higher = preferred
    commands_up: List[List[str]] = field(default_factory=list)
    commands_down: List[List[str]] = field(default_factory=list)
    notes: str = ""

    def __repr__(self) -> str:
        return f"MonitorMethod(name={self.name!r}, priority={self.priority})"


# ─── Chip Detector ────────────────────────────────────────────────────────────


class ChipDetector:
    """
    Probes multiple system sources to identify a wireless chipset.

    Supports detection from:
        - /sys/class/net/<iface>/device/driver symlink
        - /sys/class/net/<iface>/device/uevent (PCI/USB vendor:product)
        - lspci -k (PCI wireless devices)
        - lsusb (USB wireless adapters)
        - ethtool -i <iface> (driver/firmware)
        - iw dev <iface> info / iw phy <phy> info (capabilities)
    """

    # Mapping of kernel driver names to vendor/family
    DRIVER_VENDOR_MAP: Dict[str, str] = {
        # Intel
        "iwlwifi": "Intel",
        "iwl3945": "Intel",
        "iwl4965": "Intel",
        "ipw2100": "Intel",
        "ipw2200": "Intel",
        # Atheros/Qualcomm
        "ath9k": "Atheros",
        "ath9k_htc": "Atheros",
        "ath10k_pci": "Atheros",
        "ath10k_usb": "Atheros",
        "ath11k": "Atheros",
        "ath12k": "Atheros",
        "ath5k": "Atheros",
        "ath6kl": "Atheros",
        "carl9170": "Atheros",
        # Realtek
        "rtl8187": "Realtek",
        "rtl8xxxu": "Realtek",
        "rtl88xxau": "Realtek",
        "88XXau": "Realtek",
        "r8188eu": "Realtek",
        "r8192eu": "Realtek",
        "rtw88_pci": "Realtek",
        "rtw88_usb": "Realtek",
        "rtw89_pci": "Realtek",
        # Broadcom
        "brcmfmac": "Broadcom",
        "brcmsmac": "Broadcom",
        "b43": "Broadcom",
        "b43legacy": "Broadcom",
        "wl": "Broadcom",
        # MediaTek/Ralink
        "mt76x0u": "MediaTek",
        "mt76x2u": "MediaTek",
        "mt76x0e": "MediaTek",
        "mt76x2e": "MediaTek",
        "mt7921e": "MediaTek",
        "mt7921u": "MediaTek",
        "mt7921s": "MediaTek",
        "mt792x_usb": "MediaTek",
        "rt2800usb": "Ralink",
        "rt2800pci": "Ralink",
        "rt73usb": "Ralink",
        "rt61pci": "Ralink",
        "rt2500usb": "Ralink",
        "rt2500pci": "Ralink",
    }

    # Drivers known to support packet injection
    INJECTION_DRIVERS = {
        "ath9k", "ath9k_htc", "ath10k_pci", "ath10k_usb",
        "rt2800usb", "rt2800pci", "rt73usb", "rt61pci",
        "rtl8187", "rtl8xxxu", "rtl88xxau", "88XXau",
        "carl9170", "b43", "brcmfmac", "iwlwifi",
        "mt76x0u", "mt76x2u", "mt7921e", "mt7921u",
        "ath11k", "ath12k",
    }

    def __init__(self):
        self._lspci_cache: Optional[str] = None
        self._lsusb_cache: Optional[str] = None

    def detect(self, interface: str) -> ChipInfo:
        """
        Detect the chipset for the given wireless interface.

        Probes all available sources and aggregates findings into a ChipInfo.

        Args:
            interface: The network interface name (e.g., 'wlan0').

        Returns:
            ChipInfo with as much detail as could be determined.
        """
        if not IS_LINUX:
            log.warning("Chip detection is only supported on Linux")
            return ChipInfo()

        info = ChipInfo()

        # Source 1: sysfs driver symlink
        self._detect_from_sysfs_driver(interface, info)

        # Source 2: sysfs uevent (vendor:product IDs)
        self._detect_from_sysfs_uevent(interface, info)

        # Source 3: lspci (PCI devices)
        self._detect_from_lspci(interface, info)

        # Source 4: lsusb (USB devices)
        self._detect_from_lsusb(interface, info)

        # Source 5: ethtool -i (driver/firmware details)
        self._detect_from_ethtool(interface, info)

        # Source 6: iw dev/phy (capabilities and supported modes)
        self._detect_from_iw(interface, info)

        # Derive vendor from driver if not already set
        if not info.vendor and info.driver:
            info.vendor = self._vendor_from_driver(info.driver)

        # Determine injection support
        if info.driver:
            info.injection_support = self._check_injection_support(info.driver)

        log.info(f"Chip detection for {interface}: {info.summary()}")
        return info

    # ─── Detection Sources ────────────────────────────────────────────────────

    def _detect_from_sysfs_driver(self, interface: str, info: ChipInfo) -> None:
        """Source 1: Read driver from /sys/class/net/<iface>/device/driver symlink."""
        driver_path = f"/sys/class/net/{interface}/device/driver"
        if os.path.islink(driver_path):
            try:
                driver_name = os.path.basename(os.readlink(driver_path))
                if driver_name and not info.driver:
                    info.driver = driver_name
                    log.debug(f"sysfs driver for {interface}: {driver_name}")
            except OSError as e:
                log.debug(f"Could not read driver symlink for {interface}: {e}")

    def _detect_from_sysfs_uevent(self, interface: str, info: ChipInfo) -> None:
        """Source 2: Read PCI/USB IDs from /sys/class/net/<iface>/device/uevent."""
        uevent_path = f"/sys/class/net/{interface}/device/uevent"
        if not os.path.isfile(uevent_path):
            return

        try:
            with open(uevent_path, "r") as f:
                content = f.read()
        except OSError as e:
            log.debug(f"Could not read uevent for {interface}: {e}")
            return

        for line in content.splitlines():
            # PCI_ID=VVVV:DDDD
            if line.startswith("PCI_ID="):
                parts = line.split("=", 1)[1].split(":")
                if len(parts) == 2:
                    info.vendor_id = parts[0].strip()
                    info.product_id = parts[1].strip()
                    if not info.bus_type:
                        info.bus_type = "pci"
                    log.debug(f"uevent PCI ID: {info.vendor_id}:{info.product_id}")

            # PRODUCT=VVVV/PPPP/... (USB format)
            elif line.startswith("PRODUCT="):
                parts = line.split("=", 1)[1].split("/")
                if len(parts) >= 2:
                    info.vendor_id = parts[0].strip()
                    info.product_id = parts[1].strip()
                    if not info.bus_type:
                        info.bus_type = "usb"
                    log.debug(f"uevent USB PRODUCT: {info.vendor_id}/{info.product_id}")

            # DRIVER=xyz
            elif line.startswith("DRIVER="):
                drv = line.split("=", 1)[1].strip()
                if drv and not info.driver:
                    info.driver = drv

            # SUBSYSTEM=pci or SUBSYSTEM=usb
            elif line.startswith("SUBSYSTEM="):
                subsys = line.split("=", 1)[1].strip().lower()
                if subsys in ("pci", "usb", "sdio") and not info.bus_type:
                    info.bus_type = subsys

    def _detect_from_lspci(self, interface: str, info: ChipInfo) -> None:
        """Source 3: Parse lspci -k output for PCI wireless devices."""
        if info.bus_type and info.bus_type != "pci":
            return  # Skip if already determined as USB/SDIO

        lspci_output = self._get_lspci_output()
        if not lspci_output:
            return

        # Look for network/wireless controller entries
        # Format:  XX:XX.X Network controller: Vendor Device Name
        #          Kernel driver in use: driver_name
        blocks = re.split(r"\n(?=\S)", lspci_output)
        for block in blocks:
            if not re.search(r"Network controller|Wireless", block, re.IGNORECASE):
                continue

            # If we already have a driver, match by driver name in the block
            if info.driver and info.driver in block:
                # Extract model from the first line
                first_line = block.splitlines()[0] if block.splitlines() else ""
                model_match = re.search(r":\s+(.+)$", first_line)
                if model_match and not info.model:
                    info.model = model_match.group(1).strip()
                if not info.bus_type:
                    info.bus_type = "pci"
                log.debug(f"lspci matched driver {info.driver}: {info.model}")
                return

            # If we have vendor/product IDs, try to match those
            if info.vendor_id and info.product_id:
                id_pattern = f"{info.vendor_id}:{info.product_id}".lower()
                if id_pattern in block.lower():
                    first_line = block.splitlines()[0] if block.splitlines() else ""
                    model_match = re.search(r":\s+(.+)$", first_line)
                    if model_match and not info.model:
                        info.model = model_match.group(1).strip()
                    # Extract driver if listed
                    drv_match = re.search(
                        r"Kernel driver in use:\s*(\S+)", block
                    )
                    if drv_match and not info.driver:
                        info.driver = drv_match.group(1)
                    if not info.bus_type:
                        info.bus_type = "pci"
                    log.debug(f"lspci matched IDs: {info.model}")
                    return

    def _detect_from_lsusb(self, interface: str, info: ChipInfo) -> None:
        """Source 4: Parse lsusb output for USB wireless adapters."""
        if info.bus_type and info.bus_type != "usb":
            return  # Skip if already determined as PCI/SDIO

        lsusb_output = self._get_lsusb_output()
        if not lsusb_output:
            return

        # If we have vendor:product from uevent, match in lsusb
        if info.vendor_id and info.product_id:
            # lsusb format: Bus 001 Device 003: ID VVVV:PPPP Description
            vid = info.vendor_id.lower().lstrip("0") or "0"
            pid = info.product_id.lower().lstrip("0") or "0"
            # Try matching with zero-padded 4-char IDs
            vid_padded = info.vendor_id.lower().zfill(4)
            pid_padded = info.product_id.lower().zfill(4)
            search_id = f"{vid_padded}:{pid_padded}"

            for line in lsusb_output.splitlines():
                if search_id in line.lower():
                    # Extract device description
                    desc_match = re.search(
                        r"ID\s+[0-9a-fA-F:]+\s+(.+)$", line
                    )
                    if desc_match and not info.model:
                        info.model = desc_match.group(1).strip()
                    if not info.bus_type:
                        info.bus_type = "usb"
                    log.debug(f"lsusb matched: {info.model}")
                    return

    def _detect_from_ethtool(self, interface: str, info: ChipInfo) -> None:
        """Source 5: Use ethtool -i to get driver, version, firmware info."""
        try:
            result = subprocess.run(
                ["ethtool", "-i", interface],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"ethtool failed for {interface}: {e}")
            return

        for line in result.stdout.splitlines():
            if line.startswith("driver:"):
                drv = line.split(":", 1)[1].strip()
                if drv and not info.driver:
                    info.driver = drv
            elif line.startswith("version:"):
                ver = line.split(":", 1)[1].strip()
                if ver and not info.firmware_version:
                    info.firmware_version = ver
            elif line.startswith("firmware-version:"):
                fw = line.split(":", 1)[1].strip()
                if fw:
                    info.firmware_version = fw
            elif line.startswith("bus-info:"):
                bus = line.split(":", 1)[1].strip()
                if bus and not info.bus_type:
                    if "usb" in bus.lower():
                        info.bus_type = "usb"
                    elif "pci" in bus.lower() or bus.startswith("0000:"):
                        info.bus_type = "pci"

    def _detect_from_iw(self, interface: str, info: ChipInfo) -> None:
        """Source 6: Use iw dev/phy to detect capabilities and supported modes."""
        # Get phy name for the interface
        phy = self._get_phy_for_interface(interface)

        # iw dev <iface> info -- basic interface info
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("wiphy"):
                        # wiphy 0 -> phy0
                        wiphy_match = re.match(r"wiphy\s+(\d+)", line)
                        if wiphy_match and not phy:
                            phy = f"phy{wiphy_match.group(1)}"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"iw dev info failed for {interface}: {e}")

        if not phy:
            return

        # iw phy <phy> info -- full capabilities
        try:
            result = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"iw phy info failed for {phy}: {e}")
            return

        # Parse supported interface modes
        in_modes_section = False
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if "Supported interface modes:" in line:
                in_modes_section = True
                continue
            if in_modes_section:
                if stripped.startswith("*"):
                    mode = stripped.lstrip("* ").strip()
                    if mode and mode not in info.supported_modes:
                        info.supported_modes.append(mode)
                elif stripped and not stripped.startswith("*"):
                    in_modes_section = False

    # ─── Helper Methods ───────────────────────────────────────────────────────

    def _get_phy_for_interface(self, interface: str) -> Optional[str]:
        """Determine the phy device for a given interface."""
        # Try sysfs path first
        phy_path = f"/sys/class/net/{interface}/phy80211/name"
        if os.path.isfile(phy_path):
            try:
                with open(phy_path, "r") as f:
                    return f.read().strip()
            except OSError:
                pass

        # Try phy80211 symlink
        phy_link = f"/sys/class/net/{interface}/phy80211"
        if os.path.islink(phy_link):
            return os.path.basename(os.readlink(phy_link))

        return None

    def _get_lspci_output(self) -> str:
        """Get cached lspci -k output."""
        if self._lspci_cache is not None:
            return self._lspci_cache

        try:
            result = subprocess.run(
                ["lspci", "-k"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._lspci_cache = result.stdout
            else:
                self._lspci_cache = ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._lspci_cache = ""

        return self._lspci_cache

    def _get_lsusb_output(self) -> str:
        """Get cached lsusb output."""
        if self._lsusb_cache is not None:
            return self._lsusb_cache

        try:
            result = subprocess.run(
                ["lsusb"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._lsusb_cache = result.stdout
            else:
                self._lsusb_cache = ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            self._lsusb_cache = ""

        return self._lsusb_cache

    def _vendor_from_driver(self, driver: str) -> str:
        """Determine vendor name from the kernel driver name."""
        # Exact match first
        if driver in self.DRIVER_VENDOR_MAP:
            return self.DRIVER_VENDOR_MAP[driver]

        # Partial match for variant driver names
        for known_driver, vendor in self.DRIVER_VENDOR_MAP.items():
            if known_driver in driver or driver.startswith(known_driver):
                return vendor

        # Heuristic matching by prefix
        driver_lower = driver.lower()
        if driver_lower.startswith("iwl"):
            return "Intel"
        if driver_lower.startswith("ath"):
            return "Atheros"
        if driver_lower.startswith("rtl") or driver_lower.startswith("r81"):
            return "Realtek"
        if driver_lower.startswith("brcm") or driver_lower.startswith("b43"):
            return "Broadcom"
        if driver_lower.startswith("mt7") or driver_lower.startswith("mt76"):
            return "MediaTek"
        if driver_lower.startswith("rt2") or driver_lower.startswith("rt6"):
            return "Ralink"

        return "Unknown"

    def _check_injection_support(self, driver: str) -> bool:
        """Check if the driver is known to support packet injection."""
        if driver in self.INJECTION_DRIVERS:
            return True
        # Partial match for variant names
        for known in self.INJECTION_DRIVERS:
            if known in driver or driver.startswith(known):
                return True
        return False


# ─── Monitor Method Selector ──────────────────────────────────────────────────


class MonitorMethodSelector:
    """
    Selects the optimal monitor mode method for a given chipset.

    Methods:
        - 'airmon-ng': Best for cards known to work with aircrack-ng suite
          (ath9k, ath9k_htc, carl9170, rt2800usb)
        - 'iw': Standard nl80211 method for well-supported drivers
          (iwlwifi, mt76, ath10k, ath11k)
        - 'driver': Direct driver-specific commands for cards requiring them
          (rtl88xxau with custom ioctl)

    Each selection returns a priority-ordered list of methods to try,
    so if the primary fails, the system can fall back to alternatives.
    """

    # Drivers best served by airmon-ng
    AIRMON_DRIVERS = {
        "ath9k", "ath9k_htc", "carl9170",
        "rt2800usb", "rt2800pci", "rt73usb", "rt61pci",
        "rtl8187", "b43",
    }

    # Drivers that work well with standard iw commands
    IW_DRIVERS = {
        "iwlwifi", "iwl3945", "iwl4965",
        "mt76x0u", "mt76x2u", "mt76x0e", "mt76x2e",
        "mt7921e", "mt7921u", "mt7921s",
        "ath10k_pci", "ath10k_usb", "ath11k", "ath12k",
        "brcmfmac", "brcmsmac",
        "rtw88_pci", "rtw88_usb", "rtw89_pci",
    }

    # Drivers requiring direct driver commands (ioctl-based)
    DRIVER_CMD_DRIVERS = {
        "rtl88xxau", "88XXau", "rtl8xxxu",
        "r8188eu", "r8192eu",
    }

    def select(self, chip_info: ChipInfo) -> List[MonitorMethod]:
        """
        Select monitor mode methods for the given chip, ordered by priority.

        Args:
            chip_info: Detected chip information.

        Returns:
            List of MonitorMethod objects ordered by priority (highest first).
        """
        driver = chip_info.driver
        interface = "IFACE"  # Placeholder; actual interface filled at runtime

        methods: List[MonitorMethod] = []

        if self._is_airmon_driver(driver):
            methods.append(self._airmon_method(interface, driver))
            methods.append(self._iw_method(interface))
            methods.append(self._driver_method(interface, driver))
        elif self._is_driver_cmd_driver(driver):
            methods.append(self._driver_method(interface, driver))
            methods.append(self._iw_method(interface))
            methods.append(self._airmon_method(interface, driver))
        elif self._is_iw_driver(driver):
            methods.append(self._iw_method(interface))
            methods.append(self._airmon_method(interface, driver))
            methods.append(self._driver_method(interface, driver))
        else:
            # Unknown driver: try iw first (safest default), then airmon, then driver
            methods.append(self._iw_method(interface))
            methods.append(self._airmon_method(interface, driver))
            methods.append(self._driver_method(interface, driver))

        # Assign priorities (highest first)
        for idx, method in enumerate(methods):
            method.priority = len(methods) - idx

        log.debug(
            f"Monitor methods for driver '{driver}': "
            f"{[m.name for m in methods]}"
        )
        return methods

    def get_primary_method(self, chip_info: ChipInfo) -> str:
        """Return the name of the primary (best) method for the chip."""
        methods = self.select(chip_info)
        if methods:
            return methods[0].name
        return "iw"

    # ─── Method Builders ──────────────────────────────────────────────────────

    def _airmon_method(self, interface: str, driver: str) -> MonitorMethod:
        """Build airmon-ng based monitor method."""
        return MonitorMethod(
            name="airmon-ng",
            commands_up=[
                ["airmon-ng", "check", "kill"],
                ["airmon-ng", "start", interface],
            ],
            commands_down=[
                ["airmon-ng", "stop", f"{interface}mon"],
            ],
            notes=f"airmon-ng method for {driver}; handles process killing automatically",
        )

    def _iw_method(self, interface: str) -> MonitorMethod:
        """Build iw/ip based monitor method (standard nl80211)."""
        return MonitorMethod(
            name="iw",
            commands_up=[
                ["ip", "link", "set", "dev", interface, "down"],
                ["iw", "dev", interface, "set", "type", "monitor"],
                ["ip", "link", "set", "dev", interface, "up"],
            ],
            commands_down=[
                ["ip", "link", "set", "dev", interface, "down"],
                ["iw", "dev", interface, "set", "type", "managed"],
                ["ip", "link", "set", "dev", interface, "up"],
            ],
            notes="Standard nl80211 iw method",
        )

    def _driver_method(self, interface: str, driver: str) -> MonitorMethod:
        """Build driver-specific monitor method."""
        if driver in ("rtl88xxau", "88XXau"):
            return MonitorMethod(
                name="driver",
                commands_up=[
                    ["ip", "link", "set", "dev", interface, "down"],
                    ["iwconfig", interface, "mode", "monitor"],
                    ["ip", "link", "set", "dev", interface, "up"],
                ],
                commands_down=[
                    ["ip", "link", "set", "dev", interface, "down"],
                    ["iwconfig", interface, "mode", "managed"],
                    ["ip", "link", "set", "dev", interface, "up"],
                ],
                notes=f"Driver-specific iwconfig method for {driver}",
            )
        # Generic driver fallback (uses iwconfig)
        return MonitorMethod(
            name="driver",
            commands_up=[
                ["ip", "link", "set", "dev", interface, "down"],
                ["iwconfig", interface, "mode", "monitor"],
                ["ip", "link", "set", "dev", interface, "up"],
            ],
            commands_down=[
                ["ip", "link", "set", "dev", interface, "down"],
                ["iwconfig", interface, "mode", "managed"],
                ["ip", "link", "set", "dev", interface, "up"],
            ],
            notes=f"Generic iwconfig driver method for {driver}",
        )

    # ─── Classification Helpers ───────────────────────────────────────────────

    def _is_airmon_driver(self, driver: str) -> bool:
        """Check if the driver works best with airmon-ng."""
        if driver in self.AIRMON_DRIVERS:
            return True
        for known in self.AIRMON_DRIVERS:
            if known in driver:
                return True
        return False

    def _is_iw_driver(self, driver: str) -> bool:
        """Check if the driver works best with standard iw commands."""
        if driver in self.IW_DRIVERS:
            return True
        for known in self.IW_DRIVERS:
            if known in driver:
                return True
        return False

    def _is_driver_cmd_driver(self, driver: str) -> bool:
        """Check if the driver requires direct driver commands."""
        if driver in self.DRIVER_CMD_DRIVERS:
            return True
        for known in self.DRIVER_CMD_DRIVERS:
            if known in driver:
                return True
        return False
