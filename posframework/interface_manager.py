"""
Intelligent Interface Auto-Discovery & Assignment Module

Automatically detects available wireless interfaces, determines their capabilities
(monitor mode, AP mode, injection support), and assigns the best interface to each role.

Design:
    - Scans /sys/class/net and uses 'iw' to enumerate wireless devices
    - Checks per-phy capabilities (AP, monitor, mesh, etc.)
    - Ranks interfaces by capability and selects optimal assignment:
        * Best monitor-capable card → monitor mode
        * Best AP-capable card → AP mode (hostapd)
    - Handles edge cases: single card, cards already in use, virtual interfaces
    - Provides fallback to manual assignment if auto-detection fails
"""

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .config import IS_LINUX, IS_WINDOWS, log


# ─── Data Models ──────────────────────────────────────────────────────────────


class InterfaceMode(Enum):
    """Current operational mode of an interface."""
    MANAGED = auto()
    MONITOR = auto()
    AP = auto()
    UNKNOWN = auto()


class InterfaceRole(Enum):
    """Assigned role for the interface."""
    MONITOR = "monitor"
    AP = "ap"
    UNASSIGNED = "unassigned"


class CardCapability(Enum):
    """Wireless card capabilities detected from phy info."""
    MONITOR = "monitor"
    AP = "AP"
    AP_VLAN = "AP/VLAN"
    MESH = "mesh point"
    IBSS = "IBSS"
    P2P_CLIENT = "P2P-client"
    P2P_GO = "P2P-GO"
    MANAGED = "managed"


@dataclass
class WirelessInterface:
    """Complete representation of a detected wireless interface."""
    name: str
    phy: str                          # Physical device (phy0, phy1, etc.)
    driver: str = ""                  # Kernel driver name
    chipset: str = ""                 # Chipset description
    mac_address: str = ""
    current_mode: InterfaceMode = InterfaceMode.UNKNOWN
    capabilities: List[CardCapability] = field(default_factory=list)
    supported_bands: List[str] = field(default_factory=list)   # ["2.4GHz", "5GHz"]
    max_tx_power: int = 0            # dBm
    supports_injection: bool = False
    is_busy: bool = False            # Currently connected/in-use
    assigned_role: InterfaceRole = InterfaceRole.UNASSIGNED

    @property
    def can_monitor(self) -> bool:
        return CardCapability.MONITOR in self.capabilities

    @property
    def can_ap(self) -> bool:
        return CardCapability.AP in self.capabilities

    @property
    def monitor_score(self) -> int:
        """Score this interface for monitor mode suitability (higher = better)."""
        score = 0
        if self.can_monitor:
            score += 50
        if self.supports_injection:
            score += 30
        if "5GHz" in self.supported_bands:
            score += 10
        if self.max_tx_power > 20:
            score += 10
        # Penalize if already in AP mode or busy with a connection
        if self.current_mode == InterfaceMode.AP:
            score -= 100
        if self.is_busy:
            score -= 20
        return score

    @property
    def ap_score(self) -> int:
        """Score this interface for AP mode suitability (higher = better)."""
        score = 0
        if self.can_ap:
            score += 50
        if "5GHz" in self.supported_bands:
            score += 5
        # Prefer cards that are NOT great for monitor (leave those for monitor)
        if not self.supports_injection:
            score += 10
        # Penalize if already in monitor mode
        if self.current_mode == InterfaceMode.MONITOR:
            score -= 100
        if self.is_busy:
            score -= 10
        return score

    def __repr__(self) -> str:
        caps = [c.value for c in self.capabilities]
        return (
            f"WirelessInterface(name={self.name!r}, phy={self.phy!r}, "
            f"driver={self.driver!r}, caps={caps}, role={self.assigned_role.value})"
        )


@dataclass
class InterfaceAssignment:
    """Result of auto-assignment — which interface goes to which role."""
    monitor_interface: Optional[WirelessInterface] = None
    ap_interface: Optional[WirelessInterface] = None
    unassigned: List[WirelessInterface] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """True if both monitor and AP roles are assigned."""
        return self.monitor_interface is not None and self.ap_interface is not None

    @property
    def monitor_name(self) -> Optional[str]:
        return self.monitor_interface.name if self.monitor_interface else None

    @property
    def ap_name(self) -> Optional[str]:
        return self.ap_interface.name if self.ap_interface else None

    def summary(self) -> str:
        lines = []
        if self.monitor_interface:
            mi = self.monitor_interface
            lines.append(
                f"  MONITOR → {mi.name} [{mi.phy}] "
                f"(driver: {mi.driver}, chipset: {mi.chipset})"
            )
        else:
            lines.append("  MONITOR → [NOT ASSIGNED]")

        if self.ap_interface:
            ai = self.ap_interface
            lines.append(
                f"  AP      → {ai.name} [{ai.phy}] "
                f"(driver: {ai.driver}, chipset: {ai.chipset})"
            )
        else:
            lines.append("  AP      → [NOT ASSIGNED]")

        if self.errors:
            lines.append("  Warnings:")
            for err in self.errors:
                lines.append(f"    ⚠ {err}")

        return "\n".join(lines)


# ─── Interface Discovery (Linux) ─────────────────────────────────────────────


class LinuxInterfaceDiscovery:
    """Discovers and probes wireless interfaces on Linux using iw/sys."""

    # Known chipsets with good injection support
    INJECTION_DRIVERS = {
        "ath9k", "ath9k_htc", "ath10k_pci", "ath10k_usb",
        "rt2800usb", "rt2800pci", "rt73usb", "rt61pci",
        "rtl8187", "rtl8xxxu", "rtl88xxau", "88XXau",
        "carl9170", "b43", "brcmfmac", "iwlwifi",
        "mt76x0u", "mt76x2u", "mt7921e", "mt7921u",
        "ath11k", "ath12k",
    }

    # Drivers known for good AP support
    AP_DRIVERS = {
        "ath9k", "ath9k_htc", "ath10k_pci",
        "rt2800usb", "rt2800pci",
        "rtl8xxxu", "rtl88xxau", "88XXau",
        "brcmfmac", "mt76x0u", "mt76x2u",
        "mt7921e", "mt7921u", "ath11k", "ath12k",
    }

    def __init__(self):
        self._phy_info_cache: Dict[str, str] = {}

    def discover_interfaces(self) -> List[WirelessInterface]:
        """Enumerate all wireless interfaces from the system.

        Uses multiple methods:
            1. /sys/class/net/*/wireless symlink
            2. iw dev output
            3. iwconfig fallback
        """
        interfaces: List[WirelessInterface] = []
        seen_names: set = set()

        # Method 1: iw dev (most reliable)
        iw_interfaces = self._discover_via_iw_dev()
        for iface in iw_interfaces:
            if iface.name not in seen_names:
                interfaces.append(iface)
                seen_names.add(iface.name)

        # Method 2: /sys/class/net scan for anything we missed
        sys_interfaces = self._discover_via_sysfs()
        for iface in sys_interfaces:
            if iface.name not in seen_names:
                interfaces.append(iface)
                seen_names.add(iface.name)

        # Enrich each interface with full capability data
        for iface in interfaces:
            self._enrich_interface(iface)

        return interfaces

    def _discover_via_iw_dev(self) -> List[WirelessInterface]:
        """Parse 'iw dev' output to find wireless interfaces."""
        interfaces = []
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return interfaces

            current_phy = ""
            current_iface: Optional[WirelessInterface] = None

            for line in result.stdout.splitlines():
                line = line.strip()

                # phy#0
                phy_match = re.match(r"phy#(\d+)", line)
                if phy_match:
                    current_phy = f"phy{phy_match.group(1)}"
                    continue

                # Interface wlan0
                iface_match = re.match(r"Interface\s+(\S+)", line)
                if iface_match:
                    if current_iface:
                        interfaces.append(current_iface)
                    current_iface = WirelessInterface(
                        name=iface_match.group(1),
                        phy=current_phy,
                    )
                    continue

                if current_iface:
                    # addr aa:bb:cc:dd:ee:ff
                    addr_match = re.match(r"addr\s+([0-9a-fA-F:]{17})", line)
                    if addr_match:
                        current_iface.mac_address = addr_match.group(1).lower()

                    # type managed|monitor|AP
                    type_match = re.match(r"type\s+(\S+)", line)
                    if type_match:
                        mode_str = type_match.group(1).lower()
                        if mode_str == "monitor":
                            current_iface.current_mode = InterfaceMode.MONITOR
                        elif mode_str == "ap":
                            current_iface.current_mode = InterfaceMode.AP
                        elif mode_str == "managed":
                            current_iface.current_mode = InterfaceMode.MANAGED
                        else:
                            current_iface.current_mode = InterfaceMode.UNKNOWN

            if current_iface:
                interfaces.append(current_iface)

        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"iw dev discovery failed: {e}")

        return interfaces

    def _discover_via_sysfs(self) -> List[WirelessInterface]:
        """Discover wireless interfaces via /sys/class/net/*/wireless."""
        interfaces = []
        net_path = "/sys/class/net"

        if not os.path.isdir(net_path):
            return interfaces

        for name in os.listdir(net_path):
            wireless_path = os.path.join(net_path, name, "wireless")
            if os.path.isdir(wireless_path):
                # Determine phy
                phy_path = os.path.join(net_path, name, "phy80211", "name")
                phy = ""
                if os.path.isfile(phy_path):
                    try:
                        with open(phy_path, "r") as f:
                            phy = f.read().strip()
                    except OSError:
                        pass

                if not phy:
                    # Try resolving via symlink
                    phy_link = os.path.join(net_path, name, "phy80211")
                    if os.path.islink(phy_link):
                        phy = os.path.basename(os.readlink(phy_link))

                interfaces.append(WirelessInterface(name=name, phy=phy))

        return interfaces

    def _enrich_interface(self, iface: WirelessInterface) -> None:
        """Fill in driver, chipset, capabilities, bands, tx power for an interface."""
        self._detect_driver(iface)
        self._detect_capabilities(iface)
        self._detect_bands(iface)
        self._check_injection_support(iface)
        self._check_busy_state(iface)

    def _detect_driver(self, iface: WirelessInterface) -> None:
        """Determine the kernel driver for the interface."""
        driver_path = f"/sys/class/net/{iface.name}/device/driver"
        if os.path.islink(driver_path):
            driver_name = os.path.basename(os.readlink(driver_path))
            iface.driver = driver_name

        # Try to get chipset info from ethtool or lsusb/lspci
        chipset = self._get_chipset_info(iface.name)
        if chipset:
            iface.chipset = chipset

    def _get_chipset_info(self, iface_name: str) -> str:
        """Try to determine chipset/device description."""
        # Check device path for PCI/USB info
        device_path = f"/sys/class/net/{iface_name}/device"

        # Try uevent for device identifiers
        uevent_path = os.path.join(device_path, "uevent")
        if os.path.isfile(uevent_path):
            try:
                with open(uevent_path, "r") as f:
                    content = f.read()
                # Look for PRODUCT or PCI_ID
                for line in content.splitlines():
                    if line.startswith("PRODUCT="):
                        return line.split("=", 1)[1]
                    if line.startswith("PCI_ID="):
                        return line.split("=", 1)[1]
            except OSError:
                pass

        # Fallback: try ethtool -i
        try:
            result = subprocess.run(
                ["ethtool", "-i", iface_name],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith("bus-info:"):
                        return line.split(":", 1)[1].strip()
            return ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""

    def _detect_capabilities(self, iface: WirelessInterface) -> None:
        """Check supported interface modes from 'iw phy <phy> info'."""
        phy_info = self._get_phy_info(iface.phy)
        if not phy_info:
            return

        # Parse "Supported interface modes:" section
        in_modes = False
        for line in phy_info.splitlines():
            stripped = line.strip()
            if "Supported interface modes:" in line:
                in_modes = True
                continue
            if in_modes:
                if stripped.startswith("*"):
                    mode_str = stripped.lstrip("* ").strip()
                    for cap in CardCapability:
                        if cap.value.lower() == mode_str.lower():
                            iface.capabilities.append(cap)
                            break
                elif stripped and not stripped.startswith("*"):
                    # End of modes section
                    in_modes = False

        # Parse max TX power
        tx_match = re.search(r"max.*?(\d+)\.?\d*\s*dBm", phy_info, re.IGNORECASE)
        if tx_match:
            iface.max_tx_power = int(tx_match.group(1))

    def _detect_bands(self, iface: WirelessInterface) -> None:
        """Determine supported frequency bands from phy info."""
        phy_info = self._get_phy_info(iface.phy)
        if not phy_info:
            return

        if re.search(r"Band\s*1|2[34]\d{2}\s*MHz", phy_info):
            iface.supported_bands.append("2.4GHz")
        if re.search(r"Band\s*2|5[0-9]{3}\s*MHz", phy_info):
            iface.supported_bands.append("5GHz")
        if re.search(r"Band\s*[34]|6[0-9]{3}\s*MHz", phy_info):
            iface.supported_bands.append("6GHz")

        # Fallback: if nothing detected, assume 2.4GHz at minimum
        if not iface.supported_bands:
            iface.supported_bands.append("2.4GHz")

    def _check_injection_support(self, iface: WirelessInterface) -> None:
        """Determine if the driver supports packet injection."""
        # Check against known-good injection drivers
        if iface.driver in self.INJECTION_DRIVERS:
            iface.supports_injection = True
            return

        # Partial match for variant driver names (e.g., rtl88xxau_wfb)
        for known_driver in self.INJECTION_DRIVERS:
            if known_driver in iface.driver or iface.driver.startswith(known_driver):
                iface.supports_injection = True
                return

        # If the interface already has monitor capability, assume injection likely works
        if iface.can_monitor:
            iface.supports_injection = True

    def _check_busy_state(self, iface: WirelessInterface) -> None:
        """Check if the interface is currently connected to a network."""
        try:
            result = subprocess.run(
                ["iw", "dev", iface.name, "link"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.strip().lower()
                if "connected" in output or "ssid" in output:
                    iface.is_busy = True
                elif "not connected" in output:
                    iface.is_busy = False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def _get_phy_info(self, phy: str) -> str:
        """Get cached 'iw phy <phy> info' output."""
        if not phy:
            return ""

        if phy in self._phy_info_cache:
            return self._phy_info_cache[phy]

        try:
            result = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._phy_info_cache[phy] = result.stdout
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"Failed to get phy info for {phy}: {e}")

        self._phy_info_cache[phy] = ""
        return ""


# ─── Interface Assignment Logic ──────────────────────────────────────────────


class InterfaceManager:
    """
    Main orchestrator: discovers interfaces, scores them, and assigns roles.

    Usage:
        manager = InterfaceManager()
        assignment = manager.auto_assign()

        if assignment.is_complete:
            print(f"Monitor: {assignment.monitor_name}")
            print(f"AP:      {assignment.ap_name}")
            manager.setup_monitor(assignment)
            manager.setup_ap(assignment)
    """

    def __init__(
        self,
        prefer_monitor: Optional[str] = None,
        prefer_ap: Optional[str] = None,
        skip_busy: bool = True,
    ):
        """
        Args:
            prefer_monitor: Force a specific interface for monitor mode.
            prefer_ap: Force a specific interface for AP mode.
            skip_busy: If True, don't assign interfaces currently connected to a network.
        """
        self.prefer_monitor = prefer_monitor
        self.prefer_ap = prefer_ap
        self.skip_busy = skip_busy
        self._discovery = LinuxInterfaceDiscovery() if IS_LINUX else None
        self._interfaces: List[WirelessInterface] = []
        self._assignment: Optional[InterfaceAssignment] = None

    def discover(self) -> List[WirelessInterface]:
        """Run interface discovery and return all detected wireless interfaces."""
        if not IS_LINUX:
            log.warning("Interface auto-discovery currently only supported on Linux")
            return []

        log.info("Scanning for wireless interfaces...")
        self._interfaces = self._discovery.discover_interfaces()

        if not self._interfaces:
            log.warning("No wireless interfaces found!")
        else:
            log.info(f"Found {len(self._interfaces)} wireless interface(s):")
            for iface in self._interfaces:
                caps = ", ".join(c.value for c in iface.capabilities)
                bands = "/".join(iface.supported_bands)
                mode_str = iface.current_mode.name.lower()
                log.info(
                    f"  {iface.name} [{iface.phy}] — "
                    f"driver={iface.driver}, mode={mode_str}, "
                    f"bands={bands}, caps=[{caps}]"
                )

        return self._interfaces

    def auto_assign(self) -> InterfaceAssignment:
        """Automatically assign interfaces to monitor and AP roles.

        Algorithm:
            1. If user forced specific interfaces, use those.
            2. Otherwise, score all interfaces for each role.
            3. Assign the highest-scoring unique interface to each role.
            4. If only one card available, assign it to monitor (AP requires separate card).
        """
        if not self._interfaces:
            self.discover()

        assignment = InterfaceAssignment()
        available = list(self._interfaces)

        # Filter out busy interfaces if configured to skip them
        if self.skip_busy:
            free = [i for i in available if not i.is_busy]
            if len(free) < len(available):
                busy_names = [i.name for i in available if i.is_busy]
                log.info(f"Skipping busy interfaces: {busy_names}")
                # But don't filter if that leaves us with nothing
                if free:
                    available = free
                else:
                    assignment.errors.append(
                        "All interfaces are busy (connected). Will disconnect one."
                    )

        # Handle user preferences / forced assignments
        if self.prefer_monitor:
            mon_iface = self._find_by_name(available, self.prefer_monitor)
            if mon_iface:
                assignment.monitor_interface = mon_iface
                mon_iface.assigned_role = InterfaceRole.MONITOR
                available = [i for i in available if i.name != mon_iface.name]
            else:
                assignment.errors.append(
                    f"Preferred monitor interface '{self.prefer_monitor}' not found"
                )

        if self.prefer_ap:
            ap_iface = self._find_by_name(available, self.prefer_ap)
            if ap_iface:
                assignment.ap_interface = ap_iface
                ap_iface.assigned_role = InterfaceRole.AP
                available = [i for i in available if i.name != ap_iface.name]
            else:
                assignment.errors.append(
                    f"Preferred AP interface '{self.prefer_ap}' not found"
                )

        # Auto-assign remaining roles
        if not assignment.monitor_interface and available:
            # Score and pick best monitor candidate
            monitor_candidates = [i for i in available if i.can_monitor]
            if not monitor_candidates:
                # Relax: try any interface
                monitor_candidates = available

            monitor_candidates.sort(key=lambda i: i.monitor_score, reverse=True)
            best_mon = monitor_candidates[0]
            assignment.monitor_interface = best_mon
            best_mon.assigned_role = InterfaceRole.MONITOR
            available = [i for i in available if i.name != best_mon.name]

        if not assignment.ap_interface and available:
            # Score and pick best AP candidate from remaining
            ap_candidates = [i for i in available if i.can_ap]
            if not ap_candidates:
                ap_candidates = available

            ap_candidates.sort(key=lambda i: i.ap_score, reverse=True)
            best_ap = ap_candidates[0]
            assignment.ap_interface = best_ap
            best_ap.assigned_role = InterfaceRole.AP
            available = [i for i in available if i.name != best_ap.name]

        # Anything left is unassigned
        assignment.unassigned = available

        # Validate
        if not assignment.monitor_interface:
            assignment.errors.append("No interface available for monitor mode")
        elif not assignment.monitor_interface.can_monitor:
            assignment.errors.append(
                f"WARNING: {assignment.monitor_interface.name} may not support monitor mode"
            )

        if not assignment.ap_interface:
            assignment.errors.append("No interface available for AP mode (need 2 wireless cards)")
        elif not assignment.ap_interface.can_ap:
            assignment.errors.append(
                f"WARNING: {assignment.ap_interface.name} may not support AP mode"
            )

        self._assignment = assignment
        return assignment

    def setup_monitor(self, assignment: Optional[InterfaceAssignment] = None) -> Tuple[bool, str]:
        """Put the monitor interface into monitor mode.

        Returns:
            Tuple of (success, interface_name_after_setup).
            The interface name may change (e.g., wlan0 → wlan0mon).
        """
        assignment = assignment or self._assignment
        if not assignment or not assignment.monitor_interface:
            log.error("No interface assigned for monitor mode")
            return (False, "")

        iface = assignment.monitor_interface
        log.info(f"Setting up monitor mode on {iface.name} [{iface.phy}]...")

        # If already in monitor mode, just return
        if iface.current_mode == InterfaceMode.MONITOR:
            log.info(f"{iface.name} is already in monitor mode")
            return (True, iface.name)

        # Kill interfering processes
        self._kill_interfering_processes()

        # Bring interface down
        if not self._run_quiet(["ip", "link", "set", "dev", iface.name, "down"]):
            log.error(f"Failed to bring down {iface.name}")
            return (False, iface.name)

        # Set monitor mode
        success = self._run_quiet(
            ["iw", "dev", iface.name, "set", "type", "monitor"]
        )
        if not success:
            log.error(f"Failed to set monitor mode on {iface.name}")
            self._run_quiet(["ip", "link", "set", "dev", iface.name, "up"])
            return (False, iface.name)

        # Rename to *mon convention
        mon_name = f"{iface.name}mon" if not iface.name.endswith("mon") else iface.name
        if mon_name != iface.name:
            renamed = self._run_quiet(
                ["ip", "link", "set", "dev", iface.name, "name", mon_name]
            )
            if not renamed:
                # Keep original name
                mon_name = iface.name
                log.debug(f"Could not rename to {mon_name}, keeping {iface.name}")

        # Bring interface up
        if not self._run_quiet(["ip", "link", "set", "dev", mon_name, "up"]):
            log.error(f"Failed to bring up {mon_name}")
            return (False, mon_name)

        iface.current_mode = InterfaceMode.MONITOR
        log.info(f"✓ Monitor mode active on {mon_name}")
        return (True, mon_name)

    def setup_ap(self, assignment: Optional[InterfaceAssignment] = None) -> Tuple[bool, str]:
        """Prepare the AP interface for hostapd (managed mode, interface up).

        Does NOT start hostapd — just ensures the interface is in the right state
        for another module (rogueap.py / hostapd_helper.py) to start the AP.

        Returns:
            Tuple of (success, interface_name).
        """
        assignment = assignment or self._assignment
        if not assignment or not assignment.ap_interface:
            log.error("No interface assigned for AP mode")
            return (False, "")

        iface = assignment.ap_interface

        # If it's already in AP mode, leave it alone
        if iface.current_mode == InterfaceMode.AP:
            log.info(f"{iface.name} is already in AP mode")
            return (True, iface.name)

        log.info(f"Preparing AP interface {iface.name} [{iface.phy}]...")

        # Disconnect if busy
        if iface.is_busy:
            log.info(f"Disconnecting {iface.name} from current network...")
            self._run_quiet(["iw", "dev", iface.name, "disconnect"])
            time.sleep(0.5)

        # Ensure it's in managed mode (hostapd will switch it to AP)
        self._run_quiet(["ip", "link", "set", "dev", iface.name, "down"])
        self._run_quiet(["iw", "dev", iface.name, "set", "type", "managed"])
        self._run_quiet(["ip", "link", "set", "dev", iface.name, "up"])

        iface.current_mode = InterfaceMode.MANAGED
        log.info(f"✓ AP interface ready: {iface.name}")
        return (True, iface.name)

    def teardown(self, assignment: Optional[InterfaceAssignment] = None) -> None:
        """Restore all interfaces to their original state (managed mode, up)."""
        assignment = assignment or self._assignment
        if not assignment:
            return

        for iface in [assignment.monitor_interface, assignment.ap_interface]:
            if iface is None:
                continue

            current_name = iface.name
            # If the name ends with "mon", try to rename back
            orig_name = current_name.rstrip("mon") if current_name.endswith("mon") else current_name
            # More careful: only strip if it was appended
            if current_name.endswith("mon") and len(current_name) > 3:
                orig_name = current_name[:-3]
            else:
                orig_name = current_name

            log.info(f"Restoring {current_name} to managed mode...")
            self._run_quiet(["ip", "link", "set", "dev", current_name, "down"])
            self._run_quiet(["iw", "dev", current_name, "set", "type", "managed"])

            if orig_name != current_name:
                self._run_quiet(
                    ["ip", "link", "set", "dev", current_name, "name", orig_name]
                )
                current_name = orig_name

            self._run_quiet(["ip", "link", "set", "dev", current_name, "up"])
            iface.current_mode = InterfaceMode.MANAGED
            iface.assigned_role = InterfaceRole.UNASSIGNED
            log.info(f"  Restored {current_name}")

    def get_assignment(self) -> Optional[InterfaceAssignment]:
        """Get the current interface assignment."""
        return self._assignment

    # ─── Internal Helpers ─────────────────────────────────────────────────────

    def _find_by_name(
        self, interfaces: List[WirelessInterface], name: str
    ) -> Optional[WirelessInterface]:
        """Find an interface by name (case-insensitive, partial match)."""
        # Exact match first
        for iface in interfaces:
            if iface.name == name:
                return iface
        # Partial match
        for iface in interfaces:
            if name in iface.name or iface.name in name:
                return iface
        return None

    def _kill_interfering_processes(self) -> None:
        """Kill processes that interfere with monitor mode (NetworkManager, wpa_supplicant)."""
        # Use airmon-ng check kill if available
        result = subprocess.run(
            ["which", "airmon-ng"],
            capture_output=True, timeout=5
        )
        if result.returncode == 0:
            log.info("Killing interfering processes (airmon-ng check kill)...")
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                capture_output=True, timeout=15
            )
            return

        # Manual kill of common interfering services
        interfering = ["wpa_supplicant", "NetworkManager", "avahi-daemon"]
        for proc in interfering:
            subprocess.run(
                ["pkill", "-f", proc],
                capture_output=True, timeout=5
            )

        # Alternatively, just stop the services gracefully
        for svc in ["NetworkManager", "wpa_supplicant"]:
            subprocess.run(
                ["systemctl", "stop", svc],
                capture_output=True, timeout=10
            )

        time.sleep(1)

    def _run_quiet(self, cmd: List[str], timeout: int = 10) -> bool:
        """Run a command silently, return True on success."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                log.debug(f"Command failed: {' '.join(cmd)} → {result.stderr.strip()}")
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"Command error: {' '.join(cmd)} → {e}")
            return False


# ─── Convenience Functions ────────────────────────────────────────────────────


def auto_detect_interfaces(
    prefer_monitor: Optional[str] = None,
    prefer_ap: Optional[str] = None,
) -> InterfaceAssignment:
    """
    One-call auto-detection and assignment.

    Discovers all wireless interfaces, determines capabilities, and assigns
    the best candidates for monitor and AP roles.

    Args:
        prefer_monitor: Optional interface name to force for monitor mode.
        prefer_ap: Optional interface name to force for AP mode.

    Returns:
        InterfaceAssignment with the chosen interfaces.
    """
    manager = InterfaceManager(
        prefer_monitor=prefer_monitor,
        prefer_ap=prefer_ap,
    )
    manager.discover()
    assignment = manager.auto_assign()

    log.info("Interface Assignment:")
    log.info(assignment.summary())

    return assignment


def setup_dual_interfaces(
    prefer_monitor: Optional[str] = None,
    prefer_ap: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str], "InterfaceManager"]:
    """
    Full auto-setup: discover, assign, configure both interfaces.

    Returns:
        Tuple of (monitor_interface_name, ap_interface_name, manager).
        Names reflect post-setup state (e.g., wlan0mon after monitor enable).
        Manager is returned so caller can call teardown() later.
    """
    manager = InterfaceManager(
        prefer_monitor=prefer_monitor,
        prefer_ap=prefer_ap,
    )
    manager.discover()
    assignment = manager.auto_assign()

    log.info("Interface Assignment:")
    log.info(assignment.summary())

    monitor_name = None
    ap_name = None

    if assignment.monitor_interface:
        success, mon_iface = manager.setup_monitor(assignment)
        if success:
            monitor_name = mon_iface
        else:
            log.error("Failed to set up monitor interface")

    if assignment.ap_interface:
        success, ap_iface = manager.setup_ap(assignment)
        if success:
            ap_name = ap_iface
        else:
            log.error("Failed to set up AP interface")

    return monitor_name, ap_name, manager
