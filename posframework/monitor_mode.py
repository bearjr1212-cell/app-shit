"""
Cross-Platform Monitor Mode Manager

Provides monitor mode management for WiFi interfaces on both Linux and Windows.
Linux: Uses 'iw' and 'ip' commands for interface configuration.
Windows: Handles Npcap-based monitoring, chip detection, and interface configuration.
"""

import os
import subprocess
import time
import re
from typing import Optional, Tuple, List, Dict

from .config import IS_WINDOWS, IS_LINUX, log


class MonitorModeError(Exception):
    """Raised when monitor mode operations fail."""
    pass


class MonitorManagerInterface:
    """Base class for monitor mode management across platforms."""

    def __init__(self, interface: str):
        self.interface = interface
        self.monitor_active = False
        self.original_mac: Optional[str] = None

    def check_supported(self) -> bool:
        """Check if the interface supports monitor mode."""
        raise NotImplementedError("Subclasses must implement check_supported()")

    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on the interface."""
        raise NotImplementedError("Subclasses must implement enable_monitor_mode()")

    def disable_monitor_mode(self) -> bool:
        """Disable monitor mode and restore normal operation."""
        raise NotImplementedError("Subclasses must implement disable_monitor_mode()")

    def set_channel(self, channel: int) -> bool:
        """Set the wireless channel for monitoring."""
        raise NotImplementedError("Subclasses must implement set_channel()")

    def get_mac_address(self) -> Optional[str]:
        """Get the current MAC address of the interface."""
        raise NotImplementedError("Subclasses must implement get_mac_address()")

    def set_mac_address(self, mac: str) -> bool:
        """Set a new MAC address on the interface."""
        raise NotImplementedError("Subclasses must implement set_mac_address()")


class WindowsMonitorManager(MonitorManagerInterface):
    """Monitor mode manager for Windows systems using Npcap."""

    def __init__(self, interface: str):
        super().__init__(interface)
        self._npcap_path: Optional[str] = self._get_npcap_path()
        self._is_virtual: bool = self._is_virtual_adapter()
        self._saved_connection: Optional[Dict[str, str]] = None

    def _get_npcap_path(self) -> Optional[str]:
        """Locate the Npcap installation directory."""
        possible_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                log.info(f"Found Npcap at: {path}")
                return path
        log.warning("Npcap not found in any standard location")
        return None

    def _is_virtual_adapter(self) -> bool:
        """Check if the interface is a virtual adapter."""
        virtual_keywords = [
            "Virtual",
            "Hosted",
            "Microsoft Wi-Fi Direct",
            "WAN Miniport",
            "Loopback",
            "Teredo",
        ]
        for keyword in virtual_keywords:
            if keyword.lower() in self.interface.lower():
                return True
        return False

    def _get_current_connection(self) -> Optional[Dict[str, str]]:
        """Get the current WiFi connection details."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                log.error("Failed to query wlan interfaces")
                return None

            output = result.stdout
            connection_info: Dict[str, str] = {}

            ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, re.MULTILINE)
            if ssid_match:
                connection_info["ssid"] = ssid_match.group(1).strip()

            bssid_match = re.search(r"^\s*BSSID\s*:\s*(.+)$", output, re.MULTILINE)
            if bssid_match:
                connection_info["bssid"] = bssid_match.group(1).strip()

            channel_match = re.search(r"^\s*Channel\s*:\s*(\d+)", output, re.MULTILINE)
            if channel_match:
                connection_info["channel"] = channel_match.group(1).strip()

            if connection_info:
                return connection_info
            return None

        except (subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Error getting connection info: {e}")
            return None

    def disconnect_wifi(self) -> bool:
        """Disconnect from current WiFi network, saving connection details."""
        self._saved_connection = self._get_current_connection()
        if self._saved_connection:
            log.info(f"Saved connection: {self._saved_connection.get('ssid', 'Unknown')}")

        try:
            result = subprocess.run(
                ["netsh", "wlan", "disconnect"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                log.info("WiFi disconnected successfully")
                time.sleep(1)
                return True
            else:
                log.error(f"Disconnect failed: {result.stderr}")
                return False
        except (subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Error disconnecting WiFi: {e}")
            return False

    def reconnect_wifi(self) -> bool:
        """Reconnect to the previously saved WiFi network."""
        if not self._saved_connection or "ssid" not in self._saved_connection:
            log.info("No saved connection to reconnect to")
            return False

        ssid = self._saved_connection["ssid"]
        try:
            result = subprocess.run(
                ["netsh", "wlan", "connect", f"name={ssid}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                log.info(f"Reconnected to: {ssid}")
                time.sleep(2)
                return True
            else:
                log.error(f"Reconnect failed: {result.stderr}")
                return False
        except (subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Error reconnecting WiFi: {e}")
            return False

    def check_supported(self) -> bool:
        """Check if monitor mode is supported on this interface."""
        if self._is_virtual:
            log.info(f"Virtual adapter not supported: {self.interface}")
            return False

        if self._npcap_path is None:
            log.warning("Npcap not installed - monitor mode unavailable")
            return False

        log.info(f"Interface '{self.interface}' supports monitor mode")
        return True

    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on Windows via Npcap."""
        if not self.check_supported():
            log.error(f"Monitor mode not supported on '{self.interface}'")
            return False

        self.original_mac = self.get_mac_address()
        log.info(f"Original MAC: {self.original_mac}")

        if not self.disconnect_wifi():
            log.warning("Could not disconnect WiFi before enabling monitor mode")

        self.monitor_active = True
        log.info(f"Monitor mode enabled on '{self.interface}' (Npcap-based)")
        return True

    def disable_monitor_mode(self) -> bool:
        """Disable monitor mode and restore normal WiFi operation."""
        if not self.monitor_active:
            log.info("Monitor mode is not active")
            return False

        self.reconnect_wifi()
        self.monitor_active = False
        log.info(f"Monitor mode disabled on '{self.interface}'")
        return True

    def set_channel(self, channel: int) -> bool:
        """Set the wireless channel (Windows auto-selects channel)."""
        log.info(f"Channel {channel} requested - Windows auto-selects channel during scan")
        return True

    def get_mac_address(self) -> Optional[str]:
        """Get the MAC address of the interface from ipconfig."""
        try:
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            sections = re.split(r"\r?\n(?=\S)", output)

            for section in sections:
                if self.interface.lower() in section.lower():
                    mac_match = re.search(
                        r"Physical Address[\s.]*:\s*([0-9A-Fa-f-]{17})",
                        section,
                    )
                    if mac_match:
                        mac = mac_match.group(1).replace("-", ":").upper()
                        return mac

            return None

        except (subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Error getting MAC address: {e}")
            return None

    def set_mac_address(self, mac: str) -> bool:
        """Attempt to set MAC address (requires registry modification on Windows)."""
        log.warning(
            "Changing MAC on Windows requires registry modification "
            "and adapter restart. This is not fully automated."
        )
        log.info(
            f"To change MAC to {mac}, modify the NetworkAddress registry key "
            r"under HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}"
        )
        return False


class LinuxMonitorManager(MonitorManagerInterface):
    """Monitor mode manager for Linux systems using iw/ip commands."""

    def __init__(self, interface: str):
        super().__init__(interface)
        # Determine the base interface name by stripping any 'mon' suffix(es).
        # This prevents the "monmonmon" bug where repeatedly constructing
        # LinuxMonitorManager on an already-renamed interface keeps appending 'mon'.
        base = interface
        while base.endswith("mon"):
            base = base[:-3]
        # If stripping produced an empty string (e.g., interface was literally "mon"),
        # fall back to the original name.
        if not base:
            base = interface
        self._original_interface: str = base
        self._monitor_interface: str = f"{base}mon"
        self._passed_interface: str = interface  # what was actually passed in
        self._original_state: Optional[Dict[str, str]] = None

    def _run_cmd(self, cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
        """Run a shell command and return (success, output)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout.strip()
            if result.returncode != 0:
                err = result.stderr.strip()
                log.debug(f"Command failed: {' '.join(cmd)} -> {err}")
                return (False, err)
            return (True, output)
        except (subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Error running command {' '.join(cmd)}: {e}")
            return (False, str(e))

    def _save_original_state(self) -> None:
        """Save the original interface state for later restoration."""
        self._original_state = {
            "interface": self._original_interface,
        }
        mac = self.get_mac_address()
        if mac:
            self._original_state["mac"] = mac
        log.info(f"Saved original state for {self._original_interface}")

    def _interface_down(self, iface: str) -> bool:
        """Bring an interface down."""
        success, _ = self._run_cmd(["ip", "link", "set", "dev", iface, "down"])
        return success

    def _interface_up(self, iface: str) -> bool:
        """Bring an interface up."""
        success, _ = self._run_cmd(["ip", "link", "set", "dev", iface, "up"])
        return success

    def check_supported(self) -> bool:
        """Check if the interface supports monitor mode using iw."""
        success, output = self._run_cmd(["iw", "phy"])
        if not success:
            log.warning("iw command not available or failed")
            return False

        # Check if interface exists (try original base name, then passed name)
        success, output = self._run_cmd(["iw", "dev", self._original_interface, "info"])
        if not success and self._passed_interface != self._original_interface:
            success, output = self._run_cmd(["iw", "dev", self._passed_interface, "info"])
            if success:
                # The passed name exists but the base doesn't — adjust
                self._original_interface = self._passed_interface
        if not success:
            log.warning(f"Interface '{self._original_interface}' not found")
            return False

        # Check for monitor mode support in phy capabilities
        success, output = self._run_cmd(["iw", "phy"])
        if success and "monitor" in output.lower():
            log.info(f"Interface '{self._original_interface}' supports monitor mode")
            return True

        # If we can't determine from phy info, assume support (common case)
        log.info(f"Assuming monitor mode support for '{self._original_interface}'")
        return True

    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on Linux using iw/ip commands.

        Steps:
            1. Save original state (MAC, interface name)
            2. Bring interface down
            3. Set interface type to monitor
            4. Rename interface to <iface>mon
            5. Bring monitor interface up
        """
        # If the passed interface already ends with 'mon' and exists, check if
        # it's already in monitor mode to avoid the monmonmon problem.
        if self._passed_interface != self._original_interface:
            success, output = self._run_cmd(
                ["iw", "dev", self._passed_interface, "info"]
            )
            if success and "type monitor" in output:
                log.info(f"{self._passed_interface} is already in monitor mode")
                self._monitor_interface = self._passed_interface
                self.interface = self._passed_interface
                self.monitor_active = True
                return True
            # The passed name has 'mon' but the device doesn't exist or isn't
            # in monitor mode — try the base name instead.
            success_base, _ = self._run_cmd(
                ["iw", "dev", self._original_interface, "info"]
            )
            if not success_base and success:
                # The 'mon' name exists but base doesn't — use it as-is
                self._original_interface = self._passed_interface

        self._save_original_state()
        self.original_mac = self.get_mac_address()

        # Bring interface down
        if not self._interface_down(self._original_interface):
            log.error(f"Failed to bring down {self._original_interface}")
            return False

        # Set monitor mode
        success, _ = self._run_cmd([
            "iw", "dev", self._original_interface, "set", "type", "monitor"
        ])
        if not success:
            log.error(f"Failed to set monitor mode on {self._original_interface}")
            # Try to restore interface
            self._interface_up(self._original_interface)
            return False

        # Rename interface to monitor name (e.g., wlan0 -> wlan0mon)
        if self._original_interface != self._monitor_interface:
            success, _ = self._run_cmd([
                "ip", "link", "set", "dev", self._original_interface, "name", self._monitor_interface
            ])
            if not success:
                # Renaming failed, keep original name
                log.warning(f"Could not rename to {self._monitor_interface}, using {self._original_interface}")
                self._monitor_interface = self._original_interface
        

        # Bring monitor interface up
        if not self._interface_up(self._monitor_interface):
            log.error(f"Failed to bring up {self._monitor_interface}")
            return False

        self.interface = self._monitor_interface
        self.monitor_active = True
        log.info(f"Monitor mode enabled: {self._monitor_interface}")
        return True

    def disable_monitor_mode(self) -> bool:
        """Disable monitor mode and restore the interface to managed mode.

        Steps:
            1. Bring monitor interface down
            2. Set interface type back to managed
            3. Rename interface back to original name
            4. Restore original MAC if changed
            5. Bring interface up
        """
        if not self.monitor_active:
            log.info("Monitor mode is not active")
            return False

        # Bring interface down
        self._interface_down(self._monitor_interface)

        # Set managed mode
        self._run_cmd([
            "iw", "dev", self._monitor_interface, "set", "type", "managed"
        ])

        # Rename back to original if it was renamed
        if self._monitor_interface != self._original_interface:
            self._run_cmd([
                "ip", "link", "set", "dev", self._monitor_interface,
                "name", self._original_interface
            ])

        # Restore original MAC if saved
        if self._original_state and "mac" in self._original_state:
            self._run_cmd([
                "ip", "link", "set", "dev", self._original_interface,
                "address", self._original_state["mac"]
            ])

        # Bring interface back up
        self._interface_up(self._original_interface)

        self.interface = self._original_interface
        self.monitor_active = False
        log.info(f"Monitor mode disabled, restored: {self._original_interface}")
        return True

    def set_channel(self, channel: int) -> bool:
        """Set the wireless channel using iw."""
        target_iface = self._monitor_interface if self.monitor_active else self._original_interface
        success, _ = self._run_cmd([
            "iw", "dev", target_iface, "set", "channel", str(channel)
        ])
        if success:
            log.debug(f"Channel set to {channel} on {target_iface}")
        else:
            log.warning(f"Failed to set channel {channel} on {target_iface}")
        return success

    def get_mac_address(self) -> Optional[str]:
        """Get the current MAC address using 'ip link show'."""
        target_iface = self._monitor_interface if self.monitor_active else self._original_interface
        success, output = self._run_cmd(["ip", "link", "show", target_iface])
        if not success:
            return None

        # Parse MAC from: link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
        mac_match = re.search(
            r"link/ether\s+([0-9a-fA-F:]{17})",
            output,
        )
        if mac_match:
            return mac_match.group(1).upper()
        return None

    def set_mac_address(self, mac: str) -> bool:
        """Set a new MAC address using 'ip link set dev <iface> address <mac>'.

        The interface must be down to change the MAC address.
        """
        target_iface = self._monitor_interface if self.monitor_active else self._original_interface

        # Bring interface down
        if not self._interface_down(target_iface):
            log.error(f"Failed to bring down {target_iface} for MAC change")
            return False

        # Set the new MAC address
        success, _ = self._run_cmd([
            "ip", "link", "set", "dev", target_iface, "address", mac
        ])
        if not success:
            log.error(f"Failed to set MAC address to {mac} on {target_iface}")
            self._interface_up(target_iface)
            return False

        # Bring interface back up
        self._interface_up(target_iface)
        log.info(f"MAC address set to {mac} on {target_iface}")
        return True


class ChipMonitorManager:
    """Chip-based monitor mode configuration manager."""

    CHIP_OUI: Dict[str, List[str]] = {
        "Intel": ["00:13:E8", "00:15:00", "00:16:EA", "00:1B:77", "00:1C:BF", "00:1D:E0", "00:1E:64"],
        "Broadcom": ["00:10:18", "00:17:C4", "00:1A:2B", "00:1B:E9", "00:1C:10"],
        "Atheros": ["00:03:7F", "00:0B:6B", "00:13:74", "00:15:AF", "00:1B:9E"],
        "Realtek": ["00:0A:EB", "00:0E:2E", "00:13:EF", "00:1A:3F", "00:1F:D4", "52:54:00"],
    }

    def detect_chip(self, mac_address: str) -> Optional[str]:
        """Detect the WiFi chip manufacturer from MAC address OUI."""
        if not mac_address:
            return None

        mac_upper = mac_address.upper().replace("-", ":")
        oui = mac_upper[:8]

        for chip_type, oui_list in self.CHIP_OUI.items():
            if oui in oui_list:
                log.info(f"Detected chip type: {chip_type} (OUI: {oui})")
                return chip_type

        log.info(f"Unknown chip manufacturer for OUI: {oui}")
        return None

    def get_chip_config(self, chip_type: str, interface: str) -> Dict[str, str]:
        """Get chip-specific configuration for monitor mode."""
        configs: Dict[str, Dict[str, str]] = {
            "Intel": {
                "driver_hint": "Intel WiFi driver (Netwtw06/08/10)",
                "monitor_support": "limited",
                "notes": "Intel adapters have limited raw capture support on Windows",
            },
            "Broadcom": {
                "driver_hint": "Broadcom WiFi driver (bcmwl)",
                "monitor_support": "partial",
                "notes": "Some Broadcom chips support monitor via custom drivers",
            },
            "Atheros": {
                "driver_hint": "Atheros/Qualcomm WiFi driver",
                "monitor_support": "good",
                "notes": "Atheros chips often have better monitor mode support",
            },
            "Realtek": {
                "driver_hint": "Realtek WiFi driver (rtl88xx)",
                "monitor_support": "good",
                "notes": "Realtek adapters with custom drivers support monitor mode well",
            },
        }

        config = configs.get(chip_type, {
            "driver_hint": "Unknown",
            "monitor_support": "unknown",
            "notes": "Chip type not recognized",
        })
        config["interface"] = interface
        config["chip_type"] = chip_type

        log.info(f"Config for {chip_type} on {interface}: support={config['monitor_support']}")
        return config


class WindowsChipMonitorManager(ChipMonitorManager):
    """Windows-specific chip monitor manager wrapping WindowsMonitorManager."""

    def __init__(self, interface: str):
        super().__init__()
        self.monitor_manager = WindowsMonitorManager(interface)
        self.interface = interface

    def enable_with_chip_config(self) -> Tuple[bool, Dict[str, str]]:
        """Enable monitor mode with chip-specific configuration."""
        mac = self.monitor_manager.get_mac_address()
        chip_type = self.detect_chip(mac) if mac else None

        config: Dict[str, str] = {}
        if chip_type:
            config = self.get_chip_config(chip_type, self.interface)

        success = self.monitor_manager.enable_monitor_mode()
        return success, config

    def disable(self) -> bool:
        """Disable monitor mode."""
        return self.monitor_manager.disable_monitor_mode()


# ─────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────


def get_interface_mac(interface: str) -> Optional[str]:
    """Get the MAC address for a given interface name."""
    manager = WindowsMonitorManager(interface)
    return manager.get_mac_address()


def setup_monitor_mode(interface: str, chip_type: Optional[str] = None) -> Tuple[bool, Optional[object]]:
    """Set up monitor mode on the specified interface.

    Auto-detects platform and uses the appropriate monitor manager:
        - Linux: LinuxMonitorManager (iw/ip commands)
        - Windows: WindowsChipMonitorManager (Npcap-based)

    Args:
        interface: The network interface name.
        chip_type: Optional chip type hint for configuration (Windows only).

    Returns:
        Tuple of (success, manager instance or None).
    """
    log.info(f"Setting up monitor mode on: {interface}")

    if IS_LINUX:
        manager = LinuxMonitorManager(interface)
        if not manager.check_supported():
            log.info(f"Interface '{interface}' does not support monitor mode")
            return (False, None)
        success = manager.enable_monitor_mode()
        if success:
            log.info(f"Monitor mode active on Linux: {manager.interface}")
            return (True, manager)
        else:
            log.error("Failed to enable monitor mode on Linux")
            return (False, None)

    # Default: Windows path
    chip_manager = WindowsChipMonitorManager(interface)

    if not chip_manager.monitor_manager.check_supported():
        log.info(f"Interface '{interface}' does not support monitor mode")
        return (False, None)

    success, config = chip_manager.enable_with_chip_config()
    if success:
        log.info(f"Monitor mode active. Config: {config}")
        return (True, chip_manager)
    else:
        log.error("Failed to enable monitor mode")
        return (False, None)


def teardown_monitor_mode(manager) -> bool:
    """Tear down monitor mode and restore normal operation.

    Args:
        manager: Any object with a disable_monitor_mode() or disable() method.

    Returns:
        True if teardown was successful, False otherwise.
    """
    if manager is None:
        return False
    if hasattr(manager, 'disable_monitor_mode'):
        return manager.disable_monitor_mode()
    if hasattr(manager, 'disable'):
        return manager.disable()
    return False


def check_npcap_monitor_support() -> bool:
    """Check if Npcap is installed and supports monitor mode."""
    possible_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
    ]
    for path in possible_paths:
        if os.path.exists(path):
            log.info(f"Npcap found at: {path}")
            return True
    log.warning("Npcap not installed - monitor mode not available")
    return False


def get_available_interfaces() -> List[Dict[str, str]]:
    """Get a list of available wireless interfaces on Windows.

    Returns:
        List of dicts with interface name, state, and description.
    """
    interfaces: List[Dict[str, str]] = []

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            log.error("Failed to enumerate wireless interfaces")
            return interfaces

        output = result.stdout
        current: Dict[str, str] = {}

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Name"):
                if current:
                    interfaces.append(current)
                current = {}
                name_match = re.match(r"Name\s*:\s*(.+)", line)
                if name_match:
                    current["name"] = name_match.group(1).strip()
            elif line.startswith("Description"):
                desc_match = re.match(r"Description\s*:\s*(.+)", line)
                if desc_match:
                    current["description"] = desc_match.group(1).strip()
            elif line.startswith("State"):
                state_match = re.match(r"State\s*:\s*(.+)", line)
                if state_match:
                    current["state"] = state_match.group(1).strip()

        if current:
            interfaces.append(current)

    except (subprocess.TimeoutExpired, OSError) as e:
        log.error(f"Error enumerating interfaces: {e}")

    log.info(f"Found {len(interfaces)} wireless interface(s)")
    return interfaces
