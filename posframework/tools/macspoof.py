"""
MAC Address Spoofing
────────────────────
MAC randomization and vendor-specific spoofing using macchanger
and fallback to raw iw/ip commands.

Capabilities:
  - Full random MAC
  - Same-vendor random (preserves OUI)
  - Specific MAC assignment
  - Restore original MAC
  - Vendor-targeted spoofing (impersonate specific device types)
"""

import os
import re
import random
import subprocess
from typing import Optional, Tuple

from posframework.config import IS_LINUX, log
from posframework.tools import is_available, run_tool


# ─── Known POS/Payment Vendor OUIs for impersonation ──────────────────────────

VENDOR_OUIS = {
    "verifone": ["00:1C:12", "00:1F:C4", "70:5A:0F"],
    "ingenico": ["00:07:81", "00:21:F2", "D8:D3:85"],
    "ncr": ["00:03:47", "00:0E:4E", "00:16:52"],
    "epson": ["00:1B:11", "00:26:AB", "44:D2:44"],
    "zebra": ["00:A0:F8", "AC:3F:A4", "00:15:70"],
    "cisco": ["00:1A:A1", "00:22:55", "00:25:45"],
    "apple": ["AC:DE:48", "F0:18:98", "3C:22:FB"],
    "samsung": ["00:07:AB", "00:12:FB", "00:15:99"],
    "intel": ["00:02:B3", "00:03:47", "00:13:02"],
    "random_iot": ["B8:27:EB", "DC:A6:32", "E4:5F:01"],  # Raspberry Pi
}


class MACSpoofer:
    """
    MAC address manipulation for wireless interfaces.

    Usage:
        spoofer = MACSpoofer("wlan0")
        spoofer.randomize()                    # Full random MAC
        spoofer.set_vendor("verifone")          # Impersonate POS terminal
        spoofer.set_mac("AA:BB:CC:DD:EE:FF")   # Specific MAC
        spoofer.restore()                       # Restore original
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._original_mac: Optional[str] = None
        self._current_mac: Optional[str] = None
        self._use_macchanger = is_available("macchanger")

        # Store original MAC on init
        self._original_mac = self.get_current_mac()
        self._current_mac = self._original_mac

    def get_current_mac(self) -> Optional[str]:
        """Read the current MAC address of the interface."""
        try:
            if IS_LINUX:
                # Read from /sys (most reliable)
                sys_path = f"/sys/class/net/{self.interface}/address"
                if os.path.exists(sys_path):
                    with open(sys_path, "r") as f:
                        return f.read().strip().lower()

                # Fallback to ip link
                result = subprocess.run(
                    ["ip", "link", "show", self.interface],
                    capture_output=True, text=True, timeout=5
                )
                mac_match = re.search(
                    r"link/ether\s+([0-9a-f:]{17})", result.stdout
                )
                if mac_match:
                    return mac_match.group(1).lower()
        except Exception as e:
            log.debug(f"MAC read error: {e}")
        return None

    def randomize(self) -> Optional[str]:
        """
        Set a fully random MAC address.

        Returns:
            The new MAC address, or None on failure.
        """
        if self._use_macchanger:
            return self._macchanger_random()
        return self._manual_random()

    def randomize_same_vendor(self) -> Optional[str]:
        """
        Randomize MAC but keep the same OUI (vendor prefix).

        Returns:
            The new MAC address, or None on failure.
        """
        if self._use_macchanger:
            return self._macchanger_endonly()
        # Manual: keep first 3 bytes, randomize last 3
        current = self.get_current_mac()
        if not current:
            return None
        oui = current[:8]
        new_mac = oui + ":" + ":".join(
            f"{random.randint(0, 255):02x}" for _ in range(3)
        )
        return self.set_mac(new_mac)

    def set_vendor(self, vendor: str) -> Optional[str]:
        """
        Set MAC to impersonate a specific vendor type.

        Args:
            vendor: Vendor name from VENDOR_OUIS dict (e.g., 'verifone', 'cisco').

        Returns:
            The new MAC address, or None on failure.
        """
        ouis = VENDOR_OUIS.get(vendor.lower())
        if not ouis:
            log.warning(f"Unknown vendor: {vendor}. Available: {list(VENDOR_OUIS.keys())}")
            return None

        oui = random.choice(ouis)
        suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
        new_mac = f"{oui}:{suffix}"
        return self.set_mac(new_mac)

    def set_mac(self, mac: str) -> Optional[str]:
        """
        Set a specific MAC address on the interface.

        Args:
            mac: Target MAC address (e.g., 'AA:BB:CC:DD:EE:FF').

        Returns:
            The new MAC address (confirmed), or None on failure.
        """
        mac = mac.lower()

        # Validate format
        if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
            log.error(f"Invalid MAC format: {mac}")
            return None

        # Ensure locally administered bit is set (avoids conflicts)
        # Bit 1 of first octet = locally administered
        first_byte = int(mac[:2], 16)
        first_byte = (first_byte | 0x02) & 0xFE  # Set LA bit, clear multicast
        mac = f"{first_byte:02x}" + mac[2:]

        if self._use_macchanger:
            result = self._macchanger_set(mac)
        else:
            result = self._manual_set(mac)

        if result:
            self._current_mac = result
            log.info(f"MAC changed: {self.interface} → {result}")
        return result

    def restore(self) -> Optional[str]:
        """
        Restore the original MAC address.

        Returns:
            The restored MAC, or None on failure.
        """
        if not self._original_mac:
            log.warning("No original MAC stored")
            return None

        if self._use_macchanger:
            result = self._macchanger_restore()
        else:
            result = self._manual_set(self._original_mac)

        if result:
            self._current_mac = result
            log.info(f"MAC restored: {self.interface} → {result}")
        return result

    # ─── macchanger backend ───────────────────────────────────────────────────

    def _macchanger_random(self) -> Optional[str]:
        """Full random via macchanger -r."""
        self._bring_down()
        try:
            result = run_tool("macchanger", ["-r", self.interface], timeout=10)
            return self._parse_macchanger_output(result.stdout)
        except Exception as e:
            log.error(f"macchanger -r failed: {e}")
            return None
        finally:
            self._bring_up()

    def _macchanger_endonly(self) -> Optional[str]:
        """Same-vendor random via macchanger -e."""
        self._bring_down()
        try:
            result = run_tool("macchanger", ["-e", self.interface], timeout=10)
            return self._parse_macchanger_output(result.stdout)
        except Exception as e:
            log.error(f"macchanger -e failed: {e}")
            return None
        finally:
            self._bring_up()

    def _macchanger_set(self, mac: str) -> Optional[str]:
        """Specific MAC via macchanger -m."""
        self._bring_down()
        try:
            result = run_tool(
                "macchanger", ["-m", mac, self.interface], timeout=10
            )
            return self._parse_macchanger_output(result.stdout)
        except Exception as e:
            log.error(f"macchanger -m failed: {e}")
            return None
        finally:
            self._bring_up()

    def _macchanger_restore(self) -> Optional[str]:
        """Restore permanent MAC via macchanger -p."""
        self._bring_down()
        try:
            result = run_tool("macchanger", ["-p", self.interface], timeout=10)
            return self._parse_macchanger_output(result.stdout)
        except Exception as e:
            log.error(f"macchanger -p failed: {e}")
            return None
        finally:
            self._bring_up()

    def _parse_macchanger_output(self, output: str) -> Optional[str]:
        """Extract new MAC from macchanger output."""
        # Pattern: "New MAC:   xx:xx:xx:xx:xx:xx"
        match = re.search(r"New\s+MAC:\s+([0-9a-f:]{17})", output, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    # ─── Manual backend (ip/iw) ───────────────────────────────────────────────

    def _manual_random(self) -> Optional[str]:
        """Generate and set a random MAC using ip link."""
        # Random MAC with locally-administered bit set
        mac_bytes = [random.randint(0, 255) for _ in range(6)]
        mac_bytes[0] = (mac_bytes[0] | 0x02) & 0xFE  # LA + unicast
        mac = ":".join(f"{b:02x}" for b in mac_bytes)
        return self._manual_set(mac)

    def _manual_set(self, mac: str) -> Optional[str]:
        """Set MAC using ip link set."""
        self._bring_down()
        try:
            result = subprocess.run(
                ["ip", "link", "set", "dev", self.interface, "address", mac],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Verify
                actual = self.get_current_mac()
                if actual and actual == mac.lower():
                    return actual
                return mac.lower()  # Assume success
            else:
                log.error(f"ip link set address failed: {result.stderr}")
                return None
        except Exception as e:
            log.error(f"Manual MAC set failed: {e}")
            return None
        finally:
            self._bring_up()

    # ─── Interface up/down ────────────────────────────────────────────────────

    def _bring_down(self):
        """Bring interface down (required before MAC change)."""
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", self.interface, "down"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    def _bring_up(self):
        """Bring interface back up after MAC change."""
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", self.interface, "up"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
