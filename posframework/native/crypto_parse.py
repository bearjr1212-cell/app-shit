"""
posframework.native.crypto_parse - ctypes wrapper for libcrypto_parse.so

Provides fast C-accelerated RSN/WPA Information Element parsing.
Falls back to the Python implementation in posframework.crypto if
the native library is not compiled.

Returns the same dict format as posframework.crypto.parse_rsn_ie / parse_wpa_ie.
"""

import ctypes
from ctypes import c_int, c_uint8, c_uint16, c_size_t, c_char, POINTER, Structure
from typing import Dict, List

from posframework.config import log
from posframework.native import get_lib

# ─── ctypes Struct Definitions ─────────────────────────────────────────────────


class RsnInfo(Structure):
    """Mirrors rsn_info_t from crypto_parse.h"""
    _fields_ = [
        ("group_cipher", c_char * 32),
        ("pairwise_ciphers", (c_char * 32) * 4),
        ("pw_count", c_int),
        ("akm_suites", (c_char * 32) * 4),
        ("akm_count", c_int),
        ("capabilities", c_uint16),
    ]


class WpaInfo(Structure):
    """Mirrors wpa_info_t from crypto_parse.h"""
    _fields_ = [
        ("group_cipher", c_char * 32),
        ("pairwise_ciphers", (c_char * 32) * 4),
        ("pw_count", c_int),
        ("akm_suites", (c_char * 32) * 4),
        ("akm_count", c_int),
    ]


# ─── Native Library Setup ─────────────────────────────────────────────────────

_lib = get_lib("libcrypto_parse")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # int parse_rsn_ie(const uint8_t *data, size_t len, rsn_info_t *out)
    _lib.parse_rsn_ie.argtypes = [POINTER(c_uint8), c_size_t, POINTER(RsnInfo)]
    _lib.parse_rsn_ie.restype = c_int

    # int parse_wpa_ie(const uint8_t *data, size_t len, wpa_info_t *out)
    _lib.parse_wpa_ie.argtypes = [POINTER(c_uint8), c_size_t, POINTER(WpaInfo)]
    _lib.parse_wpa_ie.restype = c_int

    log.debug("crypto_parse: using native C implementation")
else:
    log.warning("crypto_parse: libcrypto_parse.so not available, using Python fallback")


# ─── Helper Functions ──────────────────────────────────────────────────────────

def _decode_str(buf: bytes) -> str:
    """Decode a null-terminated C string from a ctypes char buffer."""
    if isinstance(buf, bytes):
        return buf.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return ""


def _rsn_struct_to_dict(info: RsnInfo) -> Dict:
    """Convert RsnInfo ctypes struct to Python dict matching crypto.py format."""
    result = {
        "group_cipher": _decode_str(info.group_cipher) or None,
        "pairwise_ciphers": [],
        "akm_suites": [],
        "capabilities": int(info.capabilities),
    }

    for i in range(info.pw_count):
        cipher = _decode_str(bytes(info.pairwise_ciphers[i]))
        if cipher:
            result["pairwise_ciphers"].append(cipher)

    for i in range(info.akm_count):
        akm = _decode_str(bytes(info.akm_suites[i]))
        if akm:
            result["akm_suites"].append(akm)

    return result


def _wpa_struct_to_dict(info: WpaInfo) -> Dict:
    """Convert WpaInfo ctypes struct to Python dict matching crypto.py format."""
    result = {
        "group_cipher": _decode_str(info.group_cipher) or None,
        "pairwise_ciphers": [],
        "akm_suites": [],
    }

    for i in range(info.pw_count):
        cipher = _decode_str(bytes(info.pairwise_ciphers[i]))
        if cipher:
            result["pairwise_ciphers"].append(cipher)

    for i in range(info.akm_count):
        akm = _decode_str(bytes(info.akm_suites[i]))
        if akm:
            result["akm_suites"].append(akm)

    return result


# ─── Public API ────────────────────────────────────────────────────────────────

def parse_rsn_ie(data: bytes) -> dict:
    """
    Parse an RSN Information Element (tag 48) into its components.

    Args:
        data: IE body bytes (after tag id and length bytes)

    Returns:
        Dict with keys:
            - group_cipher: str or None
            - pairwise_ciphers: List[str]
            - akm_suites: List[str]
            - capabilities: int (RSN capabilities bitmask)
    """
    if not data:
        return {"group_cipher": None, "pairwise_ciphers": [], "akm_suites": [], "capabilities": 0}

    if _USE_NATIVE:
        info = RsnInfo()
        buf = (c_uint8 * len(data))(*data)
        result = _lib.parse_rsn_ie(buf, len(data), ctypes.byref(info))
        if result < 0:
            log.debug("crypto_parse: native parse_rsn_ie returned error, returning empty")
            return {"group_cipher": None, "pairwise_ciphers": [], "akm_suites": [], "capabilities": 0}
        return _rsn_struct_to_dict(info)
    else:
        # Fallback to Python implementation
        from posframework.crypto import parse_rsn_ie as _py_parse_rsn
        return _py_parse_rsn(data)


def parse_wpa_ie(data: bytes) -> dict:
    """
    Parse a WPA vendor-specific Information Element.

    Args:
        data: IE body bytes (starting at OUI: 00:50:f2:01)

    Returns:
        Dict with keys:
            - group_cipher: str or None
            - pairwise_ciphers: List[str]
            - akm_suites: List[str]
    """
    if not data:
        return {"group_cipher": None, "pairwise_ciphers": [], "akm_suites": []}

    if _USE_NATIVE:
        info = WpaInfo()
        buf = (c_uint8 * len(data))(*data)
        result = _lib.parse_wpa_ie(buf, len(data), ctypes.byref(info))
        if result < 0:
            log.debug("crypto_parse: native parse_wpa_ie returned error, returning empty")
            return {"group_cipher": None, "pairwise_ciphers": [], "akm_suites": []}
        return _wpa_struct_to_dict(info)
    else:
        # Fallback to Python implementation
        from posframework.crypto import parse_wpa_ie as _py_parse_wpa
        return _py_parse_wpa(data)
