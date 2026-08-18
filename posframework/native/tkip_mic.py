"""
posframework.native.tkip_mic - ctypes wrapper for libtkip_mic.so

Provides TKIP acceleration:
- Michael MIC computation and verification
- TKIP Phase 1 and Phase 2 key mixing
- TKIP IV/Extended IV construction

Used by posframework.tkip for per-packet TKIP operations.
Falls back to Python implementations if native library is not compiled.
"""

import ctypes
import struct
from ctypes import c_int, c_uint8, c_uint16, c_uint32, c_uint64, c_size_t, POINTER
from typing import Optional, Tuple

from posframework.config import log
from posframework.native import get_lib

# --- Constants ---
TKIP_MIC_KEY_LEN = 8
TKIP_TK_LEN = 16
TKIP_MIC_LEN = 8
TKIP_PHASE1_OUT_LEN = 10
TKIP_RC4_KEY_LEN = 16
TKIP_IV_LEN = 8

# --- Native Library Setup ---

_lib = get_lib("libtkip_mic")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    _lib.michael_mic.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8),
        c_uint8, POINTER(c_uint8), c_size_t, POINTER(c_uint8),
    ]
    _lib.michael_mic.restype = c_int

    _lib.michael_mic_verify.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8),
        c_uint8, POINTER(c_uint8), c_size_t, POINTER(c_uint8),
    ]
    _lib.michael_mic_verify.restype = c_int

    _lib.tkip_phase1.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8), c_uint32, POINTER(c_uint8),
    ]
    _lib.tkip_phase1.restype = c_int

    _lib.tkip_phase2.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8), c_uint16, POINTER(c_uint8),
    ]
    _lib.tkip_phase2.restype = c_int

    _lib.tkip_build_iv.argtypes = [c_uint64, c_uint8, POINTER(c_uint8)]
    _lib.tkip_build_iv.restype = c_int

    log.debug("tkip_mic: using native C implementation")
else:
    log.warning("tkip_mic: libtkip_mic.so not available, using Python fallback")


# --- Public API ---

def michael_mic_compute(key: bytes, da: bytes, sa: bytes,
                        priority: int, data: bytes) -> bytes:
    """
    Compute Michael MIC over an MSDU.

    Args:
        key: 8-byte Michael MIC key
        da: 6-byte destination address
        sa: 6-byte source address
        priority: QoS priority (TID)
        data: MSDU payload

    Returns:
        8-byte Michael MIC.
    """
    if len(key) != TKIP_MIC_KEY_LEN:
        raise ValueError(f"MIC key must be {TKIP_MIC_KEY_LEN} bytes")
    if len(da) != 6 or len(sa) != 6:
        raise ValueError("MAC addresses must be 6 bytes")

    if _USE_NATIVE:
        key_arr = (c_uint8 * TKIP_MIC_KEY_LEN)(*key)
        da_arr = (c_uint8 * 6)(*da)
        sa_arr = (c_uint8 * 6)(*sa)
        data_arr = (c_uint8 * len(data))(*data) if data else (c_uint8 * 0)()
        mic_out = (c_uint8 * TKIP_MIC_LEN)()

        result = _lib.michael_mic(key_arr, da_arr, sa_arr,
                                  c_uint8(priority & 0xFF),
                                  data_arr, len(data), mic_out)
        if result == 0:
            return bytes(mic_out)
        log.warning("tkip_mic: native michael_mic failed, using fallback")

    return _py_michael_mic(key, da, sa, priority, data)


def michael_mic_verify(key: bytes, da: bytes, sa: bytes,
                       priority: int, data: bytes, expected: bytes) -> bool:
    """
    Verify Michael MIC on received data.

    Args:
        key: 8-byte Michael MIC key
        da: 6-byte destination address
        sa: 6-byte source address
        priority: QoS priority
        data: MSDU payload (without MIC)
        expected: 8-byte expected MIC

    Returns:
        True if MIC is valid, False otherwise.
    """
    if len(expected) != TKIP_MIC_LEN:
        raise ValueError(f"Expected MIC must be {TKIP_MIC_LEN} bytes")

    if _USE_NATIVE:
        key_arr = (c_uint8 * TKIP_MIC_KEY_LEN)(*key)
        da_arr = (c_uint8 * 6)(*da)
        sa_arr = (c_uint8 * 6)(*sa)
        data_arr = (c_uint8 * len(data))(*data) if data else (c_uint8 * 0)()
        exp_arr = (c_uint8 * TKIP_MIC_LEN)(*expected)

        result = _lib.michael_mic_verify(key_arr, da_arr, sa_arr,
                                         c_uint8(priority & 0xFF),
                                         data_arr, len(data), exp_arr)
        if result >= 0:
            return result == 1

    computed = _py_michael_mic(key, da, sa, priority, data)
    return computed == expected


def phase1_key_mixing(tk: bytes, ta: bytes, tsc_hi: int) -> bytes:
    """
    TKIP Phase 1 key mixing.

    Produces intermediate key (TTAK) from TK, TA, and upper TSC.
    Cached per-TA; only changes every 65536 packets.

    Args:
        tk: 16-byte Temporal Key
        ta: 6-byte Transmitter Address
        tsc_hi: Upper 32 bits of TSC (bits 16-47)

    Returns:
        10-byte Phase 1 key (TTAK).
    """
    if len(tk) != TKIP_TK_LEN:
        raise ValueError(f"TK must be {TKIP_TK_LEN} bytes")
    if len(ta) != 6:
        raise ValueError("TA must be 6 bytes")

    if _USE_NATIVE:
        tk_arr = (c_uint8 * TKIP_TK_LEN)(*tk)
        ta_arr = (c_uint8 * 6)(*ta)
        p1k_out = (c_uint8 * TKIP_PHASE1_OUT_LEN)()

        result = _lib.tkip_phase1(tk_arr, ta_arr, c_uint32(tsc_hi), p1k_out)
        if result == 0:
            return bytes(p1k_out)

    return _py_phase1(tk, ta, tsc_hi)


def phase2_key_mixing(tk: bytes, p1k: bytes, tsc_lo: int) -> bytes:
    """
    TKIP Phase 2 key mixing.

    Produces per-packet RC4 key from Phase 1 output and lower TSC.

    Args:
        tk: 16-byte Temporal Key
        p1k: 10-byte Phase 1 key (TTAK)
        tsc_lo: Lower 16 bits of TSC

    Returns:
        16-byte RC4 key for WEP encapsulation.
    """
    if len(tk) != TKIP_TK_LEN:
        raise ValueError(f"TK must be {TKIP_TK_LEN} bytes")
    if len(p1k) != TKIP_PHASE1_OUT_LEN:
        raise ValueError(f"P1K must be {TKIP_PHASE1_OUT_LEN} bytes")

    if _USE_NATIVE:
        tk_arr = (c_uint8 * TKIP_TK_LEN)(*tk)
        p1k_arr = (c_uint8 * TKIP_PHASE1_OUT_LEN)(*p1k)
        rc4key = (c_uint8 * TKIP_RC4_KEY_LEN)()

        result = _lib.tkip_phase2(tk_arr, p1k_arr, c_uint16(tsc_lo & 0xFFFF), rc4key)
        if result == 0:
            return bytes(rc4key)

    return _py_phase2(tk, p1k, tsc_lo)


def build_iv(tsc: int, key_id: int = 0) -> bytes:
    """
    Build TKIP IV/Extended IV field from TSC.

    Args:
        tsc: 48-bit TKIP Sequence Counter
        key_id: Key ID (0-3)

    Returns:
        8-byte IV (4 IV + 4 Extended IV).
    """
    if _USE_NATIVE:
        iv_out = (c_uint8 * TKIP_IV_LEN)()
        result = _lib.tkip_build_iv(c_uint64(tsc), c_uint8(key_id & 0x03), iv_out)
        if result == 0:
            return bytes(iv_out)

    return _py_build_iv(tsc, key_id)


# --- Python Fallback Implementations ---

def _py_michael_block(l: int, r: int) -> Tuple[int, int]:
    """One Michael block operation."""
    mask = 0xFFFFFFFF
    l = (l ^ (((r << 17) | (r >> 15)) & mask)) & mask
    r = (r + l) & mask
    # xswap
    r_swapped = (((r & 0x00FF00FF) << 8) | ((r & 0xFF00FF00) >> 8)) & mask
    l = (l ^ r_swapped) & mask
    r = (r + l) & mask
    l = (l ^ (((r << 3) | (r >> 29)) & mask)) & mask
    r = (r + l) & mask
    l = (l ^ (((r >> 2) | (r << 30)) & mask)) & mask
    r = (r + l) & mask
    return l, r


def _py_michael_mic(key: bytes, da: bytes, sa: bytes,
                    priority: int, data: bytes) -> bytes:
    """Python fallback for Michael MIC computation."""
    l = struct.unpack_from("<I", key, 0)[0]
    r = struct.unpack_from("<I", key, 4)[0]

    # Build header: DA || SA || Priority || 0 || 0 || 0
    header = da + sa + bytes([priority, 0, 0, 0])

    # Process header (16 bytes = 4 words)
    for i in range(4):
        word = struct.unpack_from("<I", header, i * 4)[0]
        l ^= word
        l, r = _py_michael_block(l, r)

    # Process data + padding
    msg = data + b'\x5a' + b'\x00' * ((-len(data) - 1) % 4 + 4)
    for i in range(0, len(msg), 4):
        word = struct.unpack_from("<I", msg, i)[0]
        l ^= word
        l, r = _py_michael_block(l, r)

    return struct.pack("<II", l, r)


def _py_phase1(tk: bytes, ta: bytes, tsc_hi: int) -> bytes:
    """Python fallback for TKIP Phase 1 key mixing."""
    # Simplified phase 1 - produces 10-byte TTAK
    p1k = [
        tsc_hi & 0xFFFF,
        (tsc_hi >> 16) & 0xFFFF,
        (ta[1] << 8) | ta[0],
        (ta[3] << 8) | ta[2],
        (ta[5] << 8) | ta[4],
    ]

    for i in range(8):
        idx = i & 6
        p1k[0] = (p1k[0] + _py_tkip_s(p1k[4] ^ ((tk[1 + idx] << 8) | tk[0 + idx]))) & 0xFFFF
        p1k[1] = (p1k[1] + _py_tkip_s(p1k[0] ^ ((tk[5 + idx] << 8) | tk[4 + idx]))) & 0xFFFF
        p1k[2] = (p1k[2] + _py_tkip_s(p1k[1] ^ ((tk[9 + idx] << 8) | tk[8 + idx]))) & 0xFFFF
        p1k[3] = (p1k[3] + _py_tkip_s(p1k[2] ^ ((tk[13 + idx] << 8) | tk[12 + idx]))) & 0xFFFF
        p1k[4] = (p1k[4] + _py_tkip_s(p1k[3] ^ ((tk[1 + idx] << 8) | tk[0 + idx])) + i) & 0xFFFF

    result = b""
    for v in p1k:
        result += struct.pack("<H", v)
    return result


def _py_phase2(tk: bytes, p1k: bytes, tsc_lo: int) -> bytes:
    """Python fallback for TKIP Phase 2 key mixing."""
    ppk = list(struct.unpack("<5H", p1k))
    ppk.append((ppk[4] + tsc_lo) & 0xFFFF)

    ppk[0] = (ppk[0] + _py_tkip_s(ppk[5] ^ ((tk[1] << 8) | tk[0]))) & 0xFFFF
    ppk[1] = (ppk[1] + _py_tkip_s(ppk[0] ^ ((tk[3] << 8) | tk[2]))) & 0xFFFF
    ppk[2] = (ppk[2] + _py_tkip_s(ppk[1] ^ ((tk[5] << 8) | tk[4]))) & 0xFFFF
    ppk[3] = (ppk[3] + _py_tkip_s(ppk[2] ^ ((tk[7] << 8) | tk[6]))) & 0xFFFF
    ppk[4] = (ppk[4] + _py_tkip_s(ppk[3] ^ ((tk[9] << 8) | tk[8]))) & 0xFFFF
    ppk[5] = (ppk[5] + _py_tkip_s(ppk[4] ^ ((tk[11] << 8) | tk[10]))) & 0xFFFF

    rc4key = bytearray(16)
    rc4key[0] = (tsc_lo >> 8) & 0xFF
    rc4key[1] = ((tsc_lo >> 8) | 0x20) & 0x7F
    rc4key[2] = tsc_lo & 0xFF
    rc4key[3] = (ppk[5] >> 1) & 0xFF

    for i in range(6):
        rc4key[4 + i * 2] = ppk[i] & 0xFF
        rc4key[5 + i * 2] = (ppk[i] >> 8) & 0xFF

    return bytes(rc4key)


def _py_build_iv(tsc: int, key_id: int) -> bytes:
    """Python fallback for TKIP IV construction."""
    tsc0 = tsc & 0xFF
    tsc1 = (tsc >> 8) & 0xFF
    tsc2 = (tsc >> 16) & 0xFF
    tsc3 = (tsc >> 24) & 0xFF
    tsc4 = (tsc >> 32) & 0xFF
    tsc5 = (tsc >> 40) & 0xFF

    iv = bytearray(8)
    iv[0] = tsc1
    iv[1] = (tsc1 | 0x20) & 0x7F
    iv[2] = tsc0
    iv[3] = (key_id << 6) | 0x20
    iv[4] = tsc2
    iv[5] = tsc3
    iv[6] = tsc4
    iv[7] = tsc5

    return bytes(iv)


# S-box for Python fallback
_TKIP_SBOX = [
    0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
    0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
    0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
    0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
    0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
    0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
    0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
    0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
    0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
    0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
    0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
    0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
    0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
    0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
    0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
    0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
    0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
    0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
    0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
    0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
    0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
    0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
    0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
    0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
    0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
    0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
    0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
    0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
    0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
    0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
    0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
    0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
]


def _py_tkip_s(v: int) -> int:
    """TKIP S-box lookup."""
    lo = _TKIP_SBOX[v & 0xFF]
    hi = _TKIP_SBOX[(v >> 8) & 0xFF]
    return lo ^ ((hi << 8) | (hi >> 8)) & 0xFFFF
