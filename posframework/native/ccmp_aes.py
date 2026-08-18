"""
posframework.native.ccmp_aes - ctypes wrapper for libccmp_aes.so

Provides CCMP (AES-CCM) acceleration:
- AES-128 block encryption
- CCMP encrypt (AES-CCM with M=8, L=2)
- CCMP decrypt with MIC verification
- Nonce construction from 802.11 frame fields
- AAD construction from MAC header

Used by posframework.ccmp for data frame encryption/decryption.
Falls back to Python implementations if native library is not compiled.
"""

import ctypes
import struct
from ctypes import c_int, c_uint8, c_size_t, POINTER
from typing import Optional, Tuple

from posframework.config import log
from posframework.native import get_lib

# --- Constants ---
CCMP_TK_LEN = 16
CCMP_MIC_LEN = 8
CCMP_PN_LEN = 6
CCMP_NONCE_LEN = 13
CCMP_AAD_MAX_LEN = 30
CCMP_HDR_LEN = 8
AES_BLOCK_SIZE = 16

# --- Native Library Setup ---

_lib = get_lib("libccmp_aes")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    _lib.aes128_encrypt_block.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8),
    ]
    _lib.aes128_encrypt_block.restype = c_int

    _lib.ccmp_encrypt.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), POINTER(c_uint8),
    ]
    _lib.ccmp_encrypt.restype = c_int

    _lib.ccmp_decrypt.argtypes = [
        POINTER(c_uint8), POINTER(c_uint8),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), POINTER(c_uint8),
    ]
    _lib.ccmp_decrypt.restype = c_int

    _lib.ccmp_build_nonce.argtypes = [
        c_uint8, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8),
    ]
    _lib.ccmp_build_nonce.restype = c_int

    _lib.ccmp_build_aad.argtypes = [
        POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_size_t),
    ]
    _lib.ccmp_build_aad.restype = c_int

    log.debug("ccmp_aes: using native C implementation")
else:
    log.warning("ccmp_aes: libccmp_aes.so not available, using Python fallback")


# --- Public API ---

def aes128_encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 encrypt a single 16-byte block.

    Args:
        key: 16-byte AES key
        plaintext: 16-byte input block

    Returns:
        16-byte ciphertext block.
    """
    if len(key) != 16 or len(plaintext) != 16:
        raise ValueError("Key and plaintext must both be 16 bytes")

    if _USE_NATIVE:
        key_arr = (c_uint8 * 16)(*key)
        in_arr = (c_uint8 * 16)(*plaintext)
        out_arr = (c_uint8 * 16)()

        result = _lib.aes128_encrypt_block(key_arr, in_arr, out_arr)
        if result == 0:
            return bytes(out_arr)

    return _py_aes128_encrypt(key, plaintext)


def ccmp_encrypt(tk: bytes, nonce: bytes, aad: bytes,
                 plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    CCMP encrypt (AES-CCM) a plaintext payload.

    Args:
        tk: 16-byte Temporal Key
        nonce: 13-byte nonce
        aad: Additional Authenticated Data
        plaintext: Data to encrypt

    Returns:
        Tuple of (ciphertext, 8-byte MIC).
    """
    if len(tk) != CCMP_TK_LEN:
        raise ValueError(f"TK must be {CCMP_TK_LEN} bytes")
    if len(nonce) != CCMP_NONCE_LEN:
        raise ValueError(f"Nonce must be {CCMP_NONCE_LEN} bytes")

    if _USE_NATIVE:
        tk_arr = (c_uint8 * CCMP_TK_LEN)(*tk)
        nonce_arr = (c_uint8 * CCMP_NONCE_LEN)(*nonce)
        aad_arr = (c_uint8 * len(aad))(*aad) if aad else (c_uint8 * 0)()
        plain_arr = (c_uint8 * len(plaintext))(*plaintext) if plaintext else (c_uint8 * 0)()
        cipher_out = (c_uint8 * len(plaintext))() if plaintext else (c_uint8 * 0)()
        mic_out = (c_uint8 * CCMP_MIC_LEN)()

        result = _lib.ccmp_encrypt(
            tk_arr, nonce_arr, aad_arr, len(aad),
            plain_arr, len(plaintext), cipher_out, mic_out
        )
        if result == 0:
            return bytes(cipher_out), bytes(mic_out)
        log.warning("ccmp_aes: native encrypt failed, using fallback")

    return _py_ccmp_encrypt(tk, nonce, aad, plaintext)


def ccmp_decrypt(tk: bytes, nonce: bytes, aad: bytes,
                 ciphertext: bytes, mic: bytes) -> Optional[bytes]:
    """
    CCMP decrypt (AES-CCM) and verify MIC.

    Args:
        tk: 16-byte Temporal Key
        nonce: 13-byte nonce
        aad: Additional Authenticated Data
        ciphertext: Encrypted data (without MIC)
        mic: 8-byte MIC to verify

    Returns:
        Decrypted plaintext if MIC is valid, None if MIC fails.
    """
    if len(tk) != CCMP_TK_LEN:
        raise ValueError(f"TK must be {CCMP_TK_LEN} bytes")
    if len(nonce) != CCMP_NONCE_LEN:
        raise ValueError(f"Nonce must be {CCMP_NONCE_LEN} bytes")
    if len(mic) != CCMP_MIC_LEN:
        raise ValueError(f"MIC must be {CCMP_MIC_LEN} bytes")

    if _USE_NATIVE:
        tk_arr = (c_uint8 * CCMP_TK_LEN)(*tk)
        nonce_arr = (c_uint8 * CCMP_NONCE_LEN)(*nonce)
        aad_arr = (c_uint8 * len(aad))(*aad) if aad else (c_uint8 * 0)()
        cipher_arr = (c_uint8 * len(ciphertext))(*ciphertext) if ciphertext else (c_uint8 * 0)()
        mic_arr = (c_uint8 * CCMP_MIC_LEN)(*mic)
        plain_out = (c_uint8 * len(ciphertext))() if ciphertext else (c_uint8 * 0)()

        result = _lib.ccmp_decrypt(
            tk_arr, nonce_arr, aad_arr, len(aad),
            cipher_arr, len(ciphertext), mic_arr, plain_out
        )
        if result == 0:
            return bytes(plain_out)
        elif result == -1:
            return None  # MIC failure
        # result == -2 means error, fall through to Python

    return _py_ccmp_decrypt(tk, nonce, aad, ciphertext, mic)


def build_nonce(priority: int, addr2: bytes, pn: bytes) -> bytes:
    """
    Construct CCMP nonce from 802.11 frame fields.

    Args:
        priority: QoS priority (TID), 0 for non-QoS
        addr2: 6-byte transmitter address
        pn: 6-byte Packet Number (big-endian)

    Returns:
        13-byte nonce.
    """
    if len(addr2) != 6:
        raise ValueError("addr2 must be 6 bytes")
    if len(pn) != CCMP_PN_LEN:
        raise ValueError(f"PN must be {CCMP_PN_LEN} bytes")

    if _USE_NATIVE:
        addr2_arr = (c_uint8 * 6)(*addr2)
        pn_arr = (c_uint8 * CCMP_PN_LEN)(*pn)
        nonce_out = (c_uint8 * CCMP_NONCE_LEN)()

        result = _lib.ccmp_build_nonce(c_uint8(priority & 0xFF),
                                       addr2_arr, pn_arr, nonce_out)
        if result == 0:
            return bytes(nonce_out)

    # Python fallback
    return bytes([priority & 0xFF]) + addr2 + pn


def build_aad(mac_header: bytes) -> bytes:
    """
    Construct AAD from 802.11 MAC header.

    Masks mutable fields and constructs AAD per IEEE 802.11-2020.

    Args:
        mac_header: 802.11 MAC header (minimum 24 bytes)

    Returns:
        AAD bytes (22-30 bytes depending on frame type).
    """
    if len(mac_header) < 24:
        raise ValueError("MAC header must be at least 24 bytes")

    if _USE_NATIVE:
        hdr_arr = (c_uint8 * len(mac_header))(*mac_header)
        aad_out = (c_uint8 * CCMP_AAD_MAX_LEN)()
        aad_len = c_size_t(0)

        result = _lib.ccmp_build_aad(hdr_arr, len(mac_header),
                                     aad_out, ctypes.byref(aad_len))
        if result == 0:
            return bytes(aad_out[:aad_len.value])

    return _py_build_aad(mac_header)


# --- Python Fallback Implementations ---

# AES S-box
_AES_SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

_AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _py_xtime(x: int) -> int:
    return ((x << 1) ^ (0x1B if (x & 0x80) else 0)) & 0xFF


def _py_aes_key_expand(key: bytes) -> bytearray:
    """AES-128 key expansion to 176 bytes (11 round keys)."""
    rk = bytearray(176)
    rk[:16] = key

    for i in range(4, 44):
        temp = list(rk[(i-1)*4:i*4])
        if i % 4 == 0:
            # RotWord + SubWord + Rcon
            t = temp[0]
            temp[0] = _AES_SBOX[temp[1]] ^ _AES_RCON[i // 4]
            temp[1] = _AES_SBOX[temp[2]]
            temp[2] = _AES_SBOX[temp[3]]
            temp[3] = _AES_SBOX[t]
        for j in range(4):
            rk[i*4+j] = rk[(i-4)*4+j] ^ temp[j]

    return rk


def _py_aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Pure Python AES-128 block encryption."""
    rk = _py_aes_key_expand(key)
    state = bytearray(plaintext)

    # Initial AddRoundKey
    for i in range(16):
        state[i] ^= rk[i]

    for rnd in range(1, 11):
        # SubBytes
        for i in range(16):
            state[i] = _AES_SBOX[state[i]]

        # ShiftRows
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[10] = state[10], state[2]
        state[6], state[14] = state[14], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

        # MixColumns (skip in last round)
        if rnd < 10:
            for c in range(4):
                ci = c * 4
                a0, a1, a2, a3 = state[ci], state[ci+1], state[ci+2], state[ci+3]
                t = a0 ^ a1 ^ a2 ^ a3
                state[ci] = a0 ^ _py_xtime(a0 ^ a1) ^ t
                state[ci+1] = a1 ^ _py_xtime(a1 ^ a2) ^ t
                state[ci+2] = a2 ^ _py_xtime(a2 ^ a3) ^ t
                state[ci+3] = a3 ^ _py_xtime(a3 ^ a0) ^ t

        # AddRoundKey
        for i in range(16):
            state[i] ^= rk[rnd * 16 + i]

    return bytes(state)


def _py_ccm_format_b0(nonce: bytes, plain_len: int, aad_len: int) -> bytes:
    """Format B0 block for CBC-MAC."""
    flags = 0
    if aad_len > 0:
        flags |= 0x40
    flags |= 3 << 3  # M' = (8-2)/2 = 3
    flags |= 1       # L' = 2-1 = 1
    return bytes([flags]) + nonce + struct.pack(">H", plain_len)


def _py_ccm_format_ctr(nonce: bytes, counter: int) -> bytes:
    """Format counter block."""
    return bytes([1]) + nonce + struct.pack(">H", counter)  # L'=1


def _py_ccm_cbc_mac(key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
    """Compute CBC-MAC for CCM."""
    rk = _py_aes_key_expand(key)

    # Process B0
    b0 = _py_ccm_format_b0(nonce, len(data), len(aad))
    mac = bytearray(_py_aes128_encrypt(key, b0))

    # Process AAD
    if aad:
        block = bytearray(16)
        # Length encoding (2 bytes for len < 0xFF00)
        block[0] = (len(aad) >> 8) & 0xFF
        block[1] = len(aad) & 0xFF
        first_chunk = min(len(aad), 14)
        block[2:2+first_chunk] = aad[:first_chunk]
        aad_offset = first_chunk

        for i in range(16):
            block[i] ^= mac[i]
        mac = bytearray(_py_aes128_encrypt(key, bytes(block)))

        while aad_offset < len(aad):
            block = bytearray(16)
            chunk = min(len(aad) - aad_offset, 16)
            block[:chunk] = aad[aad_offset:aad_offset+chunk]
            aad_offset += chunk
            for i in range(16):
                block[i] ^= mac[i]
            mac = bytearray(_py_aes128_encrypt(key, bytes(block)))

    # Process data
    offset = 0
    while offset < len(data):
        block = bytearray(16)
        chunk = min(len(data) - offset, 16)
        block[:chunk] = data[offset:offset+chunk]
        offset += chunk
        for i in range(16):
            block[i] ^= mac[i]
        mac = bytearray(_py_aes128_encrypt(key, bytes(block)))

    return bytes(mac)


def _py_ccmp_encrypt(tk: bytes, nonce: bytes, aad: bytes,
                     plaintext: bytes) -> Tuple[bytes, bytes]:
    """Python fallback for CCMP encryption."""
    # CBC-MAC over plaintext
    full_tag = _py_ccm_cbc_mac(tk, nonce, aad, plaintext)

    # Encrypt tag with counter 0
    a0 = _py_ccm_format_ctr(nonce, 0)
    s0 = _py_aes128_encrypt(tk, a0)
    mic = bytes(full_tag[i] ^ s0[i] for i in range(8))

    # Encrypt plaintext with counter 1, 2, ...
    ciphertext = bytearray()
    offset = 0
    counter = 1
    while offset < len(plaintext):
        ai = _py_ccm_format_ctr(nonce, counter)
        si = _py_aes128_encrypt(tk, ai)
        chunk = min(len(plaintext) - offset, 16)
        for i in range(chunk):
            ciphertext.append(plaintext[offset + i] ^ si[i])
        offset += chunk
        counter += 1

    return bytes(ciphertext), mic


def _py_ccmp_decrypt(tk: bytes, nonce: bytes, aad: bytes,
                     ciphertext: bytes, mic: bytes) -> Optional[bytes]:
    """Python fallback for CCMP decryption."""
    # Decrypt ciphertext
    plaintext = bytearray()
    offset = 0
    counter = 1
    while offset < len(ciphertext):
        ai = _py_ccm_format_ctr(nonce, counter)
        si = _py_aes128_encrypt(tk, ai)
        chunk = min(len(ciphertext) - offset, 16)
        for i in range(chunk):
            plaintext.append(ciphertext[offset + i] ^ si[i])
        offset += chunk
        counter += 1

    # Verify MIC
    full_tag = _py_ccm_cbc_mac(tk, nonce, aad, bytes(plaintext))
    a0 = _py_ccm_format_ctr(nonce, 0)
    s0 = _py_aes128_encrypt(tk, a0)

    diff = 0
    for i in range(8):
        diff |= (full_tag[i] ^ s0[i]) ^ mic[i]

    if diff != 0:
        return None

    return bytes(plaintext)


def _py_build_aad(mac_header: bytes) -> bytes:
    """Python fallback for AAD construction."""
    fc = mac_header[0] | (mac_header[1] << 8)
    is_qos = (len(mac_header) >= 26) and ((fc & 0x0080) != 0)

    fc0_masked = mac_header[0] & 0x8F
    fc1_masked = mac_header[1] & 0xC7

    aad = bytearray()
    aad.append(fc0_masked)
    aad.append(fc1_masked)
    aad.extend(mac_header[4:10])   # A1
    aad.extend(mac_header[10:16])  # A2
    aad.extend(mac_header[16:22])  # A3
    aad.append(mac_header[22] & 0x0F)  # SC fragment only
    aad.append(0x00)

    if is_qos and len(mac_header) >= 26:
        aad.append(mac_header[24] & 0x0F)  # TID
        aad.append(0x00)

    return bytes(aad)
