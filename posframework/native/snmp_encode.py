"""
posframework.native.snmp_encode - ctypes wrapper for libsnmp_encode.so

Provides fast BER/ASN.1 SNMP GetRequest encoding for printer
reconnaissance. Falls back to pure Python struct-based encoding
if the native library is not compiled.

Used by printer_recon.py for querying printer metadata via SNMP v1/v2c.
"""

import ctypes
import struct
from ctypes import c_int, c_uint8, c_uint32, c_size_t, c_char_p, POINTER
from typing import List, Optional

from posframework.config import log
from posframework.native import get_lib

# --- Native Library Setup ---

_lib = get_lib("libsnmp_encode")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # size_t snmp_encode_get(uint8_t *buf, size_t buf_size,
    #                        const char *community, const char *oid_str,
    #                        int request_id, int version)
    _lib.snmp_encode_get.argtypes = [
        POINTER(c_uint8), c_size_t,
        c_char_p, c_char_p,
        c_int, c_int,
    ]
    _lib.snmp_encode_get.restype = c_size_t

    # size_t snmp_encode_get_multi(uint8_t *buf, size_t buf_size,
    #                              const char *community,
    #                              const char **oid_strs, int oid_count,
    #                              int request_id, int version)
    _lib.snmp_encode_get_multi.argtypes = [
        POINTER(c_uint8), c_size_t,
        c_char_p,
        POINTER(c_char_p), c_int,
        c_int, c_int,
    ]
    _lib.snmp_encode_get_multi.restype = c_size_t

    # size_t snmp_encode_getnext(uint8_t *buf, size_t buf_size,
    #                            const char *community, const char *oid_str,
    #                            int request_id, int version)
    _lib.snmp_encode_getnext.argtypes = [
        POINTER(c_uint8), c_size_t,
        c_char_p, c_char_p,
        c_int, c_int,
    ]
    _lib.snmp_encode_getnext.restype = c_size_t

    # int snmp_parse_oid(const char *oid_str, uint32_t *components, int max_components)
    _lib.snmp_parse_oid.argtypes = [c_char_p, POINTER(c_uint32), c_int]
    _lib.snmp_parse_oid.restype = c_int

    log.debug("snmp_encode: using native C implementation")
else:
    log.warning("snmp_encode: libsnmp_encode.so not available, using Python fallback")


# --- SNMP Version Constants ---

SNMP_VERSION_1 = 0
SNMP_VERSION_2C = 1


# --- Public API ---

def encode_get(community: str, oid: str, request_id: int = 1,
               version: int = SNMP_VERSION_2C) -> bytes:
    """
    Encode an SNMP GetRequest PDU for a single OID.

    Args:
        community: Community string (e.g., "public")
        oid: OID in dotted notation (e.g., "1.3.6.1.2.1.1.1.0")
        request_id: Request ID for matching responses
        version: SNMP version (0=v1, 1=v2c)

    Returns:
        Encoded SNMP packet bytes ready to send via UDP port 161.
    """
    if _USE_NATIVE:
        buf = (c_uint8 * 512)()
        comm_bytes = community.encode("utf-8")
        oid_bytes = oid.encode("utf-8")

        pkt_len = _lib.snmp_encode_get(
            buf, 512, comm_bytes, oid_bytes, request_id, version
        )
        if pkt_len == 0:
            log.warning(f"snmp_encode: native encode_get failed for OID '{oid}'")
            return _fallback_encode_get(community, oid, request_id, version)
        return bytes(buf[:pkt_len])
    else:
        return _fallback_encode_get(community, oid, request_id, version)


def encode_get_multi(community: str, oids: List[str], request_id: int = 1,
                     version: int = SNMP_VERSION_2C) -> bytes:
    """
    Encode an SNMP GetRequest PDU for multiple OIDs.

    Args:
        community: Community string
        oids: List of OID strings in dotted notation
        request_id: Request ID
        version: SNMP version

    Returns:
        Encoded SNMP packet bytes.
    """
    if not oids:
        return b""

    if _USE_NATIVE:
        buf = (c_uint8 * 512)()
        comm_bytes = community.encode("utf-8")

        oid_count = len(oids)
        oid_arr_type = c_char_p * oid_count
        oid_arr = oid_arr_type(*(o.encode("utf-8") for o in oids))

        pkt_len = _lib.snmp_encode_get_multi(
            buf, 512, comm_bytes, oid_arr, oid_count, request_id, version
        )
        if pkt_len == 0:
            log.warning(f"snmp_encode: native encode_get_multi failed")
            return _fallback_encode_get(community, oids[0], request_id, version)
        return bytes(buf[:pkt_len])
    else:
        # Fallback: encode first OID only (simplified)
        return _fallback_encode_get(community, oids[0], request_id, version)


def encode_getnext(community: str, oid: str, request_id: int = 1,
                   version: int = SNMP_VERSION_2C) -> bytes:
    """
    Encode an SNMP GetNextRequest PDU for a single OID.

    Used for SNMP table walking/enumeration.

    Args:
        community: Community string
        oid: OID in dotted notation
        request_id: Request ID
        version: SNMP version

    Returns:
        Encoded SNMP packet bytes.
    """
    if _USE_NATIVE:
        buf = (c_uint8 * 512)()
        comm_bytes = community.encode("utf-8")
        oid_bytes = oid.encode("utf-8")

        pkt_len = _lib.snmp_encode_getnext(
            buf, 512, comm_bytes, oid_bytes, request_id, version
        )
        if pkt_len == 0:
            log.warning(f"snmp_encode: native encode_getnext failed for OID '{oid}'")
            return _fallback_encode_getnext(community, oid, request_id, version)
        return bytes(buf[:pkt_len])
    else:
        return _fallback_encode_getnext(community, oid, request_id, version)


# --- Fallback (Pure Python) Implementations ---

def _ber_encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _ber_encode_integer(value: int) -> bytes:
    """Encode a BER INTEGER."""
    if value == 0:
        int_bytes = b"\x00"
    elif value > 0:
        int_bytes = value.to_bytes((value.bit_length() + 8) // 8, 'big')
    else:
        # Negative
        length = (value.bit_length() + 9) // 8
        int_bytes = value.to_bytes(length, 'big', signed=True)
    return b"\x02" + _ber_encode_length(len(int_bytes)) + int_bytes


def _ber_encode_octet_string(data: bytes) -> bytes:
    """Encode a BER OCTET STRING."""
    return b"\x04" + _ber_encode_length(len(data)) + data


def _ber_encode_null() -> bytes:
    """Encode BER NULL."""
    return b"\x05\x00"


def _ber_encode_oid(oid_str: str) -> bytes:
    """Encode an OID string to BER format."""
    parts = oid_str.strip(".").split(".")
    components = [int(p) for p in parts]

    if len(components) < 2:
        return b""

    # First two components encoded as first*40 + second
    oid_bytes = bytearray([components[0] * 40 + components[1]])

    for comp in components[2:]:
        if comp == 0:
            oid_bytes.append(0)
        else:
            # Base-128 encoding
            groups = []
            val = comp
            while val > 0:
                groups.append(val & 0x7F)
                val >>= 7
            groups.reverse()
            for i, g in enumerate(groups):
                if i < len(groups) - 1:
                    oid_bytes.append(g | 0x80)
                else:
                    oid_bytes.append(g)

    return b"\x06" + _ber_encode_length(len(oid_bytes)) + bytes(oid_bytes)


def _ber_encode_sequence(data: bytes) -> bytes:
    """Wrap data in a BER SEQUENCE."""
    return b"\x30" + _ber_encode_length(len(data)) + data


def _fallback_encode_get(community: str, oid: str, request_id: int, version: int) -> bytes:
    """Build SNMP GetRequest using pure Python BER encoding."""
    # Variable binding: SEQUENCE { OID, NULL }
    varbind = _ber_encode_oid(oid) + _ber_encode_null()
    varbind_seq = _ber_encode_sequence(varbind)
    varbind_list = _ber_encode_sequence(varbind_seq)

    # PDU body: request-id + error-status + error-index + varbind-list
    pdu_body = (
        _ber_encode_integer(request_id)
        + _ber_encode_integer(0)  # error-status
        + _ber_encode_integer(0)  # error-index
        + varbind_list
    )

    # GetRequest PDU (tag 0xA0)
    pdu = b"\xa0" + _ber_encode_length(len(pdu_body)) + pdu_body

    # SNMP message: version + community + PDU
    msg_body = (
        _ber_encode_integer(version)
        + _ber_encode_octet_string(community.encode("utf-8"))
        + pdu
    )

    # Outer SEQUENCE
    return _ber_encode_sequence(msg_body)


def _fallback_encode_getnext(community: str, oid: str, request_id: int, version: int) -> bytes:
    """Build SNMP GetNextRequest using pure Python BER encoding."""
    # Variable binding: SEQUENCE { OID, NULL }
    varbind = _ber_encode_oid(oid) + _ber_encode_null()
    varbind_seq = _ber_encode_sequence(varbind)
    varbind_list = _ber_encode_sequence(varbind_seq)

    # PDU body
    pdu_body = (
        _ber_encode_integer(request_id)
        + _ber_encode_integer(0)
        + _ber_encode_integer(0)
        + varbind_list
    )

    # GetNextRequest PDU (tag 0xA1)
    pdu = b"\xa1" + _ber_encode_length(len(pdu_body)) + pdu_body

    # SNMP message
    msg_body = (
        _ber_encode_integer(version)
        + _ber_encode_octet_string(community.encode("utf-8"))
        + pdu
    )

    return _ber_encode_sequence(msg_body)
