/**
 * snmp_encode.c - Fast BER/ASN.1 SNMP encoding for printer reconnaissance
 *
 * Constructs SNMP v1/v2c GetRequest and GetNextRequest PDUs using
 * BER encoding. Replaces slow Python struct-based SNMP packet building
 * in printer_recon.py with optimized C encoding.
 *
 * No external dependencies (no net-snmp, no openssl).
 * Pure C11 with standard library only.
 *
 * Compile: gcc -std=c11 -shared -fPIC -o libsnmp_encode.so snmp_encode.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "snmp_encode.h"

/* ==================== ASN.1/BER Constants ==================== */

/* ASN.1 tag types */
#define ASN1_INTEGER        0x02
#define ASN1_OCTET_STRING   0x04
#define ASN1_NULL           0x05
#define ASN1_OID            0x06
#define ASN1_SEQUENCE       0x30

/* SNMP PDU types */
#define SNMP_GET_REQUEST    0xA0
#define SNMP_GETNEXT_REQUEST 0xA1
#define SNMP_GET_RESPONSE   0xA2

/* ==================== BER Encoding Helpers ==================== */

/**
 * Encode a BER length field.
 * Returns number of bytes written to buf.
 */
static size_t ber_encode_length(uint8_t *buf, size_t len)
{
    if (len < 128) {
        buf[0] = (uint8_t)len;
        return 1;
    } else if (len < 256) {
        buf[0] = 0x81;
        buf[1] = (uint8_t)len;
        return 2;
    } else {
        buf[0] = 0x82;
        buf[1] = (uint8_t)(len >> 8);
        buf[2] = (uint8_t)(len & 0xFF);
        return 3;
    }
}

/**
 * Calculate BER length field size for a given content length.
 */
static size_t ber_length_size(size_t len)
{
    if (len < 128) return 1;
    if (len < 256) return 2;
    return 3;
}

/**
 * Encode a BER INTEGER value.
 * Returns number of bytes written.
 */
static size_t ber_encode_integer(uint8_t *buf, int32_t value)
{
    size_t offset = 0;
    uint8_t int_bytes[4];
    int int_len = 0;

    /* Encode the integer value in big-endian minimal form */
    if (value == 0) {
        int_bytes[0] = 0;
        int_len = 1;
    } else {
        int32_t v = value;
        int temp_len = 0;
        uint8_t temp[4];

        /* Extract bytes in little-endian */
        if (v > 0) {
            while (v > 0) {
                temp[temp_len++] = (uint8_t)(v & 0xFF);
                v >>= 8;
            }
            /* Add leading zero if high bit set */
            if (temp[temp_len - 1] & 0x80) {
                temp[temp_len++] = 0;
            }
        } else {
            /* Negative integers */
            while (v < -1 || (temp_len == 0)) {
                temp[temp_len++] = (uint8_t)(v & 0xFF);
                v >>= 8;
                if (temp_len >= 4) break;
            }
            if (!(temp[temp_len - 1] & 0x80)) {
                temp[temp_len++] = 0xFF;
            }
        }

        /* Reverse to big-endian */
        for (int i = 0; i < temp_len; i++) {
            int_bytes[i] = temp[temp_len - 1 - i];
        }
        int_len = temp_len;
    }

    /* Tag */
    buf[offset++] = ASN1_INTEGER;
    /* Length */
    offset += ber_encode_length(buf + offset, (size_t)int_len);
    /* Value */
    memcpy(buf + offset, int_bytes, (size_t)int_len);
    offset += (size_t)int_len;

    return offset;
}

/**
 * Encode a BER OCTET STRING.
 * Returns number of bytes written.
 */
static size_t ber_encode_octet_string(uint8_t *buf, const char *str, size_t str_len)
{
    size_t offset = 0;

    buf[offset++] = ASN1_OCTET_STRING;
    offset += ber_encode_length(buf + offset, str_len);
    memcpy(buf + offset, str, str_len);
    offset += str_len;

    return offset;
}

/**
 * Encode a BER NULL value.
 * Returns number of bytes written (always 2).
 */
static size_t ber_encode_null(uint8_t *buf)
{
    buf[0] = ASN1_NULL;
    buf[1] = 0x00;
    return 2;
}

/**
 * Encode an OID into BER format.
 * Returns number of bytes written.
 */
static size_t ber_encode_oid(uint8_t *buf, const uint32_t *components, int count)
{
    size_t offset = 0;
    uint8_t oid_bytes[128];
    size_t oid_len = 0;

    if (count < 2) {
        errno = EINVAL;
        return 0;
    }

    /* First two components are encoded as: first*40 + second */
    oid_bytes[oid_len++] = (uint8_t)(components[0] * 40 + components[1]);

    /* Remaining components use base-128 encoding */
    for (int i = 2; i < count; i++) {
        uint32_t val = components[i];

        if (val == 0) {
            oid_bytes[oid_len++] = 0;
        } else {
            /* Encode in base-128, most significant group first */
            uint8_t temp[5]; /* max 5 bytes for 32-bit value */
            int temp_len = 0;

            while (val > 0) {
                temp[temp_len++] = (uint8_t)(val & 0x7F);
                val >>= 7;
            }

            /* Write in reverse, setting high bit on all but last */
            for (int j = temp_len - 1; j >= 0; j--) {
                if (j > 0) {
                    oid_bytes[oid_len++] = temp[j] | 0x80;
                } else {
                    oid_bytes[oid_len++] = temp[j];
                }
            }
        }

        if (oid_len >= sizeof(oid_bytes)) {
            errno = ENOBUFS;
            return 0;
        }
    }

    /* Write tag + length + value */
    buf[offset++] = ASN1_OID;
    offset += ber_encode_length(buf + offset, oid_len);
    memcpy(buf + offset, oid_bytes, oid_len);
    offset += oid_len;

    return offset;
}

/* ==================== OID Parsing ==================== */

__attribute__((visibility("default")))
int snmp_parse_oid(const char *oid_str, uint32_t *components, int max_components)
{
    int count = 0;
    const char *p = oid_str;

    if (!oid_str || !components || max_components <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Skip leading dot if present */
    if (*p == '.') {
        p++;
    }

    while (*p && count < max_components) {
        char *end;
        unsigned long val = strtoul(p, &end, 10);
        if (end == p) {
            break; /* No more digits */
        }
        components[count++] = (uint32_t)val;
        p = end;
        if (*p == '.') {
            p++;
        }
    }

    return count;
}

/* ==================== Internal PDU Builder ==================== */

/**
 * Build the variable bindings portion of an SNMP PDU.
 * Each binding is: SEQUENCE { OID, NULL }
 */
static size_t build_varbind_list(uint8_t *buf, size_t buf_size,
                                 const char **oid_strs, int oid_count)
{
    uint8_t bindings[384];
    size_t bindings_len = 0;

    for (int i = 0; i < oid_count; i++) {
        uint32_t components[MAX_OID_COMPONENTS];
        int comp_count = snmp_parse_oid(oid_strs[i], components, MAX_OID_COMPONENTS);
        if (comp_count < 2) {
            continue; /* Skip invalid OIDs */
        }

        /* Encode: SEQUENCE { OID, NULL } */
        uint8_t varbind[128];
        size_t vb_offset = 0;

        /* OID */
        size_t oid_enc_len = ber_encode_oid(varbind + vb_offset, components, comp_count);
        if (oid_enc_len == 0) continue;
        vb_offset += oid_enc_len;

        /* NULL value */
        vb_offset += ber_encode_null(varbind + vb_offset);

        /* Wrap in SEQUENCE */
        size_t seq_total = 1 + ber_length_size(vb_offset) + vb_offset;
        if (bindings_len + seq_total > sizeof(bindings)) break;

        bindings[bindings_len++] = ASN1_SEQUENCE;
        bindings_len += ber_encode_length(bindings + bindings_len, vb_offset);
        memcpy(bindings + bindings_len, varbind, vb_offset);
        bindings_len += vb_offset;
    }

    /* Wrap all bindings in outer SEQUENCE (varbind list) */
    size_t total = 1 + ber_length_size(bindings_len) + bindings_len;
    if (total > buf_size) {
        errno = ENOBUFS;
        return 0;
    }

    size_t offset = 0;
    buf[offset++] = ASN1_SEQUENCE;
    offset += ber_encode_length(buf + offset, bindings_len);
    memcpy(buf + offset, bindings, bindings_len);
    offset += bindings_len;

    return offset;
}

/**
 * Build a complete SNMP PDU (GetRequest or GetNextRequest).
 */
static size_t build_snmp_pdu(uint8_t *buf, size_t buf_size,
                             uint8_t pdu_type,
                             const char *community,
                             const char **oid_strs, int oid_count,
                             int request_id, int version)
{
    uint8_t pdu_body[384];
    size_t pdu_body_len = 0;

    /* PDU body: request-id, error-status, error-index, varbind-list */

    /* Request ID */
    pdu_body_len += ber_encode_integer(pdu_body + pdu_body_len, request_id);
    /* Error Status (0 = noError) */
    pdu_body_len += ber_encode_integer(pdu_body + pdu_body_len, 0);
    /* Error Index (0) */
    pdu_body_len += ber_encode_integer(pdu_body + pdu_body_len, 0);
    /* Variable Bindings */
    size_t vb_len = build_varbind_list(pdu_body + pdu_body_len,
                                       sizeof(pdu_body) - pdu_body_len,
                                       oid_strs, oid_count);
    if (vb_len == 0) {
        return 0;
    }
    pdu_body_len += vb_len;

    /* Now build the full SNMP message:
       SEQUENCE { version, community, PDU } */
    uint8_t msg_body[448];
    size_t msg_body_len = 0;

    /* Version */
    msg_body_len += ber_encode_integer(msg_body + msg_body_len, version);

    /* Community */
    size_t comm_len = strlen(community);
    msg_body_len += ber_encode_octet_string(msg_body + msg_body_len, community, comm_len);

    /* PDU (tagged with pdu_type) */
    msg_body[msg_body_len++] = pdu_type;
    msg_body_len += ber_encode_length(msg_body + msg_body_len, pdu_body_len);
    memcpy(msg_body + msg_body_len, pdu_body, pdu_body_len);
    msg_body_len += pdu_body_len;

    /* Outer SEQUENCE wrapper */
    size_t total = 1 + ber_length_size(msg_body_len) + msg_body_len;
    if (total > buf_size) {
        errno = ENOBUFS;
        return 0;
    }

    size_t offset = 0;
    buf[offset++] = ASN1_SEQUENCE;
    offset += ber_encode_length(buf + offset, msg_body_len);
    memcpy(buf + offset, msg_body, msg_body_len);
    offset += msg_body_len;

    return offset;
}

/* ==================== Public API ==================== */

__attribute__((visibility("default")))
size_t snmp_encode_get(uint8_t *buf, size_t buf_size,
                       const char *community, const char *oid_str,
                       int request_id, int version)
{
    if (!buf || !community || !oid_str) {
        errno = EINVAL;
        return 0;
    }

    const char *oids[1] = { oid_str };
    return build_snmp_pdu(buf, buf_size, SNMP_GET_REQUEST,
                          community, oids, 1, request_id, version);
}

__attribute__((visibility("default")))
size_t snmp_encode_get_multi(uint8_t *buf, size_t buf_size,
                             const char *community,
                             const char **oid_strs, int oid_count,
                             int request_id, int version)
{
    if (!buf || !community || !oid_strs || oid_count <= 0) {
        errno = EINVAL;
        return 0;
    }

    return build_snmp_pdu(buf, buf_size, SNMP_GET_REQUEST,
                          community, oid_strs, oid_count, request_id, version);
}

__attribute__((visibility("default")))
size_t snmp_encode_getnext(uint8_t *buf, size_t buf_size,
                           const char *community, const char *oid_str,
                           int request_id, int version)
{
    if (!buf || !community || !oid_str) {
        errno = EINVAL;
        return 0;
    }

    const char *oids[1] = { oid_str };
    return build_snmp_pdu(buf, buf_size, SNMP_GETNEXT_REQUEST,
                          community, oids, 1, request_id, version);
}
