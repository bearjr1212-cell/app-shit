/**
 * snmp_encode.h - Fast BER/ASN.1 SNMP encoding for printer reconnaissance
 *
 * Provides efficient construction of SNMP GetRequest PDUs using
 * BER (Basic Encoding Rules) for ASN.1. Used by printer_recon.py
 * to query printer metadata via SNMP v1/v2c.
 *
 * No external dependencies (no net-snmp needed).
 */

#ifndef SNMP_ENCODE_H
#define SNMP_ENCODE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SNMP versions */
#define SNMP_VERSION_1   0
#define SNMP_VERSION_2C  1

/* Maximum OID components */
#define MAX_OID_COMPONENTS 32

/* Maximum encoded packet size */
#define SNMP_MAX_PACKET_SIZE 512

/**
 * Encode an SNMP GetRequest PDU for a single OID.
 *
 * Builds a complete SNMP v1/v2c GetRequest packet ready to send
 * via UDP port 161.
 *
 * @param buf           Output buffer
 * @param buf_size      Size of output buffer
 * @param community     Community string (e.g., "public")
 * @param oid_str       OID in dotted notation (e.g., "1.3.6.1.2.1.1.1.0")
 * @param request_id    Request ID for matching responses
 * @param version       SNMP version (0=v1, 1=v2c)
 * @return              Encoded packet length, 0 on error
 */
__attribute__((visibility("default")))
size_t snmp_encode_get(uint8_t *buf, size_t buf_size,
                       const char *community, const char *oid_str,
                       int request_id, int version);

/**
 * Encode an SNMP GetRequest PDU for multiple OIDs (GetBulk-style).
 *
 * Builds a single SNMP packet requesting multiple OIDs at once.
 *
 * @param buf           Output buffer
 * @param buf_size      Size of output buffer
 * @param community     Community string
 * @param oid_strs      Array of OID strings in dotted notation
 * @param oid_count     Number of OIDs in array
 * @param request_id    Request ID for matching responses
 * @param version       SNMP version (0=v1, 1=v2c)
 * @return              Encoded packet length, 0 on error
 */
__attribute__((visibility("default")))
size_t snmp_encode_get_multi(uint8_t *buf, size_t buf_size,
                             const char *community,
                             const char **oid_strs, int oid_count,
                             int request_id, int version);

/**
 * Encode an SNMP GetNextRequest PDU for a single OID.
 *
 * Used for SNMP walking/enumeration.
 *
 * @param buf           Output buffer
 * @param buf_size      Size of output buffer
 * @param community     Community string
 * @param oid_str       OID in dotted notation
 * @param request_id    Request ID
 * @param version       SNMP version (0=v1, 1=v2c)
 * @return              Encoded packet length, 0 on error
 */
__attribute__((visibility("default")))
size_t snmp_encode_getnext(uint8_t *buf, size_t buf_size,
                           const char *community, const char *oid_str,
                           int request_id, int version);

/**
 * Parse an OID string into numeric components.
 *
 * @param oid_str       OID in dotted notation (e.g., "1.3.6.1.2.1.1.1.0")
 * @param components    Output array for numeric components
 * @param max_components Maximum components to parse
 * @return              Number of components parsed, -1 on error
 */
__attribute__((visibility("default")))
int snmp_parse_oid(const char *oid_str, uint32_t *components, int max_components);

#ifdef __cplusplus
}
#endif

#endif /* SNMP_ENCODE_H */
