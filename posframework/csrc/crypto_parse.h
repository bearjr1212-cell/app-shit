/**
 * crypto_parse.h - Fast RSN/WPA Information Element parser
 *
 * Parses RSN (802.11i) and WPA (vendor-specific) IEs from beacon/probe
 * response frames to extract cipher suite and AKM information.
 */

#ifndef CRYPTO_PARSE_H
#define CRYPTO_PARSE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parsed RSN (WPA2/WPA3) Information Element data.
 */
typedef struct {
    char group_cipher[32];          /* Group data cipher suite name */
    char pairwise_ciphers[4][32];   /* Pairwise cipher suite names */
    int  pw_count;                  /* Number of pairwise cipher suites */
    char akm_suites[4][32];         /* Authentication/Key Management suite names */
    int  akm_count;                 /* Number of AKM suites */
    uint16_t capabilities;          /* RSN capabilities field */
} rsn_info_t;

/**
 * Parsed WPA (legacy) Information Element data.
 */
typedef struct {
    char group_cipher[32];          /* Group data cipher suite name */
    char pairwise_ciphers[4][32];   /* Pairwise cipher suite names */
    int  pw_count;                  /* Number of pairwise cipher suites */
    char akm_suites[4][32];         /* Authentication/Key Management suite names */
    int  akm_count;                 /* Number of AKM suites */
} wpa_info_t;

/**
 * Parse an RSN Information Element (tag 48).
 *
 * @param data  Pointer to IE body (after tag id and length bytes)
 * @param len   Length of IE body
 * @param out   Output structure to populate
 * @return      0 on success, -1 on parse error (errno set to EINVAL)
 */
__attribute__((visibility("default")))
int parse_rsn_ie(const uint8_t *data, size_t len, rsn_info_t *out);

/**
 * Parse a WPA vendor-specific Information Element.
 *
 * @param data  Pointer to IE body (after tag id and length, starting at OUI)
 * @param len   Length of IE body
 * @param out   Output structure to populate
 * @return      0 on success, -1 on parse error (errno set to EINVAL)
 */
__attribute__((visibility("default")))
int parse_wpa_ie(const uint8_t *data, size_t len, wpa_info_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_PARSE_H */
