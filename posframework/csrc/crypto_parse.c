/**
 * crypto_parse.c - Fast RSN/WPA Information Element parser
 *
 * Parses RSN (802.11i / WPA2) and WPA (vendor-specific) Information
 * Elements to extract cipher suites and AKM information from
 * beacon and probe response frames.
 *
 * No external dependencies. Pure C11 with standard library only.
 *
 * Compile: gcc -std=c11 -c crypto_parse.c -o crypto_parse.o
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "crypto_parse.h"

/* ==================== OUI Definitions ==================== */

/* IEEE 802.11 RSN OUI: 00-0F-AC */
static const uint8_t RSN_OUI[3] = { 0x00, 0x0F, 0xAC };

/* Microsoft WPA OUI: 00-50-F2 */
static const uint8_t WPA_OUI[3] = { 0x00, 0x50, 0xF2 };

/* WPA vendor IE: OUI 00-50-F2, type 1 */
static const uint8_t WPA_IE_VENDOR[4] = { 0x00, 0x50, 0xF2, 0x01 };

/* ==================== Cipher Suite Lookup ==================== */

/**
 * Resolve a cipher suite OUI+type to a human-readable name.
 *
 * @param oui   3-byte OUI
 * @param type  Suite type selector
 * @param out   Output buffer (at least 32 bytes)
 */
static void resolve_cipher_suite(const uint8_t *oui, uint8_t type, char *out)
{
    /* Check if OUI matches RSN (00-0F-AC) */
    if (memcmp(oui, RSN_OUI, 3) == 0) {
        switch (type) {
        case 0:  snprintf(out, 32, "GROUP"); break;
        case 1:  snprintf(out, 32, "WEP-40"); break;
        case 2:  snprintf(out, 32, "TKIP"); break;
        case 3:  snprintf(out, 32, "WRAP"); break;
        case 4:  snprintf(out, 32, "CCMP"); break;
        case 5:  snprintf(out, 32, "WEP-104"); break;
        case 6:  snprintf(out, 32, "BIP-CMAC-128"); break;
        case 7:  snprintf(out, 32, "NO-GROUP"); break;
        case 8:  snprintf(out, 32, "GCMP-128"); break;
        case 9:  snprintf(out, 32, "GCMP-256"); break;
        case 10: snprintf(out, 32, "CCMP-256"); break;
        case 11: snprintf(out, 32, "BIP-GMAC-128"); break;
        case 12: snprintf(out, 32, "BIP-GMAC-256"); break;
        case 13: snprintf(out, 32, "BIP-CMAC-256"); break;
        default: snprintf(out, 32, "RSN-UNKNOWN(%u)", type); break;
        }
    }
    /* Check if OUI matches WPA (00-50-F2) */
    else if (memcmp(oui, WPA_OUI, 3) == 0) {
        switch (type) {
        case 0:  snprintf(out, 32, "GROUP"); break;
        case 1:  snprintf(out, 32, "WEP-40"); break;
        case 2:  snprintf(out, 32, "TKIP"); break;
        case 3:  snprintf(out, 32, "WRAP"); break;
        case 4:  snprintf(out, 32, "CCMP"); break;
        case 5:  snprintf(out, 32, "WEP-104"); break;
        default: snprintf(out, 32, "WPA-UNKNOWN(%u)", type); break;
        }
    }
    else {
        snprintf(out, 32, "VENDOR(%02x%02x%02x:%u)",
                 oui[0], oui[1], oui[2], type);
    }
}

/**
 * Resolve an AKM suite OUI+type to a human-readable name.
 *
 * @param oui   3-byte OUI
 * @param type  Suite type selector
 * @param out   Output buffer (at least 32 bytes)
 */
static void resolve_akm_suite(const uint8_t *oui, uint8_t type, char *out)
{
    if (memcmp(oui, RSN_OUI, 3) == 0) {
        switch (type) {
        case 1:  snprintf(out, 32, "802.1X"); break;
        case 2:  snprintf(out, 32, "PSK"); break;
        case 3:  snprintf(out, 32, "FT-802.1X"); break;
        case 4:  snprintf(out, 32, "FT-PSK"); break;
        case 5:  snprintf(out, 32, "802.1X-SHA256"); break;
        case 6:  snprintf(out, 32, "PSK-SHA256"); break;
        case 7:  snprintf(out, 32, "TDLS"); break;
        case 8:  snprintf(out, 32, "SAE"); break;
        case 9:  snprintf(out, 32, "FT-SAE"); break;
        case 10: snprintf(out, 32, "AP-PEER-KEY"); break;
        case 11: snprintf(out, 32, "802.1X-SUITE-B"); break;
        case 12: snprintf(out, 32, "802.1X-SUITE-B-192"); break;
        case 13: snprintf(out, 32, "FT-802.1X-SHA384"); break;
        case 14: snprintf(out, 32, "FILS-SHA256"); break;
        case 15: snprintf(out, 32, "FILS-SHA384"); break;
        case 16: snprintf(out, 32, "FT-FILS-SHA256"); break;
        case 17: snprintf(out, 32, "FT-FILS-SHA384"); break;
        case 18: snprintf(out, 32, "OWE"); break;
        default: snprintf(out, 32, "AKM-UNKNOWN(%u)", type); break;
        }
    }
    else if (memcmp(oui, WPA_OUI, 3) == 0) {
        switch (type) {
        case 1:  snprintf(out, 32, "802.1X"); break;
        case 2:  snprintf(out, 32, "PSK"); break;
        default: snprintf(out, 32, "WPA-AKM(%u)", type); break;
        }
    }
    else {
        snprintf(out, 32, "VENDOR-AKM(%02x%02x%02x:%u)",
                 oui[0], oui[1], oui[2], type);
    }
}

/* ==================== Safe Read Helpers ==================== */

/**
 * Read a little-endian uint16 from buffer with bounds checking.
 */
static int read_le16(const uint8_t *data, size_t len, size_t offset, uint16_t *val)
{
    if (offset + 2 > len) {
        return -1;
    }
    *val = (uint16_t)(data[offset] | (data[offset + 1] << 8));
    return 0;
}

/* ==================== Public API ==================== */

/**
 * Parse an RSN Information Element (tag ID 48, WPA2/WPA3).
 *
 * RSN IE format (body, after tag id and length):
 *   [2] Version (must be 1)
 *   [4] Group Data Cipher Suite (OUI + type)
 *   [2] Pairwise Cipher Suite Count
 *   [4*n] Pairwise Cipher Suites
 *   [2] AKM Suite Count
 *   [4*m] AKM Suites
 *   [2] RSN Capabilities
 *
 * @param data  Pointer to IE body (after tag id=48 and length byte)
 * @param len   Length of IE body
 * @param out   Output structure to populate
 * @return      0 on success, -1 on parse error
 */
__attribute__((visibility("default")))
int parse_rsn_ie(const uint8_t *data, size_t len, rsn_info_t *out)
{
    size_t offset = 0;
    uint16_t version;
    uint16_t count;

    if (!data || !out) {
        errno = EINVAL;
        return -1;
    }

    /* Zero the output structure */
    memset(out, 0, sizeof(rsn_info_t));

    /* Minimum RSN IE length: version(2) + group(4) + pw_count(2) + one pw(4)
       + akm_count(2) + one akm(4) = 18, but version alone is valid min */
    if (len < 2) {
        errno = EINVAL;
        return -1;
    }

    /* Read version (must be 1) */
    if (read_le16(data, len, offset, &version) < 0) {
        errno = EINVAL;
        return -1;
    }
    offset += 2;

    if (version != 1) {
        errno = EINVAL;
        return -1;
    }

    /* Group Data Cipher Suite (4 bytes: OUI[3] + type[1]) */
    if (offset + 4 > len) {
        /* RSN IE can be truncated after version - means defaults */
        snprintf(out->group_cipher, 32, "CCMP");
        return 0;
    }
    resolve_cipher_suite(data + offset, data[offset + 3], out->group_cipher);
    offset += 4;

    /* Pairwise Cipher Suite Count */
    if (read_le16(data, len, offset, &count) < 0) {
        /* Truncated - use defaults */
        out->pw_count = 1;
        snprintf(out->pairwise_ciphers[0], 32, "CCMP");
        return 0;
    }
    offset += 2;

    /* Limit to 4 pairwise suites (struct capacity) */
    out->pw_count = (count > 4) ? 4 : (int)count;

    /* Read pairwise cipher suites */
    for (int i = 0; i < (int)count && i < 4; i++) {
        if (offset + 4 > len) {
            errno = EINVAL;
            return -1;
        }
        resolve_cipher_suite(data + offset, data[offset + 3],
                             out->pairwise_ciphers[i]);
        offset += 4;
    }
    /* Skip any excess pairwise suites beyond our capacity */
    if (count > 4) {
        offset += (count - 4) * 4;
    }

    /* AKM Suite Count */
    if (read_le16(data, len, offset, &count) < 0) {
        return 0; /* Truncated but valid so far */
    }
    offset += 2;

    /* Limit to 4 AKM suites (struct capacity) */
    out->akm_count = (count > 4) ? 4 : (int)count;

    /* Read AKM suites */
    for (int i = 0; i < (int)count && i < 4; i++) {
        if (offset + 4 > len) {
            errno = EINVAL;
            return -1;
        }
        resolve_akm_suite(data + offset, data[offset + 3],
                          out->akm_suites[i]);
        offset += 4;
    }
    /* Skip excess */
    if (count > 4) {
        offset += (count - 4) * 4;
    }

    /* RSN Capabilities (2 bytes) */
    if (offset + 2 <= len) {
        read_le16(data, len, offset, &out->capabilities);
    }

    return 0;
}

/**
 * Parse a WPA vendor-specific Information Element.
 *
 * WPA IE format (body starting at OUI, after tag id=221 and length):
 *   [4] OUI + Type (00-50-F2-01)
 *   [2] Version (must be 1)
 *   [4] Group Data Cipher Suite
 *   [2] Pairwise Cipher Suite Count
 *   [4*n] Pairwise Cipher Suites
 *   [2] AKM Suite Count
 *   [4*m] AKM Suites
 *
 * @param data  Pointer to IE body (starting at OUI, after tag+length)
 * @param len   Length of IE body
 * @param out   Output structure to populate
 * @return      0 on success, -1 on parse error
 */
__attribute__((visibility("default")))
int parse_wpa_ie(const uint8_t *data, size_t len, wpa_info_t *out)
{
    size_t offset = 0;
    uint16_t version;
    uint16_t count;

    if (!data || !out) {
        errno = EINVAL;
        return -1;
    }

    /* Zero the output structure */
    memset(out, 0, sizeof(wpa_info_t));

    /* Minimum: OUI+type(4) + version(2) = 6 */
    if (len < 6) {
        errno = EINVAL;
        return -1;
    }

    /* Verify WPA OUI + type (00-50-F2-01) */
    if (memcmp(data, WPA_IE_VENDOR, 4) != 0) {
        errno = EINVAL;
        return -1;
    }
    offset += 4;

    /* Read version (must be 1) */
    if (read_le16(data, len, offset, &version) < 0) {
        errno = EINVAL;
        return -1;
    }
    offset += 2;

    if (version != 1) {
        errno = EINVAL;
        return -1;
    }

    /* Group Data Cipher Suite */
    if (offset + 4 > len) {
        /* Truncated - default to TKIP for WPA */
        snprintf(out->group_cipher, 32, "TKIP");
        return 0;
    }
    resolve_cipher_suite(data + offset, data[offset + 3], out->group_cipher);
    offset += 4;

    /* Pairwise Cipher Suite Count */
    if (read_le16(data, len, offset, &count) < 0) {
        out->pw_count = 1;
        snprintf(out->pairwise_ciphers[0], 32, "TKIP");
        return 0;
    }
    offset += 2;

    out->pw_count = (count > 4) ? 4 : (int)count;

    /* Read pairwise cipher suites */
    for (int i = 0; i < (int)count && i < 4; i++) {
        if (offset + 4 > len) {
            errno = EINVAL;
            return -1;
        }
        resolve_cipher_suite(data + offset, data[offset + 3],
                             out->pairwise_ciphers[i]);
        offset += 4;
    }
    if (count > 4) {
        offset += (count - 4) * 4;
    }

    /* AKM Suite Count */
    if (read_le16(data, len, offset, &count) < 0) {
        return 0;
    }
    offset += 2;

    out->akm_count = (count > 4) ? 4 : (int)count;

    /* Read AKM suites */
    for (int i = 0; i < (int)count && i < 4; i++) {
        if (offset + 4 > len) {
            errno = EINVAL;
            return -1;
        }
        resolve_akm_suite(data + offset, data[offset + 3],
                          out->akm_suites[i]);
        offset += 4;
    }

    return 0;
}
