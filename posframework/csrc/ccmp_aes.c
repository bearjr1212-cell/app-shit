/**
 * ccmp_aes.c - CCMP (AES-CCM) encryption/decryption implementation
 *
 * Implements AES-128-CCM as used by IEEE 802.11 CCMP.
 * Parameters: M=8 (MIC size), L=2 (length field size)
 *
 * References:
 *   IEEE 802.11-2020 Section 12.5.3 (CCMP)
 *   RFC 3610 (Counter with CBC-MAC)
 *   FIPS 197 (AES)
 */

#include "ccmp_aes.h"
#include <string.h>

/* ---- AES-128 Implementation (FIPS 197) ---- */

static const uint8_t aes_sbox[256] = {
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
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static const uint8_t aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* GF(2^8) multiplication by 2 */
static inline uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

/* Key expansion for AES-128 (10 rounds, 44 words) */
static void aes_key_expand(const uint8_t *key, uint8_t rk[176])
{
    memcpy(rk, key, 16);

    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, rk + (i - 1) * 4, 4);

        if (i % 4 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t = temp[0];
            temp[0] = aes_sbox[temp[1]] ^ aes_rcon[i / 4];
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[t];
        }

        for (int j = 0; j < 4; j++)
            rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ temp[j];
    }
}

/* Single AES-128 block encryption */
static void aes_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];
    memcpy(state, in, 16);

    /* AddRoundKey (initial) */
    for (int i = 0; i < 16; i++)
        state[i] ^= rk[i];

    for (int round = 1; round <= 10; round++) {
        /* SubBytes */
        for (int i = 0; i < 16; i++)
            state[i] = aes_sbox[state[i]];

        /* ShiftRows */
        uint8_t tmp;
        tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
        tmp = state[2]; state[2] = state[10]; state[10] = tmp; tmp = state[6]; state[6] = state[14]; state[14] = tmp;
        tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;

        /* MixColumns (skip in last round) */
        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                int ci = c * 4;
                uint8_t a0 = state[ci], a1 = state[ci+1], a2 = state[ci+2], a3 = state[ci+3];
                uint8_t t = a0 ^ a1 ^ a2 ^ a3;
                state[ci]   = a0 ^ xtime(a0 ^ a1) ^ t;
                state[ci+1] = a1 ^ xtime(a1 ^ a2) ^ t;
                state[ci+2] = a2 ^ xtime(a2 ^ a3) ^ t;
                state[ci+3] = a3 ^ xtime(a3 ^ a0) ^ t;
            }
        }

        /* AddRoundKey */
        for (int i = 0; i < 16; i++)
            state[i] ^= rk[round * 16 + i];
    }

    memcpy(out, state, 16);
}

__attribute__((visibility("default")))
int aes128_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
    if (!key || !input || !output)
        return -1;

    uint8_t rk[176];
    aes_key_expand(key, rk);
    aes_encrypt(rk, input, output);
    return 0;
}

/* ---- CCM Mode (M=8, L=2) ---- */

/* Format the B0 block for CBC-MAC */
static void ccm_format_b0(const uint8_t *nonce, size_t plain_len,
                           size_t aad_len, uint8_t b0[16])
{
    /* Flags: Adata(1 bit) | M' (3 bits) | L' (3 bits) */
    /* M' = (M-2)/2 = (8-2)/2 = 3, L' = L-1 = 1 */
    uint8_t flags = 0;
    if (aad_len > 0)
        flags |= 0x40;            /* Adata flag */
    flags |= ((8 - 2) / 2) << 3; /* M' = 3 */
    flags |= (2 - 1);            /* L' = 1 */

    b0[0] = flags;
    memcpy(b0 + 1, nonce, 13);   /* 13-byte nonce */
    /* Length field (L=2 bytes, big-endian) */
    b0[14] = (uint8_t)((plain_len >> 8) & 0xFF);
    b0[15] = (uint8_t)(plain_len & 0xFF);
}

/* Format counter block Ai */
static void ccm_format_ctr(const uint8_t *nonce, uint16_t counter, uint8_t a[16])
{
    /* Flags: L' = 1 */
    a[0] = 2 - 1;  /* L' = L-1 = 1 */
    memcpy(a + 1, nonce, 13);
    a[14] = (uint8_t)((counter >> 8) & 0xFF);
    a[15] = (uint8_t)(counter & 0xFF);
}

/* CBC-MAC computation */
static void ccm_cbc_mac(const uint8_t rk[176],
                         const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t tag[16])
{
    uint8_t block[16];
    uint8_t mac[16];

    /* Process B0 */
    ccm_format_b0(nonce, data_len, aad_len, block);
    aes_encrypt(rk, block, mac);

    /* Process AAD */
    if (aad_len > 0) {
        memset(block, 0, 16);
        /* AAD length encoding (< 0xFF00 uses 2 bytes) */
        block[0] = (uint8_t)((aad_len >> 8) & 0xFF);
        block[1] = (uint8_t)(aad_len & 0xFF);

        size_t aad_offset = 0;
        size_t first_block_data = (aad_len < 14) ? aad_len : 14;
        memcpy(block + 2, aad, first_block_data);
        aad_offset = first_block_data;

        /* XOR with previous MAC and encrypt */
        for (int i = 0; i < 16; i++)
            block[i] ^= mac[i];
        aes_encrypt(rk, block, mac);

        /* Process remaining AAD blocks */
        while (aad_offset < aad_len) {
            memset(block, 0, 16);
            size_t chunk = (aad_len - aad_offset < 16) ? (aad_len - aad_offset) : 16;
            memcpy(block, aad + aad_offset, chunk);
            aad_offset += chunk;

            for (int i = 0; i < 16; i++)
                block[i] ^= mac[i];
            aes_encrypt(rk, block, mac);
        }
    }

    /* Process plaintext/payload data */
    size_t offset = 0;
    while (offset < data_len) {
        memset(block, 0, 16);
        size_t chunk = (data_len - offset < 16) ? (data_len - offset) : 16;
        memcpy(block, data + offset, chunk);
        offset += chunk;

        for (int i = 0; i < 16; i++)
            block[i] ^= mac[i];
        aes_encrypt(rk, block, mac);
    }

    memcpy(tag, mac, 16);
}

__attribute__((visibility("default")))
int ccmp_encrypt(const uint8_t *tk,
                 const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plaintext, size_t plain_len,
                 uint8_t *ciphertext, uint8_t *mic_out)
{
    if (!tk || !nonce || !ciphertext || !mic_out)
        return -1;
    if (!plaintext && plain_len > 0)
        return -1;
    if (plain_len > 0xFFFF)
        return -1;  /* L=2 limits message to 65535 bytes */

    uint8_t rk[176];
    aes_key_expand(tk, rk);

    /* Step 1: Compute CBC-MAC tag over plaintext */
    uint8_t full_tag[16];
    ccm_cbc_mac(rk, nonce, aad, aad_len, plaintext, plain_len, full_tag);

    /* Step 2: Encrypt tag with counter 0 to get MIC */
    uint8_t a0[16], s0[16];
    ccm_format_ctr(nonce, 0, a0);
    aes_encrypt(rk, a0, s0);

    for (int i = 0; i < 8; i++)
        mic_out[i] = full_tag[i] ^ s0[i];

    /* Step 3: Encrypt plaintext with counter 1, 2, ... */
    size_t offset = 0;
    uint16_t counter = 1;
    while (offset < plain_len) {
        uint8_t ai[16], si[16];
        ccm_format_ctr(nonce, counter, ai);
        aes_encrypt(rk, ai, si);

        size_t chunk = (plain_len - offset < 16) ? (plain_len - offset) : 16;
        for (size_t i = 0; i < chunk; i++)
            ciphertext[offset + i] = plaintext[offset + i] ^ si[i];

        offset += chunk;
        counter++;
    }

    return 0;
}

__attribute__((visibility("default")))
int ccmp_decrypt(const uint8_t *tk,
                 const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ciphertext, size_t cipher_len,
                 const uint8_t *mic,
                 uint8_t *plaintext)
{
    if (!tk || !nonce || !plaintext || !mic)
        return -2;
    if (!ciphertext && cipher_len > 0)
        return -2;
    if (cipher_len > 0xFFFF)
        return -2;

    uint8_t rk[176];
    aes_key_expand(tk, rk);

    /* Step 1: Decrypt ciphertext with counter 1, 2, ... */
    size_t offset = 0;
    uint16_t counter = 1;
    while (offset < cipher_len) {
        uint8_t ai[16], si[16];
        ccm_format_ctr(nonce, counter, ai);
        aes_encrypt(rk, ai, si);

        size_t chunk = (cipher_len - offset < 16) ? (cipher_len - offset) : 16;
        for (size_t i = 0; i < chunk; i++)
            plaintext[offset + i] = ciphertext[offset + i] ^ si[i];

        offset += chunk;
        counter++;
    }

    /* Step 2: Compute CBC-MAC over decrypted plaintext */
    uint8_t full_tag[16];
    ccm_cbc_mac(rk, nonce, aad, aad_len, plaintext, cipher_len, full_tag);

    /* Step 3: Decrypt received MIC with counter 0 */
    uint8_t a0[16], s0[16];
    ccm_format_ctr(nonce, 0, a0);
    aes_encrypt(rk, a0, s0);

    /* Step 4: Compare computed tag with decrypted MIC */
    uint8_t diff = 0;
    for (int i = 0; i < 8; i++)
        diff |= (full_tag[i] ^ s0[i]) ^ mic[i];

    if (diff != 0) {
        /* MIC verification failed - zero plaintext for security */
        memset(plaintext, 0, cipher_len);
        return -1;
    }

    return 0;
}

__attribute__((visibility("default")))
int ccmp_build_nonce(uint8_t priority, const uint8_t *addr2,
                     const uint8_t *pn, uint8_t *nonce_out)
{
    if (!addr2 || !pn || !nonce_out)
        return -1;

    /* Nonce: Priority (1) || A2 (6) || PN (6) */
    nonce_out[0] = priority;
    memcpy(nonce_out + 1, addr2, 6);
    memcpy(nonce_out + 7, pn, 6);

    return 0;
}

__attribute__((visibility("default")))
int ccmp_build_aad(const uint8_t *hdr, size_t hdr_len,
                   uint8_t *aad_out, size_t *aad_len)
{
    if (!hdr || !aad_out || !aad_len)
        return -1;
    if (hdr_len < 24)
        return -1;

    /* Determine if QoS frame (subtype 8-15 in frame control) */
    uint16_t fc = (uint16_t)hdr[0] | ((uint16_t)hdr[1] << 8);
    int is_qos = (hdr_len >= 26) && ((fc & 0x0080) != 0); /* Subtype bit 3 */

    /* Mask mutable fields in FC:
     * Retry, PwrMgt, MoreData, Protected, Order bits */
    uint8_t fc0_masked = hdr[0] & 0x8F;  /* Keep protocol + type + subtype(low) */
    uint8_t fc1_masked = hdr[1] & 0xC7;  /* Mask retry, PM, more data */

    size_t aad_length = 0;

    /* AAD = FC(masked) || A1 || A2 || A3 || SC(masked) [|| A4] [|| QoS] */
    aad_out[aad_length++] = fc0_masked;
    aad_out[aad_length++] = fc1_masked;

    /* A1 (6 bytes) */
    memcpy(aad_out + aad_length, hdr + 4, 6);
    aad_length += 6;

    /* A2 (6 bytes) */
    memcpy(aad_out + aad_length, hdr + 10, 6);
    aad_length += 6;

    /* A3 (6 bytes) */
    memcpy(aad_out + aad_length, hdr + 16, 6);
    aad_length += 6;

    /* Sequence Control: mask sequence number, keep fragment number */
    aad_out[aad_length++] = hdr[22] & 0x0F;
    aad_out[aad_length++] = 0x00;

    /* QoS field if present */
    if (is_qos && hdr_len >= 26) {
        aad_out[aad_length++] = hdr[24] & 0x0F;  /* TID only */
        aad_out[aad_length++] = 0x00;
    }

    *aad_len = aad_length;
    return 0;
}
