/**
 * tkip_mic.c - TKIP Michael MIC and key mixing implementation
 *
 * References:
 *   IEEE 802.11-2020 Section 12.5.2 (TKIP)
 *   IEEE 802.11i-2004 Section 8.3.2 (Michael)
 */

#include "tkip_mic.h"
#include <string.h>

/* ---- S-box for TKIP key mixing (from IEEE 802.11) ---- */

static const uint16_t tkip_sbox[256] = {
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
    0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A
};

static inline uint16_t tkip_s(uint16_t v)
{
    return tkip_sbox[v & 0xFF] ^ ((tkip_sbox[(v >> 8) & 0xFF] << 8) |
                                   (tkip_sbox[(v >> 8) & 0xFF] >> 8));
}

/* ---- Michael MIC algorithm ---- */

static inline uint32_t michael_rotl(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

static inline uint32_t michael_rotr(uint32_t v, int n)
{
    return (v >> n) | (v << (32 - n));
}

static inline uint32_t michael_xswap(uint32_t v)
{
    return ((v & 0x00FF00FF) << 8) | ((v & 0xFF00FF00) >> 8);
}

static void michael_block(uint32_t *l, uint32_t *r)
{
    *l ^= michael_rotl(*r, 17);
    *r += *l;
    *l ^= michael_xswap(*r);
    *r += *l;
    *l ^= michael_rotl(*r, 3);
    *r += *l;
    *l ^= michael_rotr(*r, 2);
    *r += *l;
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

__attribute__((visibility("default")))
int michael_mic(const uint8_t *key,
                const uint8_t *da, const uint8_t *sa,
                uint8_t priority,
                const uint8_t *data, size_t data_len,
                uint8_t *mic_out)
{
    if (!key || !da || !sa || !mic_out)
        return -1;
    if (!data && data_len > 0)
        return -1;

    uint32_t l = get_le32(key);
    uint32_t r = get_le32(key + 4);

    /* Michael header: DA || SA || Priority || 0x00 || 0x00 || 0x00 */
    uint8_t header[16];
    memcpy(header, da, 6);
    memcpy(header + 6, sa, 6);
    header[12] = priority;
    header[13] = 0;
    header[14] = 0;
    header[15] = 0;

    /* Process header (4 words) */
    for (int i = 0; i < 4; i++) {
        l ^= get_le32(header + i * 4);
        michael_block(&l, &r);
    }

    /* Process data in 4-byte blocks */
    size_t full_blocks = data_len / 4;
    for (size_t i = 0; i < full_blocks; i++) {
        l ^= get_le32(data + i * 4);
        michael_block(&l, &r);
    }

    /* Handle remaining bytes + padding (0x5a, then zeros, final length encoding) */
    size_t remaining = data_len % 4;
    uint8_t tail[8];
    memset(tail, 0, sizeof(tail));

    if (remaining > 0)
        memcpy(tail, data + full_blocks * 4, remaining);
    tail[remaining] = 0x5a;

    l ^= get_le32(tail);
    michael_block(&l, &r);

    /* If remaining < 4, the 0x5a fits in first word, process second word of zeros */
    l ^= get_le32(tail + 4);
    michael_block(&l, &r);

    put_le32(mic_out, l);
    put_le32(mic_out + 4, r);

    return 0;
}

__attribute__((visibility("default")))
int michael_mic_verify(const uint8_t *key,
                       const uint8_t *da, const uint8_t *sa,
                       uint8_t priority,
                       const uint8_t *data, size_t data_len,
                       const uint8_t *expected)
{
    if (!expected)
        return -1;

    uint8_t computed[8];
    int ret = michael_mic(key, da, sa, priority, data, data_len, computed);
    if (ret != 0)
        return -1;

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 8; i++)
        diff |= computed[i] ^ expected[i];

    return (diff == 0) ? 1 : 0;
}

/* ---- TKIP Key Mixing ---- */

static inline uint16_t lo16(uint32_t v) { return (uint16_t)(v & 0xFFFF); }
static inline uint16_t hi16(uint32_t v) { return (uint16_t)(v >> 16); }
static inline uint16_t mk16(uint8_t hi, uint8_t lo) { return ((uint16_t)hi << 8) | lo; }

__attribute__((visibility("default")))
int tkip_phase1(const uint8_t *tk, const uint8_t *ta,
                uint32_t tsc_hi, uint8_t *p1k_out)
{
    if (!tk || !ta || !p1k_out)
        return -1;

    uint16_t p1k[5];

    /* Initialize P1K from TSC and TA */
    p1k[0] = lo16(tsc_hi);
    p1k[1] = hi16(tsc_hi);
    p1k[2] = mk16(ta[1], ta[0]);
    p1k[3] = mk16(ta[3], ta[2]);
    p1k[4] = mk16(ta[5], ta[4]);

    /* 8 rounds of mixing */
    for (int i = 0; i < 8; i++) {
        uint16_t tk_word;
        if (i & 1) {
            tk_word = mk16(tk[((i & 6) + 1) % 16], tk[(i & 6) % 16]);
        } else {
            tk_word = mk16(tk[((i & 6) + 1) % 16], tk[(i & 6) % 16]);
        }

        p1k[0] += tkip_s(p1k[4] ^ mk16(tk[1 + (i & 6)], tk[0 + (i & 6)]));
        p1k[1] += tkip_s(p1k[0] ^ mk16(tk[5 + (i & 6)], tk[4 + (i & 6)]));
        p1k[2] += tkip_s(p1k[1] ^ mk16(tk[9 + (i & 6)], tk[8 + (i & 6)]));
        p1k[3] += tkip_s(p1k[2] ^ mk16(tk[13 + (i & 6)], tk[12 + (i & 6)]));
        p1k[4] += tkip_s(p1k[3] ^ mk16(tk[1 + (i & 6)], tk[0 + (i & 6)]));
        p1k[4] += (uint16_t)i;

        (void)tk_word; /* suppress unused warning */
    }

    /* Output as little-endian bytes */
    for (int i = 0; i < 5; i++) {
        p1k_out[i * 2] = (uint8_t)(p1k[i] & 0xFF);
        p1k_out[i * 2 + 1] = (uint8_t)(p1k[i] >> 8);
    }

    return 0;
}

__attribute__((visibility("default")))
int tkip_phase2(const uint8_t *tk, const uint8_t *p1k,
                uint16_t tsc_lo, uint8_t *rc4key)
{
    if (!tk || !p1k || !rc4key)
        return -1;

    uint16_t ppk[6];

    /* Copy P1K to PPK */
    for (int i = 0; i < 5; i++)
        ppk[i] = (uint16_t)p1k[i * 2] | ((uint16_t)p1k[i * 2 + 1] << 8);

    ppk[5] = ppk[4] + tsc_lo;

    /* 6 rounds of mixing */
    ppk[0] += tkip_s(ppk[5] ^ mk16(tk[1], tk[0]));
    ppk[1] += tkip_s(ppk[0] ^ mk16(tk[3], tk[2]));
    ppk[2] += tkip_s(ppk[1] ^ mk16(tk[5], tk[4]));
    ppk[3] += tkip_s(ppk[2] ^ mk16(tk[7], tk[6]));
    ppk[4] += tkip_s(ppk[3] ^ mk16(tk[9], tk[8]));
    ppk[5] += tkip_s(ppk[4] ^ mk16(tk[11], tk[10]));

    ppk[0] += michael_rotr((uint32_t)ppk[5] ^ ((uint32_t)mk16(tk[13], tk[12])), 1);

    /* Build RC4 key */
    rc4key[0] = (uint8_t)(tsc_lo >> 8);
    rc4key[1] = (uint8_t)((tsc_lo >> 8) | 0x20) & 0x7F;
    rc4key[2] = (uint8_t)(tsc_lo & 0xFF);
    rc4key[3] = (uint8_t)((ppk[5] >> 1) & 0xFF);

    for (int i = 0; i < 6; i++) {
        rc4key[4 + i * 2] = (uint8_t)(ppk[i] & 0xFF);
        rc4key[5 + i * 2] = (uint8_t)(ppk[i] >> 8);
    }

    return 0;
}

__attribute__((visibility("default")))
int tkip_build_iv(uint64_t tsc, uint8_t key_id, uint8_t *iv_out)
{
    if (!iv_out)
        return -1;

    uint8_t tsc0 = (uint8_t)(tsc & 0xFF);
    uint8_t tsc1 = (uint8_t)((tsc >> 8) & 0xFF);
    uint8_t tsc2 = (uint8_t)((tsc >> 16) & 0xFF);
    uint8_t tsc3 = (uint8_t)((tsc >> 24) & 0xFF);
    uint8_t tsc4 = (uint8_t)((tsc >> 32) & 0xFF);
    uint8_t tsc5 = (uint8_t)((tsc >> 40) & 0xFF);

    /* IV field (first 4 bytes) */
    iv_out[0] = tsc1;                          /* TSC1 */
    iv_out[1] = (tsc1 | 0x20) & 0x7F;         /* WEP seed */
    iv_out[2] = tsc0;                          /* TSC0 */
    iv_out[3] = (key_id << 6) | 0x20;         /* Key ID + ExtIV flag */

    /* Extended IV (next 4 bytes) */
    iv_out[4] = tsc2;
    iv_out[5] = tsc3;
    iv_out[6] = tsc4;
    iv_out[7] = tsc5;

    return 0;
}
