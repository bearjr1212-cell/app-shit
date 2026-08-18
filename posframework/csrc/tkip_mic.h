/**
 * tkip_mic.h - TKIP Michael MIC and key mixing acceleration
 *
 * Implements the Temporal Key Integrity Protocol (TKIP) components:
 * - Michael MIC algorithm (per-MSDU integrity check)
 * - TKIP Phase 1 key mixing (per-TA, per-TK intermediate key)
 * - TKIP Phase 2 key mixing (per-packet RC4 key derivation)
 * - TSC/IV generation for TKIP encapsulation
 *
 * Reference: IEEE 802.11-2020 Section 12.5 (TKIP)
 *
 * No external dependencies beyond libc.
 */

#ifndef TKIP_MIC_H
#define TKIP_MIC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TKIP constants */
#define TKIP_MIC_KEY_LEN     8
#define TKIP_TK_LEN         16
#define TKIP_MIC_LEN         8
#define TKIP_PHASE1_OUT_LEN 10   /* 5 x uint16_t = 10 bytes */
#define TKIP_RC4_KEY_LEN    16
#define TKIP_IV_LEN          8   /* Extended IV: 4-byte IV + 4-byte extended */

/**
 * TKIP per-packet parameters.
 */
typedef struct {
    uint8_t  tk[TKIP_TK_LEN];          /* 128-bit Temporal Key */
    uint8_t  tx_mic_key[TKIP_MIC_KEY_LEN]; /* TX Michael MIC key */
    uint8_t  rx_mic_key[TKIP_MIC_KEY_LEN]; /* RX Michael MIC key */
    uint8_t  ta[6];                     /* Transmitter Address */
    uint64_t tsc;                       /* TKIP Sequence Counter (48-bit) */
} tkip_ctx_t;

/**
 * Compute Michael MIC over an MSDU.
 *
 * Michael is a weak but fast keyed hash used by TKIP for per-frame integrity.
 *
 * @param key       8-byte Michael MIC key
 * @param da        6-byte destination address
 * @param sa        6-byte source address
 * @param priority  802.11 priority (QoS TID), typically 0
 * @param data      MSDU payload data
 * @param data_len  Length of payload
 * @param mic_out   8-byte MIC output
 * @return          0 on success, -1 on error
 */
__attribute__((visibility("default")))
int michael_mic(const uint8_t *key,
                const uint8_t *da, const uint8_t *sa,
                uint8_t priority,
                const uint8_t *data, size_t data_len,
                uint8_t *mic_out);

/**
 * Verify Michael MIC on received data.
 *
 * @param key       8-byte Michael MIC key
 * @param da        6-byte destination address
 * @param sa        6-byte source address
 * @param priority  802.11 priority
 * @param data      MSDU payload (without MIC)
 * @param data_len  Length of payload
 * @param expected  8-byte expected MIC
 * @return          1 if valid, 0 if invalid, -1 on error
 */
__attribute__((visibility("default")))
int michael_mic_verify(const uint8_t *key,
                       const uint8_t *da, const uint8_t *sa,
                       uint8_t priority,
                       const uint8_t *data, size_t data_len,
                       const uint8_t *expected);

/**
 * TKIP Phase 1 key mixing.
 *
 * Combines the TK with TA and upper 32 bits of TSC to produce
 * an intermediate key (TTAK). This is cached per-TA and only
 * changes every 65536 packets.
 *
 * @param tk        16-byte Temporal Key
 * @param ta        6-byte Transmitter Address
 * @param tsc_hi    Upper 32 bits of TSC (TSC2..TSC5)
 * @param p1k_out   10-byte Phase 1 output (5 x uint16_t LE)
 * @return          0 on success, -1 on error
 */
__attribute__((visibility("default")))
int tkip_phase1(const uint8_t *tk, const uint8_t *ta,
                uint32_t tsc_hi, uint8_t *p1k_out);

/**
 * TKIP Phase 2 key mixing.
 *
 * Combines Phase 1 output with lower 16 bits of TSC to produce
 * the per-packet RC4 key and IV.
 *
 * @param tk        16-byte Temporal Key
 * @param p1k       10-byte Phase 1 key output
 * @param tsc_lo    Lower 16 bits of TSC (TSC0..TSC1)
 * @param rc4key    16-byte RC4 key output
 * @return          0 on success, -1 on error
 */
__attribute__((visibility("default")))
int tkip_phase2(const uint8_t *tk, const uint8_t *p1k,
                uint16_t tsc_lo, uint8_t *rc4key);

/**
 * Build TKIP IV/Extended IV field from TSC and key ID.
 *
 * @param tsc       48-bit TKIP Sequence Counter
 * @param key_id    Key ID (0-3, typically 0)
 * @param iv_out    8-byte IV output (4 IV + 4 Extended IV)
 * @return          0 on success, -1 on error
 */
__attribute__((visibility("default")))
int tkip_build_iv(uint64_t tsc, uint8_t key_id, uint8_t *iv_out);

#ifdef __cplusplus
}
#endif

#endif /* TKIP_MIC_H */
