/**
 * ccmp_aes.h - CCMP (AES-CCM) encryption/decryption acceleration
 *
 * Implements Counter mode with CBC-MAC Protocol (CCMP) for 802.11:
 * - AES-128-CCM encryption and decryption
 * - Nonce construction from PN, address, priority
 * - AAD (Additional Authentication Data) construction
 * - CCMP encapsulation (encrypt + generate 8-byte MIC)
 * - CCMP decapsulation (decrypt + verify MIC)
 *
 * Reference: IEEE 802.11-2020 Section 12.5.3 (CCMP)
 * Reference: RFC 3610 (Counter with CBC-MAC)
 *
 * No external dependencies - uses a built-in AES-128 implementation.
 */

#ifndef CCMP_AES_H
#define CCMP_AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CCMP constants */
#define CCMP_TK_LEN        16   /* 128-bit Temporal Key */
#define CCMP_MIC_LEN        8   /* 64-bit MIC (M=8) */
#define CCMP_PN_LEN         6   /* 48-bit Packet Number */
#define CCMP_NONCE_LEN     13   /* Nonce: 1 priority + 6 addr + 6 PN */
#define CCMP_AAD_MAX_LEN   30   /* Max AAD length for 802.11 */
#define CCMP_HDR_LEN        8   /* CCMP header (IV) in encrypted frame */
#define AES_BLOCK_SIZE     16

/**
 * CCMP encryption context.
 */
typedef struct {
    uint8_t  tk[CCMP_TK_LEN];      /* Temporal Key (AES-128) */
    uint64_t tx_pn;                 /* Transmit Packet Number (48-bit) */
    uint64_t rx_pn;                 /* Last received PN (replay detection) */
} ccmp_ctx_t;

/**
 * AES-128 encrypt a single block (used internally and exposed for testing).
 *
 * @param key       16-byte AES key
 * @param input     16-byte plaintext block
 * @param output    16-byte ciphertext output
 * @return          0 on success, -1 on error
 */
__attribute__((visibility("default")))
int aes128_encrypt_block(const uint8_t *key,
                         const uint8_t *input,
                         uint8_t *output);

/**
 * CCMP encrypt (AES-CCM) a plaintext payload.
 *
 * Performs AES-CCM encryption with M=8, L=2.
 *
 * @param tk          16-byte Temporal Key
 * @param nonce       13-byte nonce
 * @param aad         Additional Authenticated Data
 * @param aad_len     Length of AAD
 * @param plaintext   Plaintext data to encrypt
 * @param plain_len   Length of plaintext
 * @param ciphertext  Output: ciphertext (same length as plaintext)
 * @param mic_out     Output: 8-byte MIC
 * @return            0 on success, -1 on error
 */
__attribute__((visibility("default")))
int ccmp_encrypt(const uint8_t *tk,
                 const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plaintext, size_t plain_len,
                 uint8_t *ciphertext, uint8_t *mic_out);

/**
 * CCMP decrypt (AES-CCM) a ciphertext payload.
 *
 * Performs AES-CCM decryption and MIC verification.
 *
 * @param tk          16-byte Temporal Key
 * @param nonce       13-byte nonce
 * @param aad         Additional Authenticated Data
 * @param aad_len     Length of AAD
 * @param ciphertext  Ciphertext data to decrypt
 * @param cipher_len  Length of ciphertext (without MIC)
 * @param mic         8-byte MIC to verify
 * @param plaintext   Output: decrypted plaintext
 * @return            0 on success (MIC valid), -1 on MIC failure, -2 on error
 */
__attribute__((visibility("default")))
int ccmp_decrypt(const uint8_t *tk,
                 const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ciphertext, size_t cipher_len,
                 const uint8_t *mic,
                 uint8_t *plaintext);

/**
 * Construct CCMP nonce from 802.11 frame fields.
 *
 * Nonce format: Priority (1) || A2 (6) || PN (6)
 *
 * @param priority   QoS priority (TID), 0 if non-QoS
 * @param addr2      6-byte Address 2 (transmitter)
 * @param pn         48-bit Packet Number (6 bytes, big-endian)
 * @param nonce_out  13-byte nonce output
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int ccmp_build_nonce(uint8_t priority, const uint8_t *addr2,
                     const uint8_t *pn, uint8_t *nonce_out);

/**
 * Construct AAD from 802.11 MAC header.
 *
 * Masks mutable fields (retry, PM, more data, subtype bits)
 * and constructs AAD per IEEE 802.11-2020 12.5.3.3.3.
 *
 * @param hdr        802.11 MAC header (minimum 24 bytes)
 * @param hdr_len    Length of header (24 for non-QoS, 26 for QoS)
 * @param aad_out    AAD output buffer (at least 30 bytes)
 * @param aad_len    Output: actual AAD length written
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int ccmp_build_aad(const uint8_t *hdr, size_t hdr_len,
                   uint8_t *aad_out, size_t *aad_len);

#ifdef __cplusplus
}
#endif

#endif /* CCMP_AES_H */
