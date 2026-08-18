/**
 * crypto_accel.h - Cryptographic acceleration for automated attack chains
 *
 * Provides high-speed crypto operations for:
 * - PMKID extraction and validation
 * - PTK/PMK derivation (PBKDF2-SHA1)
 * - WPA key hierarchy computation
 * - EAPOL MIC verification for handshake validation
 * - Downgrade attack vector preparation (WPA3->WPA2 frame crafting)
 * - Nonce generation for key reinstallation attacks
 *
 * Used by autopwn_engine.py, krack.py, pmkid.py, and handshake.py
 * for automated decryption and target processing.
 *
 * No external dependencies beyond libc.
 */

#ifndef CRYPTO_ACCEL_H
#define CRYPTO_ACCEL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key sizes */
#define PMK_LEN       32
#define PTK_LEN       80   /* 512 bits for CCMP */
#define MIC_LEN       16
#define NONCE_LEN     32
#define PMKID_LEN     16
#define SSID_MAX_LEN  32

/**
 * EAPOL key frame info needed for validation.
 */
typedef struct {
    uint8_t  anonce[NONCE_LEN];   /* AP nonce (from Msg 1/3) */
    uint8_t  snonce[NONCE_LEN];   /* STA nonce (from Msg 2) */
    uint8_t  ap_mac[6];           /* AP MAC address */
    uint8_t  sta_mac[6];          /* Station MAC address */
    uint8_t  mic[MIC_LEN];        /* MIC from message */
    uint8_t  *eapol_frame;        /* Raw EAPOL frame (MIC zeroed for calc) */
    size_t   eapol_len;           /* Length of EAPOL frame */
    int      key_ver;             /* Key descriptor version (1=HMAC-MD5, 2=HMAC-SHA1) */
} eapol_key_info_t;

/**
 * Derived from a successful handshake / PMKID attack.
 */
typedef struct {
    uint8_t  pmk[PMK_LEN];       /* Pairwise Master Key */
    uint8_t  ptk[PTK_LEN];       /* Pairwise Transient Key */
    uint8_t  kck[16];            /* Key Confirmation Key (PTK bytes 0-15) */
    uint8_t  kek[16];            /* Key Encryption Key (PTK bytes 16-31) */
    uint8_t  tk[16];             /* Temporal Key (PTK bytes 32-47) */
    int      valid;              /* 1 if keys are valid */
} derived_keys_t;

/**
 * Downgrade attack frame builder output.
 */
typedef struct {
    uint8_t  frame[256];         /* Built frame data */
    size_t   frame_len;          /* Length of built frame */
    int      attack_type;        /* 0=deauth, 1=disassoc, 2=sa_query, 3=channel_switch */
} downgrade_frame_t;

/* Downgrade attack types */
#define DOWNGRADE_DEAUTH          0
#define DOWNGRADE_DISASSOC        1
#define DOWNGRADE_SA_QUERY        2
#define DOWNGRADE_CHANNEL_SWITCH  3
#define DOWNGRADE_CSA_BEACON      4

/**
 * Compute HMAC-SHA1 (used in WPA key derivation).
 *
 * @param key       HMAC key
 * @param key_len   Length of key
 * @param data      Input data
 * @param data_len  Length of input data
 * @param output    Output buffer (20 bytes)
 * @return          0 on success, -1 on error
 */
__attribute__((visibility("default")))
int hmac_sha1(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len,
              uint8_t *output);

/**
 * PBKDF2-SHA1 key derivation (WPA PSK from passphrase).
 *
 * Derives a 256-bit PMK from a passphrase and SSID.
 * Uses 4096 iterations per the WPA2 specification.
 *
 * @param passphrase   WiFi password string
 * @param ssid         Network SSID
 * @param ssid_len     Length of SSID
 * @param output       Output buffer (32 bytes for PMK)
 * @return             0 on success, -1 on error
 */
__attribute__((visibility("default")))
int pbkdf2_sha1(const char *passphrase, const uint8_t *ssid, size_t ssid_len,
                uint8_t *output);

/**
 * Derive PTK from PMK using the PRF-512 function.
 *
 * PTK = PRF-512(PMK, "Pairwise key expansion",
 *               min(AP_MAC,STA_MAC) || max(AP_MAC,STA_MAC) ||
 *               min(ANonce,SNonce) || max(ANonce,SNonce))
 *
 * @param pmk        32-byte PMK
 * @param ap_mac     6-byte AP MAC
 * @param sta_mac    6-byte STA MAC
 * @param anonce     32-byte AP nonce
 * @param snonce     32-byte STA nonce
 * @param ptk_out    80-byte PTK output
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int derive_ptk(const uint8_t *pmk,
               const uint8_t *ap_mac, const uint8_t *sta_mac,
               const uint8_t *anonce, const uint8_t *snonce,
               uint8_t *ptk_out);

/**
 * Compute PMKID from PMK, AP MAC, and STA MAC.
 *
 * PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)
 *
 * @param pmk        32-byte PMK
 * @param ap_mac     6-byte AP MAC address
 * @param sta_mac    6-byte STA MAC address
 * @param pmkid_out  16-byte PMKID output
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int compute_pmkid(const uint8_t *pmk,
                  const uint8_t *ap_mac, const uint8_t *sta_mac,
                  uint8_t *pmkid_out);

/**
 * Verify the MIC on an EAPOL key frame.
 *
 * @param kck           16-byte KCK (from PTK[0:16])
 * @param eapol_frame   Raw EAPOL frame with MIC field zeroed
 * @param frame_len     Length of frame
 * @param expected_mic  16-byte expected MIC
 * @param key_ver       Key version (1=MD5, 2=SHA1)
 * @return              1 if MIC matches, 0 if not, -1 on error
 */
__attribute__((visibility("default")))
int verify_eapol_mic(const uint8_t *kck,
                     const uint8_t *eapol_frame, size_t frame_len,
                     const uint8_t *expected_mic, int key_ver);

/**
 * Build a WPA3 downgrade attack frame.
 *
 * Crafts management frames used to force WPA3 clients to fall back
 * to WPA2 for handshake capture (SAE -> PSK downgrade).
 *
 * @param frame_out   Output frame buffer (256 bytes min)
 * @param attack_type Downgrade attack type (DOWNGRADE_*)
 * @param ap_mac      6-byte AP MAC
 * @param sta_mac     6-byte target STA MAC
 * @param bssid       6-byte BSSID
 * @param channel     WiFi channel
 * @return            Frame length on success, 0 on error
 */
__attribute__((visibility("default")))
size_t build_downgrade_frame(uint8_t *frame_out, int attack_type,
                             const uint8_t *ap_mac, const uint8_t *sta_mac,
                             const uint8_t *bssid, int channel);

/**
 * Generate a random nonce for key reinstallation attacks.
 *
 * @param nonce_out  32-byte nonce output
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int generate_nonce(uint8_t *nonce_out);

/**
 * Build a complete automated attack vector payload.
 *
 * Combines target info with selected attack type to produce
 * ready-to-inject frame sequences for automated operation.
 *
 * @param frames_out     Output buffer for frame sequence
 * @param buf_size       Size of output buffer
 * @param frame_count    Output: number of frames built
 * @param ap_mac         6-byte AP MAC
 * @param sta_mac        6-byte target STA MAC (NULL for broadcast)
 * @param channel        WiFi channel
 * @param attack_type    Attack type selector (DOWNGRADE_*)
 * @param burst_count    Number of frames per type
 * @return               Total bytes written to frames_out, 0 on error
 */
__attribute__((visibility("default")))
size_t build_attack_vector(uint8_t *frames_out, size_t buf_size,
                           int *frame_count,
                           const uint8_t *ap_mac, const uint8_t *sta_mac,
                           int channel, int attack_type, int burst_count);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ACCEL_H */
