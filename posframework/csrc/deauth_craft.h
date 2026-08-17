/**
 * deauth_craft.h - Batch deauthentication/disassociation frame builder
 *
 * Constructs and sends 802.11 deauthentication and disassociation
 * management frames with proper RadioTap headers for injection.
 */

#ifndef DEAUTH_CRAFT_H
#define DEAUTH_CRAFT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Craft a deauthentication frame with RadioTap header.
 *
 * @param buf       Output buffer (must be at least 34 bytes)
 * @param sender    Source MAC address (6 bytes)
 * @param receiver  Destination MAC address (6 bytes)
 * @param bssid     BSSID MAC address (6 bytes)
 * @param reason    Deauth reason code (e.g., 7 = class 3 frame from nonassociated STA)
 * @return          Total frame length written to buf
 */
__attribute__((visibility("default")))
size_t craft_deauth_frame(uint8_t *buf, const uint8_t *sender,
                          const uint8_t *receiver, const uint8_t *bssid,
                          uint16_t reason);

/**
 * Craft a disassociation frame with RadioTap header.
 *
 * @param buf       Output buffer (must be at least 34 bytes)
 * @param sender    Source MAC address (6 bytes)
 * @param receiver  Destination MAC address (6 bytes)
 * @param bssid     BSSID MAC address (6 bytes)
 * @param reason    Disassoc reason code
 * @return          Total frame length written to buf
 */
__attribute__((visibility("default")))
size_t craft_disassoc_frame(uint8_t *buf, const uint8_t *sender,
                            const uint8_t *receiver, const uint8_t *bssid,
                            uint16_t reason);

/**
 * Send burst of deauth frames targeting a specific client.
 *
 * @param sock_fd        Raw socket fd (from init_raw_socket)
 * @param bssid          BSSID of the AP (6 bytes)
 * @param client         Client MAC address (6 bytes)
 * @param burst_count    Number of deauth frames to send
 * @param bidirectional  If nonzero, send deauths in both directions (AP->client and client->AP)
 * @return               Number of frames successfully sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int deauth_target(int sock_fd, const uint8_t *bssid, const uint8_t *client,
                  int burst_count, int bidirectional);

/**
 * Send broadcast deauth frames (from AP to broadcast).
 *
 * @param sock_fd      Raw socket fd
 * @param bssid        BSSID of the AP (6 bytes)
 * @param burst_count  Number of deauth frames to send
 * @return             Number of frames successfully sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int deauth_broadcast(int sock_fd, const uint8_t *bssid, int burst_count);

#ifdef __cplusplus
}
#endif

#endif /* DEAUTH_CRAFT_H */
