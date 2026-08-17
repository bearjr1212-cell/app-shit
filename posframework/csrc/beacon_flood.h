#ifndef BEACON_FLOOD_H
#define BEACON_FLOOD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build a beacon frame with RadioTap header.
 * Returns frame length written to buf.
 */
__attribute__((visibility("default")))
size_t build_beacon(uint8_t *buf, size_t buf_size,
                    const uint8_t *src_mac,
                    const char *ssid, uint8_t channel);

/**
 * Build multiple beacon frames for a list of SSIDs.
 * Writes frames contiguously to buf, frame sizes to frame_lens.
 * Returns number of frames built.
 */
__attribute__((visibility("default")))
int build_beacon_batch(uint8_t *buf, size_t buf_size,
                       size_t *frame_lens, int max_frames,
                       const uint8_t *src_mac,
                       const char **ssids, int ssid_count,
                       uint8_t channel);

/**
 * Send pre-built beacon frames in a tight loop via raw socket.
 * Sends all frames in the batch once, returns number sent.
 */
__attribute__((visibility("default")))
int flood_beacons(int sock_fd, const uint8_t *buf,
                  const size_t *frame_lens, int frame_count);

/**
 * High-level: build + send beacons for all SSIDs in one call.
 * Opens raw socket on iface, builds frames, sends burst_count times.
 * Returns total frames sent, -1 on error.
 */
__attribute__((visibility("default")))
int beacon_flood(const char *iface, const uint8_t *src_mac,
                 const char **ssids, int ssid_count,
                 uint8_t channel, int burst_count);

#ifdef __cplusplus
}
#endif

#endif /* BEACON_FLOOD_H */
