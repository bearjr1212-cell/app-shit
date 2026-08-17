/**
 * packet_engine.h - Raw socket packet injection engine
 *
 * Provides low-level AF_PACKET raw socket interface for injecting
 * arbitrary 802.11 frames directly onto the wire via monitor mode interfaces.
 *
 * Linux-only. Requires CAP_NET_RAW or root.
 */

#ifndef PACKET_ENGINE_H
#define PACKET_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a raw socket bound to the specified interface.
 *
 * @param iface  Network interface name (e.g., "wlan0mon")
 * @return       Socket file descriptor on success, -1 on error (errno set)
 */
__attribute__((visibility("default")))
int init_raw_socket(const char *iface);

/**
 * Send a single raw frame on the socket.
 *
 * @param sock_fd  Socket fd returned by init_raw_socket()
 * @param frame    Pointer to complete frame data (including radiotap header)
 * @param len      Length of frame in bytes
 * @return         0 on success, -1 on error (errno set)
 */
__attribute__((visibility("default")))
int send_frame(int sock_fd, const uint8_t *frame, size_t len);

/**
 * Send a batch of raw frames on the socket.
 *
 * @param sock_fd  Socket fd returned by init_raw_socket()
 * @param frames   Array of pointers to frame data
 * @param lens     Array of frame lengths
 * @param count    Number of frames in the batch
 * @return         Number of frames successfully sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int send_frame_batch(int sock_fd, const uint8_t **frames, size_t *lens, int count);

/**
 * Close a raw socket.
 *
 * @param sock_fd  Socket fd to close
 */
__attribute__((visibility("default")))
void close_raw_socket(int sock_fd);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_ENGINE_H */
