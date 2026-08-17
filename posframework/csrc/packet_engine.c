/**
 * packet_engine.c - Raw socket packet injection engine
 *
 * Provides AF_PACKET/SOCK_RAW interface for injecting 802.11 frames
 * directly on wireless interfaces in monitor mode.
 *
 * Linux-only. Requires CAP_NET_RAW or root privileges.
 * No external dependencies beyond libc and Linux headers.
 *
 * Compile: gcc -std=c11 -c packet_engine.c -o packet_engine.o
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "packet_engine.h"

/* Minimal radiotap header structure (8 bytes) */
struct radiotap_header {
    uint8_t  it_version;   /* Version: always 0 */
    uint8_t  it_pad;       /* Padding: 0 */
    uint16_t it_len;       /* Total header length */
    uint32_t it_present;   /* Bitmask of present fields */
} __attribute__((packed));

#define RADIOTAP_HDR_LEN 8

/**
 * Initialize a raw socket bound to the specified interface.
 *
 * Creates an AF_PACKET/SOCK_RAW socket using ETH_P_ALL protocol,
 * then binds it to the named interface for injection.
 */
__attribute__((visibility("default")))
int init_raw_socket(const char *iface)
{
    int sock_fd;
    struct ifreq ifr;
    struct sockaddr_ll sll;

    if (!iface || strlen(iface) == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Create raw socket with AF_PACKET for layer 2 access */
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        /* errno already set by socket() */
        return -1;
    }

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        int saved_errno = errno;
        close(sock_fd);
        errno = saved_errno;
        return -1;
    }

    /* Bind socket to the interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        int saved_errno = errno;
        close(sock_fd);
        errno = saved_errno;
        return -1;
    }

    return sock_fd;
}

/**
 * Send a single raw frame on the socket.
 *
 * The frame should include a radiotap header followed by the
 * 802.11 frame. The kernel/driver will use the radiotap header
 * for TX parameters and strip it before transmission.
 */
__attribute__((visibility("default")))
int send_frame(int sock_fd, const uint8_t *frame, size_t len)
{
    ssize_t ret;

    if (sock_fd < 0 || !frame || len == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Validate minimal radiotap header presence */
    if (len < RADIOTAP_HDR_LEN) {
        errno = EINVAL;
        return -1;
    }

    /* Verify radiotap header version field */
    const struct radiotap_header *rtap = (const struct radiotap_header *)frame;
    if (rtap->it_version != 0) {
        errno = EINVAL;
        return -1;
    }

    /* Send the complete frame (radiotap + 802.11) */
    ret = write(sock_fd, frame, len);
    if (ret < 0) {
        return -1;
    }

    if ((size_t)ret != len) {
        errno = EIO;
        return -1;
    }

    return 0;
}

/**
 * Send a batch of raw frames on the socket.
 *
 * Attempts to send all frames in sequence. Stops on first fatal error.
 * Returns the number of frames successfully sent.
 */
__attribute__((visibility("default")))
int send_frame_batch(int sock_fd, const uint8_t **frames, size_t *lens, int count)
{
    int sent = 0;

    if (sock_fd < 0 || !frames || !lens || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < count; i++) {
        if (!frames[i] || lens[i] == 0) {
            /* Skip invalid entries */
            continue;
        }

        if (send_frame(sock_fd, frames[i], lens[i]) == 0) {
            sent++;
        } else {
            /* If we get EAGAIN/EWOULDBLOCK, we can try to continue */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            /* Fatal error - stop sending */
            if (sent == 0) {
                return -1;
            }
            break;
        }
    }

    return sent;
}

/**
 * Close a raw socket.
 */
__attribute__((visibility("default")))
void close_raw_socket(int sock_fd)
{
    if (sock_fd >= 0) {
        close(sock_fd);
    }
}
