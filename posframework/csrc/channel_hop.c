/**
 * channel_hop.c - Direct nl80211 channel switching via netlink
 *
 * Implements channel control for wireless interfaces using nl80211
 * generic netlink commands directly via raw netlink sockets.
 * No subprocess calls to iw or iwconfig.
 * No external library dependencies (no libnl).
 *
 * Linux-only. Requires CAP_NET_ADMIN or root privileges.
 *
 * Compile: gcc -std=c11 -c channel_hop.c -o channel_hop.o
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/nl80211.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "channel_hop.h"

/* ==================== Internal Netlink Helpers ==================== */

/* Netlink message buffer size */
#define NL_BUF_SIZE 4096

/* Sequence number for netlink messages */
static uint32_t nl_seq = 0;

/**
 * Netlink message construction helper.
 * We build messages manually to avoid libnl dependency.
 */
struct nl_msg_buf {
    uint8_t buf[NL_BUF_SIZE];
    size_t  len;
};

/* Use system NLA_ALIGN if not already defined */
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + 3) & ~3)
#endif

/**
 * Initialize a netlink message buffer with genl header.
 */
static void nl_msg_init(struct nl_msg_buf *msg, uint16_t family_id,
                        uint8_t cmd, uint8_t version)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl;

    memset(msg->buf, 0, NL_BUF_SIZE);

    nlh = (struct nlmsghdr *)msg->buf;
    nlh->nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type  = family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = ++nl_seq;
    nlh->nlmsg_pid   = getpid();

    genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
    genl->cmd     = cmd;
    genl->version = version;

    msg->len = nlh->nlmsg_len;
}

/**
 * Add a netlink attribute (NLA) to the message.
 */
static int nl_msg_put_attr(struct nl_msg_buf *msg, uint16_t type,
                           const void *data, uint16_t data_len)
{
    struct nlattr *nla;
    size_t attr_len = NLA_ALIGN(sizeof(struct nlattr) + data_len);

    if (msg->len + attr_len > NL_BUF_SIZE) {
        errno = ENOSPC;
        return -1;
    }

    nla = (struct nlattr *)(msg->buf + msg->len);
    nla->nla_len  = sizeof(struct nlattr) + data_len;
    nla->nla_type = type;
    memcpy((uint8_t *)nla + sizeof(struct nlattr), data, data_len);

    msg->len += attr_len;

    /* Update nlmsghdr length */
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->buf;
    nlh->nlmsg_len = msg->len;

    return 0;
}

/**
 * Add a uint32 attribute.
 */
static int nl_msg_put_u32(struct nl_msg_buf *msg, uint16_t type, uint32_t val)
{
    return nl_msg_put_attr(msg, type, &val, sizeof(val));
}

/**
 * Open a generic netlink socket.
 */
static int nl_open(void)
{
    int fd;
    struct sockaddr_nl sa;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = getpid();
    sa.nl_groups = 0;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    return fd;
}

/**
 * Send a netlink message and wait for ACK/response.
 * Returns 0 on success (ACK received), -1 on error.
 */
static int nl_send_and_recv(int nl_fd, struct nl_msg_buf *msg,
                            uint8_t *resp_buf, size_t resp_size,
                            ssize_t *resp_len)
{
    struct sockaddr_nl dest;
    ssize_t ret;

    memset(&dest, 0, sizeof(dest));
    dest.nl_family = AF_NETLINK;
    dest.nl_pid    = 0; /* kernel */
    dest.nl_groups = 0;

    /* Request ACK */
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg->buf;
    nlh->nlmsg_flags |= NLM_F_ACK;

    ret = sendto(nl_fd, msg->buf, msg->len, 0,
                 (struct sockaddr *)&dest, sizeof(dest));
    if (ret < 0) {
        return -1;
    }

    /* Receive response */
    ret = recv(nl_fd, resp_buf, resp_size, 0);
    if (ret < 0) {
        return -1;
    }

    if (resp_len) {
        *resp_len = ret;
    }

    /* Check for error in response */
    struct nlmsghdr *resp_nlh = (struct nlmsghdr *)resp_buf;
    if (resp_nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp_nlh);
        if (err->error != 0) {
            errno = -err->error;
            return -1;
        }
        /* error == 0 means ACK */
        return 0;
    }

    return 0;
}

/**
 * Resolve the nl80211 generic netlink family ID.
 * Sends CTRL_CMD_GETFAMILY for "nl80211".
 */
static int nl_resolve_family(int nl_fd)
{
    struct nl_msg_buf msg;
    uint8_t resp[NL_BUF_SIZE];
    const char *family_name = "nl80211";

    /* Build family resolution request */
    nl_msg_init(&msg, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1);
    nl_msg_put_attr(&msg, CTRL_ATTR_FAMILY_NAME,
                    family_name, strlen(family_name) + 1);

    /* Don't request ACK for this one - we want the response */
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct sockaddr_nl dest;
    memset(&dest, 0, sizeof(dest));
    dest.nl_family = AF_NETLINK;

    ssize_t ret = sendto(nl_fd, msg.buf, msg.len, 0,
                         (struct sockaddr *)&dest, sizeof(dest));
    if (ret < 0) {
        return -1;
    }

    ret = recv(nl_fd, resp, sizeof(resp), 0);
    if (ret < 0) {
        return -1;
    }

    /* Parse the response to find CTRL_ATTR_FAMILY_ID */
    struct nlmsghdr *resp_nlh = (struct nlmsghdr *)resp;
    if (resp_nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp_nlh);
        errno = -err->error;
        return -1;
    }

    /* Skip netlink + genl headers */
    struct genlmsghdr *genl = (struct genlmsghdr *)NLMSG_DATA(resp_nlh);
    uint8_t *attrs_start = (uint8_t *)genl + GENL_HDRLEN;
    size_t attrs_len = resp_nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

    /* Walk attributes looking for CTRL_ATTR_FAMILY_ID */
    size_t offset = 0;
    while (offset < attrs_len) {
        struct nlattr *nla = (struct nlattr *)(attrs_start + offset);
        if (nla->nla_len < sizeof(struct nlattr)) {
            break;
        }

        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            uint16_t *fam_id = (uint16_t *)((uint8_t *)nla + sizeof(struct nlattr));
            return (int)*fam_id;
        }

        offset += NLA_ALIGN(nla->nla_len);
    }

    errno = ENOENT;
    return -1;
}

/**
 * Get interface index by name.
 */
static int get_ifindex(const char *iface)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    close(fd);
    return ifr.ifr_ifindex;
}

/**
 * Convert channel number to frequency in MHz.
 *
 * Supports 2.4GHz (channels 1-14) and 5GHz (channels 36-165).
 */
static int channel_to_freq(int channel)
{
    /* 2.4 GHz band */
    if (channel >= 1 && channel <= 13) {
        return 2407 + channel * 5;
    }
    if (channel == 14) {
        return 2484;
    }

    /* 5 GHz band */
    if (channel >= 36 && channel <= 165) {
        return 5000 + channel * 5;
    }

    /* 6 GHz band (WiFi 6E) */
    if (channel >= 1 && channel <= 233) {
        /* This conflicts with 2.4GHz, so only used if > 14 */
        return 5955 + channel * 5;
    }

    errno = EINVAL;
    return -1;
}

/**
 * Convert frequency (MHz) to channel number.
 */
static int freq_to_channel(int freq)
{
    /* 2.4 GHz band */
    if (freq == 2484) {
        return 14;
    }
    if (freq >= 2412 && freq <= 2472) {
        return (freq - 2407) / 5;
    }

    /* 5 GHz band */
    if (freq >= 5180 && freq <= 5825) {
        return (freq - 5000) / 5;
    }

    /* 6 GHz band */
    if (freq >= 5955 && freq <= 7115) {
        return (freq - 5955) / 5;
    }

    errno = EINVAL;
    return -1;
}

/* ==================== Public API ==================== */

/**
 * Set the channel on a wireless interface (20MHz width).
 *
 * Uses NL80211_CMD_SET_WIPHY with NL80211_ATTR_WIPHY_FREQ.
 * Channel width defaults to NL80211_CHAN_WIDTH_20_NOHT.
 */
__attribute__((visibility("default")))
int set_channel(const char *iface, int channel)
{
    int nl_fd = -1;
    int family_id;
    int ifindex;
    int freq;
    struct nl_msg_buf msg;
    uint8_t resp[NL_BUF_SIZE];
    int ret = -1;

    if (!iface || channel <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Convert channel to frequency */
    freq = channel_to_freq(channel);
    if (freq < 0) {
        return -1;
    }

    /* Get interface index */
    ifindex = get_ifindex(iface);
    if (ifindex < 0) {
        return -1;
    }

    /* Open netlink socket */
    nl_fd = nl_open();
    if (nl_fd < 0) {
        return -1;
    }

    /* Resolve nl80211 family ID */
    family_id = nl_resolve_family(nl_fd);
    if (family_id < 0) {
        int saved = errno;
        close(nl_fd);
        errno = saved;
        return -1;
    }

    /* Build NL80211_CMD_SET_WIPHY message */
    nl_msg_init(&msg, (uint16_t)family_id, NL80211_CMD_SET_WIPHY, 0);

    /* Add interface index */
    nl_msg_put_u32(&msg, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);

    /* Add frequency */
    nl_msg_put_u32(&msg, NL80211_ATTR_WIPHY_FREQ, (uint32_t)freq);

    /* Set channel width to 20MHz (no HT) */
    nl_msg_put_u32(&msg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT);

    /* Send and wait for ACK */
    if (nl_send_and_recv(nl_fd, &msg, resp, sizeof(resp), NULL) < 0) {
        int saved = errno;
        close(nl_fd);
        errno = saved;
        return -1;
    }

    ret = 0;
    close(nl_fd);
    return ret;
}

/**
 * Set the channel with HT40+/HT40- bandwidth.
 *
 * Uses NL80211_CMD_SET_WIPHY with NL80211_CHAN_WIDTH_40
 * and appropriate center frequency.
 */
__attribute__((visibility("default")))
int set_channel_ht40(const char *iface, int channel, int ht40_plus)
{
    int nl_fd = -1;
    int family_id;
    int ifindex;
    int freq;
    int center_freq;
    struct nl_msg_buf msg;
    uint8_t resp[NL_BUF_SIZE];

    if (!iface || channel <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Convert channel to frequency */
    freq = channel_to_freq(channel);
    if (freq < 0) {
        return -1;
    }

    /* Calculate center frequency for HT40 */
    if (ht40_plus) {
        center_freq = freq + 10; /* Center is 10 MHz above primary */
    } else {
        center_freq = freq - 10; /* Center is 10 MHz below primary */
    }

    /* Get interface index */
    ifindex = get_ifindex(iface);
    if (ifindex < 0) {
        return -1;
    }

    /* Open netlink socket */
    nl_fd = nl_open();
    if (nl_fd < 0) {
        return -1;
    }

    /* Resolve nl80211 family ID */
    family_id = nl_resolve_family(nl_fd);
    if (family_id < 0) {
        int saved = errno;
        close(nl_fd);
        errno = saved;
        return -1;
    }

    /* Build NL80211_CMD_SET_WIPHY message */
    nl_msg_init(&msg, (uint16_t)family_id, NL80211_CMD_SET_WIPHY, 0);

    /* Add interface index */
    nl_msg_put_u32(&msg, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);

    /* Add primary frequency */
    nl_msg_put_u32(&msg, NL80211_ATTR_WIPHY_FREQ, (uint32_t)freq);

    /* Set channel width to HT40 */
    nl_msg_put_u32(&msg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_40);

    /* Set center frequency */
    nl_msg_put_u32(&msg, NL80211_ATTR_CENTER_FREQ1, (uint32_t)center_freq);

    /* Send and wait for ACK */
    if (nl_send_and_recv(nl_fd, &msg, resp, sizeof(resp), NULL) < 0) {
        int saved = errno;
        close(nl_fd);
        errno = saved;
        return -1;
    }

    close(nl_fd);
    return 0;
}

/**
 * Get the current channel of a wireless interface.
 *
 * Uses NL80211_CMD_GET_INTERFACE to retrieve current frequency,
 * then converts to channel number.
 */
__attribute__((visibility("default")))
int get_channel(const char *iface)
{
    int nl_fd = -1;
    int family_id;
    int ifindex;
    struct nl_msg_buf msg;
    uint8_t resp[NL_BUF_SIZE];
    ssize_t resp_len = 0;

    if (!iface) {
        errno = EINVAL;
        return -1;
    }

    /* Get interface index */
    ifindex = get_ifindex(iface);
    if (ifindex < 0) {
        return -1;
    }

    /* Open netlink socket */
    nl_fd = nl_open();
    if (nl_fd < 0) {
        return -1;
    }

    /* Resolve nl80211 family ID */
    family_id = nl_resolve_family(nl_fd);
    if (family_id < 0) {
        int saved = errno;
        close(nl_fd);
        errno = saved;
        return -1;
    }

    /* Build NL80211_CMD_GET_INTERFACE message */
    nl_msg_init(&msg, (uint16_t)family_id, NL80211_CMD_GET_INTERFACE, 0);
    nl_msg_put_u32(&msg, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);

    /* Don't use ACK flag - we want the actual response data */
    struct nlmsghdr *nlh = (struct nlmsghdr *)msg.buf;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    struct sockaddr_nl dest;
    memset(&dest, 0, sizeof(dest));
    dest.nl_family = AF_NETLINK;

    ssize_t ret = sendto(nl_fd, msg.buf, msg.len, 0,
                         (struct sockaddr *)&dest, sizeof(dest));
    if (ret < 0) {
        int saved = errno;
        close(nl_fd);
        errno = saved;
        return -1;
    }

    /* Read response - may come in multiple messages */
    int freq = -1;
    int done = 0;

    while (!done) {
        resp_len = recv(nl_fd, resp, sizeof(resp), 0);
        if (resp_len < 0) {
            int saved = errno;
            close(nl_fd);
            errno = saved;
            return -1;
        }

        /* Walk all messages in the response buffer */
        struct nlmsghdr *resp_nlh;
        for (resp_nlh = (struct nlmsghdr *)resp;
             NLMSG_OK(resp_nlh, (uint32_t)resp_len);
             resp_nlh = NLMSG_NEXT(resp_nlh, resp_len)) {

            if (resp_nlh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }

            if (resp_nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp_nlh);
                if (err->error != 0) {
                    close(nl_fd);
                    errno = -err->error;
                    return -1;
                }
                done = 1;
                break;
            }

            /* Parse genl response for NL80211_ATTR_WIPHY_FREQ */
            struct genlmsghdr *genl = (struct genlmsghdr *)NLMSG_DATA(resp_nlh);
            uint8_t *attrs_start = (uint8_t *)genl + GENL_HDRLEN;
            size_t attrs_len = resp_nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

            size_t offset = 0;
            while (offset < attrs_len) {
                struct nlattr *nla = (struct nlattr *)(attrs_start + offset);
                if (nla->nla_len < sizeof(struct nlattr)) {
                    break;
                }

                if (nla->nla_type == NL80211_ATTR_WIPHY_FREQ) {
                    uint32_t *f = (uint32_t *)((uint8_t *)nla + sizeof(struct nlattr));
                    freq = (int)*f;
                    done = 1;
                    break;
                }

                offset += NLA_ALIGN(nla->nla_len);
            }
        }
    }

    close(nl_fd);

    if (freq < 0) {
        errno = ENODATA;
        return -1;
    }

    /* Convert frequency to channel */
    return freq_to_channel(freq);
}
