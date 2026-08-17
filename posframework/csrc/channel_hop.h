/**
 * channel_hop.h - Direct nl80211 channel switching via netlink
 *
 * Provides channel control for wireless interfaces using nl80211
 * generic netlink commands. No subprocess calls to iw or iwconfig.
 *
 * Linux-only. Requires CAP_NET_ADMIN or root.
 */

#ifndef CHANNEL_HOP_H
#define CHANNEL_HOP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set the channel on a wireless interface (20MHz width).
 *
 * @param iface    Interface name (e.g., "wlan0mon")
 * @param channel  Channel number (1-14 for 2.4GHz, 36-165 for 5GHz)
 * @return         0 on success, -1 on error (errno set)
 */
__attribute__((visibility("default")))
int set_channel(const char *iface, int channel);

/**
 * Set the channel with HT40+/HT40- bandwidth.
 *
 * @param iface      Interface name
 * @param channel    Channel number
 * @param ht40_plus  1 for HT40+, 0 for HT40-
 * @return           0 on success, -1 on error (errno set)
 */
__attribute__((visibility("default")))
int set_channel_ht40(const char *iface, int channel, int ht40_plus);

/**
 * Get the current channel of a wireless interface.
 *
 * @param iface  Interface name
 * @return       Channel number on success, -1 on error (errno set)
 */
__attribute__((visibility("default")))
int get_channel(const char *iface);

#ifdef __cplusplus
}
#endif

#endif /* CHANNEL_HOP_H */
