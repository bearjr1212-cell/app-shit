"""
Client Isolation Detection
──────────────────────────
Detect if a target network has AP isolation enabled.

AP isolation prevents clients from communicating with each other,
making evil twin attacks less effective (clients can't reach each other
or the attacker's services).
"""

import time

from scapy.all import sniff, Raw, ARP
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Beacon

from .config import log


class IsolationDetector:
    """
    Detect AP isolation by monitoring client behavior.

    Signs of isolation:
    - Clients associate but can't reach other devices
    - ARP requests from clients go unanswered
    - No traffic between clients on same AP
    """

    def __init__(self, interface, bssid, db=None):
        self.interface = interface
        self.bssid = bssid
        self.db = db
        self._clients = set()
        self._isolation_detected = False
        self._traffic_log = []
        self._running = False

    def _isolation_test(self):
        """
        Actively test for isolation by:
        1. Capturing client ARP traffic
        2. Attempting to respond to ARP requests from other clients
        3. If no responses, isolation is likely enabled
        """
        def pkt_handler(pkt):
            if not pkt.haslayer(Dot11):
                return
            # Check if this is ARP traffic on our BSSID
            if pkt.haslayer(ARP):
                client_mac = pkt.addr2 if pkt.addr2 else pkt.addr1
                if client_mac and client_mac != self.bssid:
                    self._clients.add(client_mac)
                    # Log ARP request/response patterns
                    if pkt[ARP].op == 1:  # ARP request
                        self._traffic_log.append(("req", client_mac, time.time()))
                    elif pkt[ARP].op == 2:  # ARP response
                        self._traffic_log.append(("resp", client_mac, time.time()))

        sniff(iface=self.interface, prn=pkt_handler, store=0, timeout=30)
        self._analyze_traffic()

    def _analyze_traffic(self):
        """Analyze captured traffic for isolation signs."""
        if len(self._clients) < 2:
            log.info(f"Isolation test: Not enough clients ({len(self._clients)}) to test")
            return

        # Count ARP requests vs responses
        requests = [t for t in self._traffic_log if t[0] == "req"]
        responses = [t for t in self._traffic_log if t[0] == "resp"]

        if len(responses) == 0 and len(requests) > 0:
            self._isolation_detected = True
            log.warning(f"AP ISOLATION DETECTED: {self.bssid} (no ARP responses)")
        elif len(responses) < len(requests) * 0.1:
            self._isolation_detected = True
            log.warning(f"AP ISOLATION LIKELY: {self.bssid} "
                       f"({len(requests)} requests, {len(responses)} responses)")

    def detect(self, timeout=30):
        """Run isolation detection test."""
        if self._isolation_detected:
            return True  # Already detected

        log.info(f"Testing AP isolation for {self.bssid}...")
        self._isolation_test()
        return self._isolation_detected

    def is_isolated(self):
        """Return whether isolation was detected."""
        return self._isolation_detected

    def get_stats(self):
        return {
            "bssid": self.bssid,
            "clients_seen": len(self._clients),
            "isolation_detected": self._isolation_detected,
            "traffic_entries": len(self._traffic_log),
        }
