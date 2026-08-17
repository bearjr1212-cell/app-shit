"""
Certificate-Based Auth Detector Module
───────────────────────────────────────
Monitors TLS handshakes for client certificate authentication:
  - Detects CertificateRequest messages from servers
  - Detects Certificate messages from clients
  - Logs client certificate subject DN, issuer, serial number
  - Flags high-value targets using certificate-based auth
  - Identifies mutual TLS (mTLS) connections
"""

import re
import time
import struct
import binascii
import threading
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff

from .config import log


class CertAuthDetector:
    """
    TLS certificate-based authentication detector.

    Monitors TLS handshakes to detect when servers request client
    certificates (CertificateRequest) and when clients present them
    (Certificate). Logs certificate metadata including subject DN,
    issuer, and serial number.
    """

    # TLS content types
    TLS_HANDSHAKE = 0x16
    TLS_CHANGE_CIPHER_SPEC = 0x14
    TLS_ALERT = 0x15

    # TLS handshake types
    HANDSHAKE_CLIENT_HELLO = 0x01
    HANDSHAKE_SERVER_HELLO = 0x02
    HANDSHAKE_CERTIFICATE = 0x0B
    HANDSHAKE_CERT_REQUEST = 0x0D
    HANDSHAKE_SERVER_HELLO_DONE = 0x0E
    HANDSHAKE_CERT_VERIFY = 0x0F

    def __init__(self, interface, ports=None):
        self.interface = interface
        self.ports = ports or [443, 8443, 636, 993, 995, 4443]
        self._running = False
        self._thread = None
        self._detections = []
        self._lock = threading.Lock()
        self._packets_processed = 0
        self._sessions = {}  # Track TLS sessions for correlation
        self._high_value_patterns = self._compile_high_value_patterns()

    def _compile_high_value_patterns(self):
        """Compile patterns for identifying high-value cert auth targets."""
        return [
            re.compile(r'(?:admin|root|superuser)', re.I),
            re.compile(r'(?:CN\s*=\s*)[^,]*(?:admin|root|svc|service)', re.I),
            re.compile(r'(?:OU\s*=\s*)[^,]*(?:IT|Security|Engineering|DevOps)', re.I),
            re.compile(r'(?:O\s*=\s*)[^,]*(?:Bank|Financial|Healthcare|Gov)', re.I),
            re.compile(r'(?:vpn|gateway|radius|ldap|kdc)', re.I),
            re.compile(r'(?:smartcard|yubikey|piv)', re.I),
        ]

    def _parse_tls_record(self, data):
        """
        Parse TLS record header.
        Returns (content_type, version, length, payload) or None.
        """
        if len(data) < 5:
            return None

        content_type = data[0]
        version = struct.unpack("!H", data[1:3])[0]
        length = struct.unpack("!H", data[3:5])[0]

        if len(data) < 5 + length:
            return None

        payload = data[5:5 + length]
        return (content_type, version, length, payload)

    def _parse_handshake_header(self, data, offset=0):
        """
        Parse TLS handshake message header.
        Returns (handshake_type, length, offset_after_header) or None.
        """
        if offset + 4 > len(data):
            return None

        hs_type = data[offset]
        length = struct.unpack("!I", b'\x00' + data[offset + 1:offset + 4])[0]

        return (hs_type, length, offset + 4)

    def _parse_certificate_message(self, data, offset=0):
        """
        Parse TLS Certificate handshake message.
        Extracts certificate chain (list of DER-encoded certificates).
        """
        certs = []

        if offset + 3 > len(data):
            return certs

        # Certificates total length (3 bytes)
        certs_total_len = struct.unpack("!I", b'\x00' + data[offset:offset + 3])[0]
        offset += 3
        end = offset + certs_total_len

        while offset + 3 < end and offset + 3 < len(data):
            # Individual certificate length (3 bytes)
            cert_len = struct.unpack("!I", b'\x00' + data[offset:offset + 3])[0]
            offset += 3

            if cert_len > 0 and offset + cert_len <= len(data):
                cert_data = data[offset:offset + cert_len]
                certs.append(cert_data)
                offset += cert_len
            else:
                break

        return certs

    def _parse_cert_request(self, data, offset=0):
        """
        Parse TLS CertificateRequest message.
        Extracts certificate types and distinguished names of acceptable CAs.
        """
        result = {
            "cert_types": [],
            "sig_algorithms": [],
            "ca_names": []
        }

        if offset >= len(data):
            return result

        # Certificate types length (1 byte)
        if offset >= len(data):
            return result
        cert_types_len = data[offset]
        offset += 1

        # Certificate types
        for i in range(cert_types_len):
            if offset >= len(data):
                break
            cert_type = data[offset]
            offset += 1
            type_names = {
                1: "rsa_sign",
                2: "dss_sign",
                64: "ecdsa_sign",
            }
            result["cert_types"].append(type_names.get(cert_type, f"type_{cert_type}"))

        # Signature algorithms length (2 bytes) - TLS 1.2+
        if offset + 2 > len(data):
            return result
        sig_algs_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        offset += sig_algs_len  # Skip signature algorithms for now

        # Distinguished names length (2 bytes)
        if offset + 2 > len(data):
            return result
        dn_list_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        dn_end = offset + dn_list_len
        while offset + 2 < dn_end and offset + 2 < len(data):
            dn_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            if dn_len > 0 and offset + dn_len <= len(data):
                dn_data = data[offset:offset + dn_len]
                dn_str = self._parse_x500_name(dn_data)
                if dn_str:
                    result["ca_names"].append(dn_str)
                offset += dn_len
            else:
                break

        return result

    def _parse_x500_name(self, data):
        """
        Parse X.500 Distinguished Name from DER-encoded data.
        Returns a string representation (e.g., "CN=..., O=..., C=...").
        """
        # OID to attribute name mapping
        oid_names = {
            b'\x55\x04\x03': 'CN',
            b'\x55\x04\x06': 'C',
            b'\x55\x04\x07': 'L',
            b'\x55\x04\x08': 'ST',
            b'\x55\x04\x0a': 'O',
            b'\x55\x04\x0b': 'OU',
            b'\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x01': 'UID',
            b'\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19': 'DC',
        }

        parts = []
        i = 0

        # Scan for OID patterns followed by string values
        while i < len(data) - 5:
            # Look for OBJECT IDENTIFIER tag (0x06)
            if data[i] == 0x06:
                oid_len = data[i + 1] if i + 1 < len(data) else 0
                if oid_len > 0 and i + 2 + oid_len < len(data):
                    oid = data[i + 2:i + 2 + oid_len]
                    # Look for the value after the OID
                    val_offset = i + 2 + oid_len
                    if val_offset < len(data) and data[val_offset] in (0x0C, 0x13, 0x16, 0x1E):
                        # UTF8String, PrintableString, IA5String, BMPString
                        val_len = data[val_offset + 1] if val_offset + 1 < len(data) else 0
                        if val_len > 0 and val_offset + 2 + val_len <= len(data):
                            val = data[val_offset + 2:val_offset + 2 + val_len]
                            attr_name = oid_names.get(oid, f"OID({binascii.hexlify(oid).decode()})")
                            try:
                                val_str = val.decode('utf-8', errors='ignore')
                                parts.append(f"{attr_name}={val_str}")
                            except Exception:
                                pass
                            i = val_offset + 2 + val_len
                            continue
            i += 1

        return ", ".join(parts) if parts else None

    def _extract_cert_info(self, cert_der):
        """
        Extract basic info from a DER-encoded X.509 certificate.
        Returns dict with subject, issuer, serial number.
        """
        info = {
            "subject": None,
            "issuer": None,
            "serial": None,
        }

        if len(cert_der) < 10:
            return info

        # Parse X.509 certificate structure (simplified)
        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        # tbsCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }

        try:
            offset = 0

            # Outer SEQUENCE
            if cert_der[offset] != 0x30:
                return info
            offset += 1
            _, offset = self._parse_der_length(cert_der, offset)

            # tbsCertificate SEQUENCE
            if cert_der[offset] != 0x30:
                return info
            offset += 1
            tbs_len, offset = self._parse_der_length(cert_der, offset)
            tbs_start = offset

            # Version [0] EXPLICIT (optional)
            if offset < len(cert_der) and cert_der[offset] == 0xA0:
                offset += 1
                v_len, offset = self._parse_der_length(cert_der, offset)
                offset += v_len

            # Serial number INTEGER
            if offset < len(cert_der) and cert_der[offset] == 0x02:
                offset += 1
                serial_len, offset = self._parse_der_length(cert_der, offset)
                if serial_len > 0 and offset + serial_len <= len(cert_der):
                    serial_bytes = cert_der[offset:offset + serial_len]
                    info["serial"] = binascii.hexlify(serial_bytes).decode()
                    offset += serial_len

            # Signature algorithm SEQUENCE (skip)
            if offset < len(cert_der) and cert_der[offset] == 0x30:
                offset += 1
                sig_len, offset = self._parse_der_length(cert_der, offset)
                offset += sig_len

            # Issuer SEQUENCE
            if offset < len(cert_der) and cert_der[offset] == 0x30:
                offset += 1
                issuer_len, offset = self._parse_der_length(cert_der, offset)
                issuer_data = cert_der[offset:offset + issuer_len]
                info["issuer"] = self._parse_x500_name(issuer_data)
                offset += issuer_len

            # Validity SEQUENCE (skip)
            if offset < len(cert_der) and cert_der[offset] == 0x30:
                offset += 1
                val_len, offset = self._parse_der_length(cert_der, offset)
                offset += val_len

            # Subject SEQUENCE
            if offset < len(cert_der) and cert_der[offset] == 0x30:
                offset += 1
                subj_len, offset = self._parse_der_length(cert_der, offset)
                subj_data = cert_der[offset:offset + subj_len]
                info["subject"] = self._parse_x500_name(subj_data)

        except (IndexError, struct.error):
            pass

        return info

    def _parse_der_length(self, data, offset):
        """Parse DER length field. Returns (length, new_offset)."""
        if offset >= len(data):
            return 0, offset

        first = data[offset]
        offset += 1

        if first < 0x80:
            return first, offset
        elif first == 0x80:
            return 0, offset
        else:
            num_bytes = first & 0x7F
            if offset + num_bytes > len(data):
                return 0, offset
            length = 0
            for i in range(num_bytes):
                length = (length << 8) | data[offset + i]
            return length, offset + num_bytes

    def _is_high_value_target(self, cert_info):
        """Check if certificate indicates a high-value target."""
        text_to_check = ""
        if cert_info.get("subject"):
            text_to_check += cert_info["subject"] + " "
        if cert_info.get("issuer"):
            text_to_check += cert_info["issuer"]

        for pattern in self._high_value_patterns:
            if pattern.search(text_to_check):
                return True
        return False

    def _packet_handler(self, pkt):
        """Process packets for TLS certificate authentication detection."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        tcp = pkt[TCP]
        # Check if on TLS ports
        if tcp.dport not in self.ports and tcp.sport not in self.ports:
            return

        self._packets_processed += 1
        payload = bytes(pkt[Raw].load)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        # Parse TLS record
        record = self._parse_tls_record(payload)
        if record is None:
            return

        content_type, version, length, hs_data = record

        # Only process Handshake messages
        if content_type != self.TLS_HANDSHAKE:
            return

        # Parse handshake messages (may be multiple in one record)
        offset = 0
        while offset < len(hs_data):
            hs = self._parse_handshake_header(hs_data, offset)
            if hs is None:
                break

            hs_type, hs_length, data_offset = hs

            if hs_type == self.HANDSHAKE_CERT_REQUEST:
                # Server is requesting client certificate
                self._handle_cert_request(
                    hs_data, data_offset, hs_length, src_ip, dst_ip, tcp
                )

            elif hs_type == self.HANDSHAKE_CERTIFICATE:
                # Certificate message - check if from client (to server port)
                is_client_cert = tcp.dport in self.ports
                self._handle_certificate(
                    hs_data, data_offset, hs_length,
                    src_ip, dst_ip, tcp, is_client_cert
                )

            offset = data_offset + hs_length

    def _handle_cert_request(self, data, offset, length, src_ip, dst_ip, tcp):
        """Handle a CertificateRequest message from a server."""
        cert_req = self._parse_cert_request(data, offset)

        session_key = (dst_ip, src_ip, tcp.dport)
        self._sessions[session_key] = {
            "cert_request": True,
            "cert_types": cert_req["cert_types"],
            "ca_names": cert_req["ca_names"],
            "timestamp": time.time()
        }

        detection = {
            "type": "certificate_request",
            "server_ip": src_ip,
            "client_ip": dst_ip,
            "server_port": tcp.sport,
            "cert_types": cert_req["cert_types"],
            "acceptable_cas": cert_req["ca_names"][:5],  # Limit stored CAs
            "timestamp": time.time(),
            "high_value": False,
        }

        # Check if any acceptable CA indicates high-value
        for ca in cert_req["ca_names"]:
            if any(p.search(ca) for p in self._high_value_patterns):
                detection["high_value"] = True
                break

        with self._lock:
            self._detections.append(detection)

        log.warning(
            f"TLS CertificateRequest from {src_ip}:{tcp.sport} -> {dst_ip} "
            f"(types={cert_req['cert_types']}, CAs={len(cert_req['ca_names'])})"
        )

    def _handle_certificate(self, data, offset, length, src_ip, dst_ip, tcp, is_client_cert):
        """Handle a Certificate message."""
        certs = self._parse_certificate_message(data, offset)

        if not certs:
            return

        # Only interested in client certificates for auth detection
        if not is_client_cert:
            return

        # Parse the first (end-entity) certificate
        cert_info = self._extract_cert_info(certs[0])
        if not cert_info.get("subject"):
            return

        is_high_value = self._is_high_value_target(cert_info)

        detection = {
            "type": "client_certificate",
            "client_ip": src_ip,
            "server_ip": dst_ip,
            "server_port": tcp.dport,
            "subject": cert_info.get("subject"),
            "issuer": cert_info.get("issuer"),
            "serial": cert_info.get("serial"),
            "chain_length": len(certs),
            "timestamp": time.time(),
            "high_value": is_high_value,
        }

        with self._lock:
            self._detections.append(detection)

        level = "critical" if is_high_value else "warning"
        getattr(log, level)(
            f"CLIENT CERT AUTH: {cert_info['subject']} "
            f"(issuer={cert_info['issuer']}, serial={cert_info['serial']}) "
            f"from {src_ip} -> {dst_ip}:{tcp.dport}"
            f"{' [HIGH VALUE]' if is_high_value else ''}"
        )

    def _sniff_loop(self):
        """Background sniffing thread."""
        port_filter = " or ".join(f"tcp port {p}" for p in self.ports)
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                filter=port_filter,
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"Cert auth detector sniff error: {e}")

    def start(self):
        """Start certificate auth detection."""
        if self._running:
            log.warning("Cert auth detector already running")
            return False

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        log.info(f"Certificate auth detector started on {self.interface}")
        return True

    def stop(self):
        """Stop certificate auth detection."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"Cert auth detector stopped. {len(self._detections)} detections")

    def get_detections(self):
        """Return all certificate auth detections."""
        with self._lock:
            return list(self._detections)

    def get_client_certs(self):
        """Return only client certificate detections."""
        with self._lock:
            return [d for d in self._detections if d["type"] == "client_certificate"]

    def get_cert_requests(self):
        """Return only CertificateRequest detections."""
        with self._lock:
            return [d for d in self._detections if d["type"] == "certificate_request"]

    def get_high_value_targets(self):
        """Return detections flagged as high-value targets."""
        with self._lock:
            return [d for d in self._detections if d.get("high_value")]

    def get_stats(self):
        """Return cert auth detection statistics."""
        with self._lock:
            by_type = defaultdict(int)
            high_value_count = 0
            for d in self._detections:
                by_type[d["type"]] += 1
                if d.get("high_value"):
                    high_value_count += 1

            return {
                "running": self._running,
                "total_detections": len(self._detections),
                "client_certificates": by_type.get("client_certificate", 0),
                "certificate_requests": by_type.get("certificate_request", 0),
                "high_value_targets": high_value_count,
                "packets_processed": self._packets_processed,
                "active_sessions": len(self._sessions),
            }
