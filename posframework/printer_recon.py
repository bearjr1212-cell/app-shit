"""
Printer Reconnaissance Module
──────────────────────────────
Discovers network printers via passive and active scanning methods.

Features:
  - Passive scanning via mDNS (port 5353) and LLMNR broadcasts
  - Fingerprinting printers from HTTP banners (ports 80/443/9100)
  - SNMP-based extraction of printer metadata (port 161)
  - Firmware version detection for vulnerability assessment
  - Manufacturer mapping (HP, Canon, Xerox, Brother, Epson)
"""

import time
import socket
import struct
import threading
from collections import defaultdict

from scapy.all import sniff, IP, UDP, Raw

from .config import IS_WINDOWS, IS_LINUX, log


# Known printer manufacturer signatures
PRINTER_SIGNATURES = {
    "HP": ["hp", "hewlett", "laserjet", "officejet", "deskjet", "envy", "pagewide"],
    "Canon": ["canon", "pixma", "imagerunner", "imageclass"],
    "Xerox": ["xerox", "phaser", "workcentre", "versalink", "altalink"],
    "Brother": ["brother", "mfc-", "hl-", "dcp-"],
    "Epson": ["epson", "workforce", "ecotank", "expression"],
    "Lexmark": ["lexmark"],
    "Ricoh": ["ricoh", "aficio"],
    "Samsung": ["samsung", "xpress"],
    "Kyocera": ["kyocera", "ecosys", "taskalfa"],
    "Konica": ["konica", "minolta", "bizhub"],
}

# SNMP OIDs for printer information
SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "hrDeviceDescr": "1.3.6.1.2.1.25.3.2.1.3.1",
    "prtGeneralSerialNumber": "1.3.6.1.2.1.43.5.1.1.17.1",
    "prtGeneralModelName": "1.3.6.1.2.1.43.5.1.1.16.1",
    "prtGeneralFirmware": "1.3.6.1.2.1.43.5.1.1.15.1",
}


class PrinterRecon:
    """
    Network printer discovery and fingerprinting module.
    Uses mDNS, SNMP, and HTTP to discover and identify printers.
    """

    def __init__(self, interface, db=None):
        self.interface = interface
        self.db = db
        self.running = False
        self._thread = None
        self._discovered_printers = {}
        self._lock = threading.Lock()

    def start(self):
        """Start passive printer discovery via mDNS/LLMNR sniffing."""
        self.running = True
        self._thread = threading.Thread(target=self._scan_mdns, daemon=True)
        self._thread.start()
        log.info("PrinterRecon: Passive printer discovery started")

    def stop(self):
        """Stop printer discovery."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"PrinterRecon: Stopped. Discovered {len(self._discovered_printers)} printers")

    def _scan_mdns(self):
        """Passively sniff mDNS (port 5353) and LLMNR for printer announcements."""
        try:
            sniff(
                iface=self.interface,
                filter="udp port 5353 or udp port 5355",
                prn=self._process_mdns_packet,
                store=False,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            log.error(f"PrinterRecon: mDNS sniff error: {e}")

    def _process_mdns_packet(self, pkt):
        """Process mDNS/LLMNR packets looking for printer services."""
        if not pkt.haslayer(Raw) or not pkt.haslayer(IP):
            return

        try:
            payload = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src

            # Look for printer service types in mDNS announcements
            printer_services = [
                b"_ipp._tcp", b"_ipps._tcp", b"_printer._tcp",
                b"_pdl-datastream._tcp", b"_http._tcp",
            ]

            for service in printer_services:
                if service in payload:
                    self._on_printer_discovered(src_ip, payload)
                    break
        except Exception as e:
            log.debug(f"PrinterRecon: Error processing mDNS packet: {e}")

    def _on_printer_discovered(self, ip, mdns_payload):
        """Handle a discovered printer from mDNS."""
        with self._lock:
            if ip in self._discovered_printers:
                return

            printer_info = {
                "ip": ip,
                "hostname": self._extract_hostname(mdns_payload),
                "model": None,
                "manufacturer": None,
                "serial": None,
                "firmware_version": None,
                "discovery_time": time.time(),
                "discovery_method": "mDNS",
            }

            self._discovered_printers[ip] = printer_info
            log.info(f"PrinterRecon: Discovered printer at {ip}")

            # Launch background fingerprinting
            threading.Thread(
                target=self._fingerprint_printer, args=(ip,), daemon=True
            ).start()

    def _extract_hostname(self, payload):
        """Extract hostname from mDNS payload."""
        try:
            # Look for .local suffix in mDNS response
            idx = payload.find(b".local")
            if idx > 0:
                # Walk backwards to find start of name
                start = max(0, idx - 64)
                segment = payload[start:idx]
                # Find printable name
                name_chars = []
                for b in reversed(segment):
                    if 32 <= b <= 126:
                        name_chars.insert(0, chr(b))
                    else:
                        break
                if name_chars:
                    return "".join(name_chars)
        except Exception:
            pass
        return None

    def _fingerprint_printer(self, ip):
        """Run active fingerprinting (SNMP + HTTP) on a discovered printer."""
        self._scan_snmp(ip)
        self._fingerprint_http(ip)

        # Store in database if available
        if self.db and ip in self._discovered_printers:
            info = self._discovered_printers[ip]
            try:
                self.db.log_printer(
                    ip=ip,
                    model=info.get("model"),
                    manufacturer=info.get("manufacturer"),
                    hostname=info.get("hostname"),
                    serial=info.get("serial"),
                    firmware=info.get("firmware_version"),
                    ssid=None,
                    bssid=None,
                    default_creds=0,
                    vulns=None,
                )
            except Exception as e:
                log.error(f"PrinterRecon: DB error for {ip}: {e}")

    def _scan_snmp(self, target_ip):
        """Query SNMP on target for printer details (port 161)."""
        community = b"public"

        for oid_name, oid in SNMP_OIDS.items():
            try:
                # Build SNMP GET request
                snmp_packet = self._build_snmp_get(community, oid)

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(snmp_packet, (target_ip, 161))

                data, _ = sock.recvfrom(4096)
                sock.close()

                value = self._parse_snmp_response(data)
                if value:
                    self._update_printer_from_snmp(target_ip, oid_name, value)

            except socket.timeout:
                break  # Printer likely does not support SNMP
            except Exception as e:
                log.debug(f"PrinterRecon: SNMP error for {target_ip}/{oid_name}: {e}")

    def _build_snmp_get(self, community, oid):
        """Build a simple SNMPv1 GET request packet."""
        # Encode OID
        oid_parts = [int(x) for x in oid.split(".")]
        encoded_oid = bytes([0x06, len(oid_parts) + 1])
        # First two OID components are encoded specially
        encoded_oid += bytes([oid_parts[0] * 40 + oid_parts[1]])
        for part in oid_parts[2:]:
            if part < 128:
                encoded_oid += bytes([part])
            else:
                # Multi-byte encoding
                high = (part >> 7) | 0x80
                low = part & 0x7F
                encoded_oid += bytes([high, low])

        # Variable binding: OID + NULL value
        varbind = encoded_oid + b"\x05\x00"
        varbind_seq = b"\x30" + bytes([len(varbind)]) + varbind
        varbind_list = b"\x30" + bytes([len(varbind_seq)]) + varbind_seq

        # PDU: GET request (0xA0)
        request_id = b"\x02\x01\x01"  # Integer: 1
        error_status = b"\x02\x01\x00"
        error_index = b"\x02\x01\x00"
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = b"\xA0" + bytes([len(pdu_content)]) + pdu_content

        # SNMP message: version + community + PDU
        version = b"\x02\x01\x00"  # SNMPv1
        community_enc = b"\x04" + bytes([len(community)]) + community
        message_content = version + community_enc + pdu
        message = b"\x30" + bytes([len(message_content)]) + message_content

        return message

    def _parse_snmp_response(self, data):
        """Parse SNMP response and extract the value string."""
        try:
            # Look for OctetString (0x04) values in response
            idx = 0
            while idx < len(data) - 2:
                if data[idx] == 0x04 and idx > 20:  # Skip community string
                    length = data[idx + 1]
                    if 0 < length < 200:
                        value = data[idx + 2: idx + 2 + length]
                        try:
                            return value.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            pass
                idx += 1
        except Exception:
            pass
        return None

    def _update_printer_from_snmp(self, ip, oid_name, value):
        """Update printer info from SNMP response."""
        with self._lock:
            if ip not in self._discovered_printers:
                self._discovered_printers[ip] = {
                    "ip": ip, "hostname": None, "model": None,
                    "manufacturer": None, "serial": None,
                    "firmware_version": None, "discovery_time": time.time(),
                    "discovery_method": "SNMP",
                }

            info = self._discovered_printers[ip]

            if oid_name == "sysName":
                info["hostname"] = value
            elif oid_name in ("sysDescr", "hrDeviceDescr"):
                info["model"] = value
                info["manufacturer"] = self._identify_manufacturer(value)
            elif oid_name == "prtGeneralSerialNumber":
                info["serial"] = value
            elif oid_name == "prtGeneralModelName":
                info["model"] = value
                info["manufacturer"] = self._identify_manufacturer(value)
            elif oid_name == "prtGeneralFirmware":
                info["firmware_version"] = value

            log.debug(f"PrinterRecon: SNMP {ip} {oid_name}={value}")

    def _fingerprint_http(self, target_ip):
        """Fingerprint printer via HTTP banner on ports 80, 443, 9100."""
        for port in (80, 9100, 443):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target_ip, port))

                # Send HTTP GET request
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())

                response = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if len(response) > 8192:
                            break
                    except socket.timeout:
                        break

                sock.close()

                if response:
                    self._parse_http_banner(target_ip, response, port)
                    break  # Got a response, no need to try other ports

            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
            except Exception as e:
                log.debug(f"PrinterRecon: HTTP error for {target_ip}:{port}: {e}")

    def _parse_http_banner(self, ip, response, port):
        """Parse HTTP response headers and body for printer info."""
        try:
            response_str = response.decode("utf-8", errors="ignore")

            # Extract Server header
            server = None
            for line in response_str.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break

            with self._lock:
                if ip not in self._discovered_printers:
                    self._discovered_printers[ip] = {
                        "ip": ip, "hostname": None, "model": None,
                        "manufacturer": None, "serial": None,
                        "firmware_version": None, "discovery_time": time.time(),
                        "discovery_method": "HTTP",
                    }

                info = self._discovered_printers[ip]

                if server:
                    manufacturer = self._identify_manufacturer(server)
                    if manufacturer:
                        info["manufacturer"] = manufacturer
                    if not info["model"]:
                        info["model"] = server

                # Try to extract model from HTML title or body
                title_start = response_str.find("<title>")
                title_end = response_str.find("</title>")
                if title_start > 0 and title_end > title_start:
                    title = response_str[title_start + 7:title_end].strip()
                    if title and not info["model"]:
                        info["model"] = title
                    manufacturer = self._identify_manufacturer(title)
                    if manufacturer:
                        info["manufacturer"] = manufacturer

            log.debug(f"PrinterRecon: HTTP banner from {ip}:{port} - {server}")

        except Exception as e:
            log.debug(f"PrinterRecon: HTTP parse error for {ip}: {e}")

    def _identify_manufacturer(self, text):
        """Identify printer manufacturer from text string."""
        if not text:
            return None
        text_lower = text.lower()
        for manufacturer, keywords in PRINTER_SIGNATURES.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return manufacturer
        return None

    def get_printers(self):
        """Return list of discovered printers."""
        with self._lock:
            return list(self._discovered_printers.values())

    def get_stats(self):
        """Return printer discovery statistics."""
        with self._lock:
            manufacturers = defaultdict(int)
            for info in self._discovered_printers.values():
                mfg = info.get("manufacturer") or "Unknown"
                manufacturers[mfg] += 1

            return {
                "printers_discovered": len(self._discovered_printers),
                "manufacturers": dict(manufacturers),
                "running": self.running,
            }
