"""
Network Segmentation Mapper
────────────────────────────
Combines VLAN discovery, ARP scans, port scanning, and inter-VLAN
routing analysis to produce a comprehensive network segmentation map.

Identifies:
  - VLANs and their IP ranges
  - Hosts per VLAN with service fingerprints
  - Inter-VLAN routing paths and gateways
  - ACL gaps (ports accessible across VLANs that should not be)
  - High-value segments (management, payment, guest)

Exports structured JSON for visualization and further analysis.
"""

import json
import time
import socket
import threading
from datetime import datetime

from scapy.all import (
    Ether, Dot1Q, ARP, IP, TCP, ICMP, sr1, sendp, sniff, conf
)

from .config import log


# Common ports for service detection
DEFAULT_SCAN_PORTS = [22, 80, 443, 445, 3389, 3306, 5432, 8080, 8443]

# Ports that indicate specific segment types
MANAGEMENT_PORTS = {22, 23, 161, 162, 830, 8291}  # SSH, Telnet, SNMP, NETCONF, WinBox
PAYMENT_PORTS = {443, 8443, 9100, 4100, 20000}    # POS common ports
GUEST_INDICATORS = set()  # guest VLANs identified by limited services


class NetworkSegmentationMapper:
    """
    Build a complete network segmentation map by combining VLAN
    discovery data, per-VLAN host discovery, service detection,
    inter-VLAN routing analysis, and ACL gap identification.
    """

    def __init__(self, interface, db=None, vlan_scanner=None,
                 scan_ports=None, scan_timeout=2, max_threads=20):
        self.interface = interface
        self.db = db
        self.vlan_scanner = vlan_scanner
        self.scan_ports = scan_ports or DEFAULT_SCAN_PORTS
        self.scan_timeout = scan_timeout
        self.max_threads = max_threads

        self._running = False
        self._lock = threading.Lock()

        # Mapping results
        self._segments = {}       # vlan_id -> segment info
        self._routes = []         # inter-VLAN routes
        self._acl_gaps = []       # detected ACL gaps
        self._high_value = []     # high-value targets
        self._hosts = {}          # vlan_id -> [{host, ports, services}]
        self._reachability = {}   # (src_vlan, dst_vlan) -> [reachable_ports]

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    def start(self):
        """Start the network mapping process."""
        if self._running:
            log.warning("NetworkSegmentationMapper already running")
            return

        self._running = True
        log.info(f"NetworkSegmentationMapper starting on {self.interface}")
        log.info(f"Scan ports: {self.scan_ports}")

    def stop(self):
        """Stop mapper and persist results to database."""
        self._running = False
        self._persist_results()
        log.info(f"NetworkSegmentationMapper stopped: "
                 f"{len(self._segments)} segments mapped, "
                 f"{len(self._routes)} routes, "
                 f"{len(self._acl_gaps)} ACL gaps")

    # ─── Scanning Methods ────────────────────────────────────────────────────

    def scan_segment(self, vlan_id, ip_range=None):
        """
        Scan a single VLAN segment: discover hosts, detect services,
        and classify the segment type.

        Args:
            vlan_id: VLAN ID to scan
            ip_range: IP range (CIDR) to scan within the VLAN.
                      If None, attempts to use known range from vlan_scanner.

        Returns:
            Segment info dict with hosts, services, and classification
        """
        if not self._running:
            self._running = True

        # Resolve IP range
        if ip_range is None and self.vlan_scanner:
            vlans = self.vlan_scanner.get_vlans()
            vlan_info = vlans.get(vlan_id, {})
            ip_range = vlan_info.get("ip_range")

        if not ip_range:
            log.warning(f"No IP range for VLAN {vlan_id}, skipping")
            return None

        log.info(f"Scanning segment VLAN {vlan_id} ({ip_range})...")

        # Phase 1: ARP discovery
        hosts = self._arp_sweep(vlan_id, ip_range)

        # Phase 2: Port scan discovered hosts
        host_details = []
        threads = []
        results_lock = threading.Lock()

        for host_ip in hosts:
            if not self._running:
                break
            t = threading.Thread(
                target=self._scan_host_services,
                args=(host_ip, host_details, results_lock),
                daemon=True
            )
            t.start()
            threads.append(t)

            # Limit concurrency
            if len(threads) >= self.max_threads:
                for tt in threads:
                    tt.join(timeout=self.scan_timeout + 5)
                threads = []

        for t in threads:
            t.join(timeout=self.scan_timeout + 5)

        # Phase 3: Classify segment
        segment_type = self._classify_segment(host_details)

        # Build segment record
        all_services = []
        for h in host_details:
            all_services.extend(h.get("services", []))

        segment = {
            "vlan_id": vlan_id,
            "ip_range": ip_range,
            "hosts_discovered": len(hosts),
            "hosts": host_details,
            "services": list(set(all_services)),
            "segment_type": segment_type,
            "acl_gaps": [],
            "first_seen": datetime.now().isoformat(timespec="seconds"),
        }

        with self._lock:
            self._segments[vlan_id] = segment
            self._hosts[vlan_id] = host_details

            # Identify high-value targets
            for h in host_details:
                if self._is_high_value(h, segment_type):
                    self._high_value.append({
                        "host": h["host"],
                        "vlan_id": vlan_id,
                        "services": h.get("services", []),
                        "reason": segment_type,
                    })

        log.info(f"VLAN {vlan_id}: {len(hosts)} hosts, "
                 f"{len(all_services)} services, type={segment_type}")

        return segment

    def map_all(self):
        """
        Map all known VLANs: scan each segment, detect inter-VLAN
        routing, and identify ACL gaps.

        Returns:
            Complete segmentation map dict
        """
        if not self._running:
            self._running = True

        log.info("Starting full network segmentation mapping...")

        # Get known VLANs
        vlans = {}
        if self.vlan_scanner:
            vlans = self.vlan_scanner.get_vlans()
        elif self.db:
            db_vlans = self.db.get_vlans()
            for v in db_vlans:
                vlans[v["vlan_id"]] = v

        if not vlans:
            log.warning("No VLANs known - run VLANScanner first")
            return self.get_map()

        # Scan each VLAN segment
        for vlan_id, vlan_info in vlans.items():
            if not self._running:
                break
            ip_range = vlan_info.get("ip_range")
            self.scan_segment(vlan_id, ip_range=ip_range)

        # Detect inter-VLAN routing
        self._detect_inter_vlan_routing()

        # Detect ACL gaps
        self._detect_acl_gaps()

        # Persist results
        self._persist_results()

        log.info(f"Mapping complete: {len(self._segments)} segments, "
                 f"{len(self._routes)} routes, "
                 f"{len(self._acl_gaps)} ACL gaps, "
                 f"{len(self._high_value)} high-value targets")

        return self.get_map()

    # ─── Inter-VLAN Routing Detection ────────────────────────────────────────

    def _detect_inter_vlan_routing(self):
        """
        Detect inter-VLAN routing by sending probes from one VLAN
        to hosts in other VLANs. If response received, routing exists.
        """
        vlan_ids = list(self._segments.keys())

        if len(vlan_ids) < 2:
            return

        log.info(f"Detecting inter-VLAN routing across "
                 f"{len(vlan_ids)} VLANs...")

        for i, src_vlan in enumerate(vlan_ids):
            for dst_vlan in vlan_ids[i + 1:]:
                if not self._running:
                    return

                # Get a sample host from dst_vlan
                dst_hosts = self._hosts.get(dst_vlan, [])
                if not dst_hosts:
                    continue

                target_ip = dst_hosts[0]["host"]
                route_detected = False
                gateway_ip = None

                # Send ICMP probe
                try:
                    probe = (
                        IP(dst=target_ip) /
                        ICMP()
                    )
                    reply = sr1(probe, iface=self.interface,
                                timeout=self.scan_timeout, verbose=False)
                    if reply:
                        route_detected = True
                        # Gateway is likely the src of the reply if different
                        if reply.haslayer(IP):
                            gateway_ip = reply[IP].src
                except Exception:
                    pass

                # Try TCP SYN to a known open port
                if not route_detected:
                    for host_info in dst_hosts:
                        open_ports = host_info.get("open_ports", [])
                        if open_ports:
                            try:
                                probe = (
                                    IP(dst=host_info["host"]) /
                                    TCP(dport=open_ports[0], flags="S")
                                )
                                reply = sr1(probe, iface=self.interface,
                                            timeout=self.scan_timeout,
                                            verbose=False)
                                if reply:
                                    route_detected = True
                                    break
                            except Exception:
                                pass

                if route_detected:
                    route = {
                        "src_vlan": src_vlan,
                        "dst_vlan": dst_vlan,
                        "route_type": "routed",
                        "gateway_ip": gateway_ip,
                        "bidirectional": 1,
                        "discovered_at": datetime.now().isoformat(
                            timespec="seconds"),
                    }
                    with self._lock:
                        self._routes.append(route)
                    log.info(f"Route detected: VLAN {src_vlan} <-> "
                             f"VLAN {dst_vlan} (gw={gateway_ip})")

    def _detect_acl_gaps(self):
        """
        Identify ACL gaps by testing port reachability across VLANs.
        Ports accessible across VLANs that should not be (e.g., management
        ports reachable from guest VLAN) indicate misconfigured ACLs.
        """
        vlan_ids = list(self._segments.keys())

        if len(vlan_ids) < 2:
            return

        log.info("Testing for ACL gaps across VLAN boundaries...")

        sensitive_ports = [22, 23, 445, 3389, 3306, 5432, 161]

        for src_vlan in vlan_ids:
            src_type = self._segments[src_vlan].get("segment_type", "unknown")

            for dst_vlan in vlan_ids:
                if src_vlan == dst_vlan:
                    continue
                if not self._running:
                    return

                dst_type = self._segments[dst_vlan].get("segment_type", "unknown")
                dst_hosts = self._hosts.get(dst_vlan, [])

                # Test sensitive ports from less-trusted to more-trusted
                if src_type == "guest" or (src_type == "unknown" and
                                           dst_type in ("management", "payment")):
                    for host_info in dst_hosts[:3]:  # sample
                        reachable = self._test_ports(
                            host_info["host"], sensitive_ports)
                        if reachable:
                            gap = {
                                "src_vlan": src_vlan,
                                "src_type": src_type,
                                "dst_vlan": dst_vlan,
                                "dst_type": dst_type,
                                "dst_host": host_info["host"],
                                "accessible_ports": reachable,
                                "severity": "high" if dst_type == "payment" else "medium",
                                "description": (
                                    f"Ports {reachable} accessible from "
                                    f"{src_type} VLAN {src_vlan} to "
                                    f"{dst_type} VLAN {dst_vlan}"
                                ),
                            }
                            with self._lock:
                                self._acl_gaps.append(gap)
                            log.warning(
                                f"ACL GAP: {src_type} VLAN {src_vlan} -> "
                                f"{dst_type} VLAN {dst_vlan} "
                                f"ports {reachable}")

    # ─── Getters ─────────────────────────────────────────────────────────────

    def get_map(self):
        """Return the complete segmentation map as a structured dict."""
        with self._lock:
            return {
                "vlans": list(self._segments.values()),
                "segments": [
                    {
                        "vlan_id": s["vlan_id"],
                        "ip_range": s["ip_range"],
                        "hosts_discovered": s["hosts_discovered"],
                        "segment_type": s["segment_type"],
                        "services": s["services"],
                    }
                    for s in self._segments.values()
                ],
                "routes": list(self._routes),
                "acl_gaps": list(self._acl_gaps),
                "high_value_targets": list(self._high_value),
                "mapped_at": datetime.now().isoformat(timespec="seconds"),
            }

    def export_map(self, format="json", output_path=None):
        """
        Export the segmentation map in the specified format.

        Args:
            format: Output format ('json' supported)
            output_path: File path to write to (optional)

        Returns:
            Serialized map string (JSON)
        """
        seg_map = self.get_map()

        if format == "json":
            result = json.dumps(seg_map, indent=2, default=str)
        else:
            log.warning(f"Unsupported export format: {format}, using JSON")
            result = json.dumps(seg_map, indent=2, default=str)

        if output_path:
            try:
                with open(output_path, "w") as f:
                    f.write(result)
                log.info(f"Map exported to {output_path}")
            except OSError as e:
                log.error(f"Failed to export map: {e}")

        return result

    def get_stats(self):
        """Return mapper statistics."""
        total_hosts = sum(len(h) for h in self._hosts.values())
        return {
            "running": self._running,
            "segments_mapped": len(self._segments),
            "total_hosts": total_hosts,
            "routes_detected": len(self._routes),
            "acl_gaps_found": len(self._acl_gaps),
            "high_value_targets": len(self._high_value),
        }

    # ─── Internal Helpers ────────────────────────────────────────────────────

    def _arp_sweep(self, vlan_id, ip_range):
        """
        Send ARP requests (optionally tagged) across the IP range
        and collect responses.

        Returns:
            List of responding host IPs
        """
        hosts = self._parse_cidr(ip_range)
        discovered = []

        for host_ip in hosts:
            if not self._running:
                break
            try:
                # Send tagged ARP if VLAN != 0/1
                if vlan_id and vlan_id > 1:
                    frame = (
                        Ether(dst="ff:ff:ff:ff:ff:ff") /
                        Dot1Q(vlan=vlan_id) /
                        ARP(pdst=host_ip, op="who-has")
                    )
                else:
                    frame = (
                        Ether(dst="ff:ff:ff:ff:ff:ff") /
                        ARP(pdst=host_ip, op="who-has")
                    )
                sendp(frame, iface=self.interface, verbose=False)
            except Exception:
                pass
            time.sleep(0.005)

        # Sniff for ARP responses
        try:
            responses = sniff(
                iface=self.interface,
                filter="arp",
                timeout=5,
                store=1
            )
            for pkt in responses:
                if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                    src_ip = pkt[ARP].psrc
                    if src_ip not in discovered and src_ip != "0.0.0.0":
                        discovered.append(src_ip)
        except Exception as e:
            log.debug(f"ARP sweep sniff error: {e}")

        return discovered

    def _scan_host_services(self, host_ip, results, results_lock):
        """
        Scan a host for open ports and identify services.

        Args:
            host_ip: IP address to scan
            results: Shared list to append results
            results_lock: Lock for thread-safe appending
        """
        open_ports = []
        services = []

        for port in self.scan_ports:
            if not self._running:
                return
            if self._is_port_open(host_ip, port):
                open_ports.append(port)
                svc = self._identify_service(port)
                services.append(svc)

        host_entry = {
            "host": host_ip,
            "open_ports": open_ports,
            "services": services,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

        with results_lock:
            results.append(host_entry)

    def _is_port_open(self, host, port):
        """Check if a TCP port is open via socket connect."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _test_ports(self, host, ports):
        """Test a list of ports on a host, return list of open ones."""
        reachable = []
        for port in ports:
            if not self._running:
                break
            if self._is_port_open(host, port):
                reachable.append(port)
        return reachable

    def _identify_service(self, port):
        """Map port number to likely service name."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            161: "snmp", 162: "snmp-trap", 389: "ldap",
            443: "https", 445: "smb", 636: "ldaps",
            830: "netconf", 1433: "mssql", 3306: "mysql",
            3389: "rdp", 4100: "pos-service", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8080: "http-proxy",
            8291: "winbox", 8443: "https-alt", 9100: "print",
            20000: "pos-terminal", 27017: "mongodb",
        }
        return services.get(port, f"tcp-{port}")

    def _classify_segment(self, host_details):
        """
        Classify a VLAN segment based on discovered services.

        Returns:
            Segment type string: 'management', 'payment', 'guest',
            'server', or 'workstation'
        """
        all_ports = set()
        for h in host_details:
            all_ports.update(h.get("open_ports", []))

        # Management VLAN: SSH/SNMP/NETCONF access dominant
        mgmt_overlap = all_ports & MANAGEMENT_PORTS
        if len(mgmt_overlap) >= 2:
            return "management"

        # Payment VLAN: POS-specific ports
        payment_overlap = all_ports & PAYMENT_PORTS
        if len(payment_overlap) >= 2:
            return "payment"

        # Server VLAN: databases, web servers
        server_ports = {80, 443, 3306, 5432, 1433, 8080, 8443, 6379, 27017}
        if len(all_ports & server_ports) >= 3:
            return "server"

        # Guest VLAN: only HTTP/HTTPS, no internal services
        if all_ports <= {80, 443, 8080, 8443} and len(all_ports) <= 3:
            return "guest"

        # Workstation: RDP or limited ports
        if 3389 in all_ports and len(all_ports) <= 4:
            return "workstation"

        return "unknown"

    def _is_high_value(self, host_info, segment_type):
        """Determine if a host is a high-value target."""
        if segment_type in ("payment", "management"):
            return True
        # Database servers are always high value
        db_ports = {3306, 5432, 1433, 6379, 27017}
        if set(host_info.get("open_ports", [])) & db_ports:
            return True
        return False

    def _parse_cidr(self, cidr):
        """Parse CIDR to host IP list (max /24)."""
        hosts = []
        try:
            if "/" not in cidr:
                return [cidr]
            base, prefix = cidr.split("/")
            parts = base.split(".")
            if len(parts) != 4:
                return []
            prefix = int(prefix)
            if prefix >= 24:
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
            else:
                # For larger subnets, only scan first /24
                for i in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
        except (ValueError, IndexError):
            pass
        return hosts

    def _persist_results(self):
        """Persist mapping results to database."""
        if not self.db:
            return

        # Store segments
        for vlan_id, seg in self._segments.items():
            try:
                self.db.log_segment(
                    vlan_id=vlan_id,
                    ip_range=seg.get("ip_range"),
                    hosts_discovered=seg.get("hosts_discovered", 0),
                    services=json.dumps(seg.get("services", [])),
                    acl_gaps=json.dumps(seg.get("acl_gaps", [])),
                    segment_type=seg.get("segment_type", "unknown"),
                )
            except Exception as e:
                log.debug(f"Failed to persist segment {vlan_id}: {e}")

        # Store routes
        for route in self._routes:
            try:
                self.db.log_vlan_route(
                    src_vlan=route["src_vlan"],
                    dst_vlan=route["dst_vlan"],
                    route_type=route.get("route_type", "routed"),
                    gateway_ip=route.get("gateway_ip"),
                    bidirectional=route.get("bidirectional", 0),
                )
            except Exception as e:
                log.debug(f"Failed to persist route: {e}")
