"""
Client Profiler
---------------
Build per-client profiles with:
  - OS fingerprint (from HTTP User-Agent, TCP window size, TTL)
  - Probed networks (from Dot11ProbeReq)
  - Credentials captured (linked from DB)
  - Handshakes captured
  - Associated APs
  - First/last seen timestamps
  - Device type classification (phone/laptop/IoT/POS)

Integrates with the database for persistence.
"""

import time
import json
import threading
from collections import defaultdict

from .config import log


# OS fingerprinting signatures based on TCP window size and TTL
TCP_OS_SIGNATURES = {
    (65535, 64): "macOS/iOS",
    (65535, 128): "Windows",
    (5840, 64): "Linux",
    (14600, 64): "Linux",
    (29200, 64): "Linux",
    (64240, 128): "Windows 10/11",
    (8192, 128): "Windows XP/7",
    (16384, 64): "Android",
    (32120, 64): "Linux (old)",
}

# Device type classification based on vendor OUI patterns
DEVICE_TYPE_PATTERNS = {
    "phone": [
        "apple", "samsung", "huawei", "xiaomi", "oppo", "oneplus",
        "google", "pixel", "lg", "motorola", "sony mobile"
    ],
    "laptop": [
        "dell", "lenovo", "hp", "asus", "acer", "microsoft surface",
        "thinkpad", "macbook"
    ],
    "iot": [
        "espressif", "tuya", "shenzhen", "nest", "ring", "wyze",
        "sonoff", "tasmota", "amazon echo", "broadlink"
    ],
    "pos": [
        "verifone", "ingenico", "pax", "newland", "castles",
        "square", "clover", "toast"
    ],
    "printer": [
        "hp print", "canon", "epson", "brother", "xerox", "lexmark",
        "ricoh", "konica"
    ],
    "router": [
        "cisco", "netgear", "tp-link", "asus router", "ubiquiti",
        "mikrotik", "linksys"
    ],
}


class ClientProfiler:
    """
    Build and maintain per-client device profiles.

    Processes packets to extract OS fingerprint information, tracks
    probed networks, associates credentials and handshakes, and
    classifies device types.
    """

    def __init__(self, db=None):
        self.db = db
        self._profiles = {}  # mac -> profile dict
        self._lock = threading.Lock()
        self._running = False

    def update_from_packet(self, pkt):
        """
        Update client profile from a captured packet.

        Extracts:
          - Probe requests (probed SSIDs)
          - HTTP User-Agent (OS fingerprint)
          - TCP window/TTL (OS fingerprint)
          - Association (AP linkage)

        Args:
            pkt: Scapy packet
        """
        try:
            self._process_packet(pkt)
        except Exception as e:
            log.debug(f"Client profiler packet error: {e}")

    def _process_packet(self, pkt):
        """Internal packet processing."""
        from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt, Dot11AssoReq
        from scapy.layers.inet import IP, TCP
        from scapy.layers.http import HTTPRequest

        # Probe requests - probed networks
        if pkt.haslayer(Dot11ProbeReq):
            client_mac = pkt.addr2
            if not client_mac:
                return

            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            if elt and elt.ID == 0 and elt.info:
                ssid = elt.info.decode(errors='ignore')

            if ssid:
                with self._lock:
                    profile = self._get_or_create_locked(client_mac)
                    if ssid not in profile["probed_networks"]:
                        profile["probed_networks"].append(ssid)
                    profile["last_seen"] = time.time()

        # Data frames - association tracking
        if pkt.haslayer(Dot11) and pkt.type == 2:
            ds_flags = pkt.FCfield & 0x3
            if ds_flags == 0x1:  # To-DS
                client_mac = pkt.addr2
                bssid = pkt.addr1
            elif ds_flags == 0x2:  # From-DS
                client_mac = pkt.addr1
                bssid = pkt.addr2
            else:
                return

            if client_mac and bssid:
                with self._lock:
                    profile = self._get_or_create_locked(client_mac)
                    if bssid not in profile["associated_aps"]:
                        profile["associated_aps"].append(bssid)
                    profile["last_seen"] = time.time()

        # TCP packets - OS fingerprinting via window size and TTL
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_layer = pkt.getlayer(IP)
            tcp_layer = pkt.getlayer(TCP)

            # Only use SYN packets for fingerprinting (initial connection)
            if tcp_layer.flags & 0x02:  # SYN flag
                src_mac = None
                if pkt.haslayer(Dot11):
                    src_mac = pkt.addr2
                elif hasattr(pkt, 'src'):
                    # Ethernet frame
                    src_mac = pkt.src

                if src_mac:
                    window = tcp_layer.window
                    ttl = ip_layer.ttl
                    os_guess = self._fingerprint_tcp(window, ttl)

                    if os_guess:
                        profile = self._get_or_create(src_mac)
                        with self._lock:
                            profile["os_fingerprint"] = os_guess
                            profile["tcp_window"] = window
                            profile["tcp_ttl"] = ttl

        # HTTP User-Agent extraction
        if pkt.haslayer(TCP):
            try:
                # Check for raw HTTP in payload
                payload = bytes(pkt.getlayer(TCP).payload)
                if payload and b"User-Agent:" in payload:
                    self._extract_user_agent(pkt, payload)
            except (TypeError, AttributeError):
                pass

    def _extract_user_agent(self, pkt, payload):
        """Extract User-Agent header from HTTP payload."""
        try:
            payload_str = payload.decode(errors='ignore')
            for line in payload_str.split("\r\n"):
                if line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()

                    src_mac = None
                    from scapy.layers.dot11 import Dot11
                    if pkt.haslayer(Dot11):
                        src_mac = pkt.addr2
                    elif hasattr(pkt, 'src'):
                        src_mac = pkt.src

                    if src_mac and ua:
                        profile = self._get_or_create(src_mac)
                        with self._lock:
                            profile["user_agent"] = ua
                            profile["os_fingerprint"] = self._parse_user_agent(ua)
                            profile["device_type"] = self._classify_from_ua(ua)
                    break
        except (UnicodeDecodeError, AttributeError):
            pass

    def _fingerprint_tcp(self, window, ttl):
        """Fingerprint OS from TCP window size and TTL."""
        # Normalize TTL to initial value
        if ttl <= 64:
            init_ttl = 64
        elif ttl <= 128:
            init_ttl = 128
        else:
            init_ttl = 255

        # Exact match
        sig = (window, init_ttl)
        if sig in TCP_OS_SIGNATURES:
            return TCP_OS_SIGNATURES[sig]

        # Heuristic based on TTL alone
        if init_ttl == 128:
            return "Windows"
        elif init_ttl == 64:
            if window > 60000:
                return "macOS/iOS"
            else:
                return "Linux/Android"

        return None

    def _parse_user_agent(self, ua):
        """Parse User-Agent string for OS identification."""
        ua_lower = ua.lower()

        if "windows nt 10" in ua_lower:
            return "Windows 10/11"
        elif "windows nt 6.3" in ua_lower:
            return "Windows 8.1"
        elif "windows nt 6.1" in ua_lower:
            return "Windows 7"
        elif "windows" in ua_lower:
            return "Windows"
        elif "mac os x" in ua_lower or "macintosh" in ua_lower:
            return "macOS"
        elif "iphone" in ua_lower:
            return "iOS (iPhone)"
        elif "ipad" in ua_lower:
            return "iOS (iPad)"
        elif "android" in ua_lower:
            return "Android"
        elif "linux" in ua_lower:
            return "Linux"
        elif "cros" in ua_lower:
            return "ChromeOS"

        return "Unknown"

    def _classify_from_ua(self, ua):
        """Classify device type from User-Agent."""
        ua_lower = ua.lower()

        if any(kw in ua_lower for kw in ["iphone", "android", "mobile"]):
            return "phone"
        elif any(kw in ua_lower for kw in ["ipad", "tablet"]):
            return "tablet"
        elif any(kw in ua_lower for kw in ["bot", "crawler", "spider"]):
            return "bot"
        elif any(kw in ua_lower for kw in ["smart-tv", "webos", "tizen"]):
            return "smart_tv"
        else:
            return "laptop"

    def _get_or_create(self, mac):
        """Get or create a profile for a MAC address."""
        mac = mac.lower()
        with self._lock:
            return self._get_or_create_locked(mac)

    def _get_or_create_locked(self, mac):
        """Get or create a profile for a MAC address. Caller must hold self._lock."""
        mac = mac.lower()
        if mac not in self._profiles:
            self._profiles[mac] = {
                "mac": mac,
                "os_fingerprint": None,
                "user_agent": None,
                "tcp_window": None,
                "tcp_ttl": None,
                "device_type": "unknown",
                "vendor": None,
                "probed_networks": [],
                "associated_aps": [],
                "credentials_captured": [],
                "handshakes_captured": [],
                "first_seen": time.time(),
                "last_seen": time.time(),
            }
        return self._profiles[mac]

    def classify_device_type(self, mac, vendor=None):
        """
        Classify device type based on vendor, OS fingerprint, and behavior.

        Args:
            mac: Client MAC address
            vendor: OUI vendor string (optional)

        Returns:
            Device type string
        """
        profile = self._get_or_create(mac)

        # Check vendor-based classification
        if vendor:
            vendor_lower = vendor.lower()
            for device_type, patterns in DEVICE_TYPE_PATTERNS.items():
                if any(p in vendor_lower for p in patterns):
                    with self._lock:
                        profile["device_type"] = device_type
                        profile["vendor"] = vendor
                    return device_type

        # Use existing fingerprint data
        with self._lock:
            if profile["device_type"] != "unknown":
                return profile["device_type"]

            # Classify from probed networks heuristic
            probed = profile.get("probed_networks", [])
            if len(probed) > 10:
                profile["device_type"] = "phone"  # Phones probe many networks
            elif any("POS" in s or "Square" in s for s in probed):
                profile["device_type"] = "pos"

            return profile["device_type"]

    def add_credential(self, mac, credential_info):
        """Link a captured credential to a client profile."""
        profile = self._get_or_create(mac)
        with self._lock:
            profile["credentials_captured"].append(credential_info)

    def add_handshake(self, mac, handshake_info):
        """Link a captured handshake to a client profile."""
        profile = self._get_or_create(mac)
        with self._lock:
            profile["handshakes_captured"].append(handshake_info)

    def get_profile(self, mac):
        """
        Get the profile for a specific client MAC.

        Args:
            mac: Client MAC address

        Returns:
            Profile dictionary or None if not found
        """
        mac = mac.lower()
        with self._lock:
            return self._profiles.get(mac)

    def get_all_profiles(self):
        """Return all client profiles."""
        with self._lock:
            return dict(self._profiles)

    def export_profiles(self, filepath=None):
        """
        Export all profiles to JSON.

        Args:
            filepath: Optional file path (default: exports/client_profiles.json)

        Returns:
            JSON string of all profiles
        """
        import os

        if filepath is None:
            os.makedirs("exports", exist_ok=True)
            filepath = "exports/client_profiles.json"

        with self._lock:
            data = dict(self._profiles)

        json_str = json.dumps(data, indent=2, default=str)

        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(json_str)
            log.info(f"Exported {len(data)} client profiles to {filepath}")
        except OSError as e:
            log.error(f"Failed to export profiles: {e}")

        return json_str

    def save_to_db(self):
        """Persist all profiles to database."""
        if not self.db:
            return

        with self._lock:
            for mac, profile in self._profiles.items():
                try:
                    self.db.store_client_profile(
                        mac=mac,
                        os_fingerprint=profile.get("os_fingerprint", ""),
                        device_type=profile.get("device_type", "unknown"),
                        probed_networks=json.dumps(profile.get("probed_networks", [])),
                        first_seen=profile.get("first_seen", 0),
                        last_seen=profile.get("last_seen", 0),
                    )
                except Exception as e:
                    log.error(f"Failed to save profile for {mac}: {e}")

    def get_stats(self):
        """Return profiler statistics."""
        with self._lock:
            total = len(self._profiles)
            with_os = sum(1 for p in self._profiles.values() if p.get("os_fingerprint"))
            device_types = defaultdict(int)
            for p in self._profiles.values():
                device_types[p.get("device_type", "unknown")] += 1

            return {
                "total_clients": total,
                "with_os_fingerprint": with_os,
                "device_types": dict(device_types),
                "total_probed_networks": sum(
                    len(p.get("probed_networks", []))
                    for p in self._profiles.values()
                ),
            }
