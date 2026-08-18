"""
Dynamic Target Queue - Auto-Populated Attack Target List
--------------------------------------------------------
Builds and maintains a prioritized list of attack targets that
dynamically updates from live recon data. Each target is assigned:
  - Attack vectors based on its security profile and characteristics
  - A target type classification (POS, IoT, Enterprise, Consumer, etc.)
  - An attack profile (aggressive, stealth, balanced)

The queue auto-populates as recon discovers new APs and clients,
and ensures prerequisites for each attack vector are met before
the vector is marked as ready.

Usage:
    queue = TargetQueue(db=db)
    queue.refresh()  # Pull latest from DB
    targets = queue.get_prioritized()
    for target in targets:
        print(f"{target['ssid']} - vectors: {target['attack_vectors']}")
"""

import time
from typing import Dict, List, Optional

from .config import log


# Attack vector definitions with their prerequisites
ATTACK_VECTORS = {
    "deauth": {
        "name": "Deauthentication",
        "description": "Disconnect clients from target AP",
        "prerequisites": ["monitor_mode"],
        "applicable_to": ["WPA", "WPA2", "WPA3", "WEP", "OPEN"],
    },
    "handshake_capture": {
        "name": "WPA Handshake Capture",
        "description": "Capture 4-way handshake for offline cracking",
        "prerequisites": ["monitor_mode", "active_clients"],
        "applicable_to": ["WPA", "WPA2"],
    },
    "pmkid_capture": {
        "name": "PMKID Capture",
        "description": "Clientless handshake capture via PMKID",
        "prerequisites": ["monitor_mode", "hcxdumptool"],
        "applicable_to": ["WPA2"],
    },
    "evil_twin": {
        "name": "Evil Twin / AP Clone",
        "description": "Clone AP to intercept client connections",
        "prerequisites": ["monitor_mode", "ap_interface", "hostapd"],
        "applicable_to": ["WPA", "WPA2", "WPA3", "OPEN"],
    },
    "karma": {
        "name": "KARMA Attack",
        "description": "Respond to all probe requests",
        "prerequisites": ["monitor_mode", "ap_interface"],
        "applicable_to": ["WPA", "WPA2", "WPA3", "WEP", "OPEN"],
    },
    "wps_crack": {
        "name": "WPS PIN Brute Force",
        "description": "Crack WPS PIN for network access",
        "prerequisites": ["monitor_mode", "reaver"],
        "applicable_to": ["WPA", "WPA2"],
        "requires_wps": True,
    },
    "dos_attack": {
        "name": "Denial of Service",
        "description": "Disrupt target AP operation",
        "prerequisites": ["monitor_mode"],
        "applicable_to": ["WPA", "WPA2", "WPA3", "WEP", "OPEN"],
    },
    "krack": {
        "name": "KRACK Attack",
        "description": "Key reinstallation attack on WPA2",
        "prerequisites": ["monitor_mode", "active_clients", "handshake_captured"],
        "applicable_to": ["WPA2"],
    },
    "wpa3_downgrade": {
        "name": "WPA3 Downgrade",
        "description": "Force WPA3 clients to connect via WPA2",
        "prerequisites": ["monitor_mode", "ap_interface"],
        "applicable_to": ["WPA3"],
    },
    "credential_harvest": {
        "name": "Credential Harvesting",
        "description": "Capture credentials via captive portal",
        "prerequisites": ["monitor_mode", "ap_interface", "hostapd", "dnsmasq"],
        "applicable_to": ["WPA", "WPA2", "WPA3", "OPEN"],
    },
    "client_isolation_bypass": {
        "name": "Client Isolation Bypass",
        "description": "Bypass AP client isolation to reach other clients",
        "prerequisites": ["monitor_mode"],
        "applicable_to": ["WPA", "WPA2", "WPA3"],
    },
}

# Target type classifications based on characteristics
TARGET_TYPES = {
    "pos": "Point-of-Sale system",
    "iot": "IoT / Embedded device",
    "enterprise": "Enterprise network",
    "consumer": "Consumer WiFi",
    "printer": "Network printer",
    "mobile": "Mobile hotspot",
    "repeater": "WiFi repeater/extender",
}

# Attack profiles determine aggressiveness
ATTACK_PROFILES = {
    "aggressive": {
        "description": "Maximum speed, all vectors enabled, high detection risk",
        "deauth_count": 50,
        "parallel_attacks": True,
        "retry_on_fail": True,
    },
    "balanced": {
        "description": "Mix of speed and stealth, standard vectors",
        "deauth_count": 10,
        "parallel_attacks": False,
        "retry_on_fail": True,
    },
    "stealth": {
        "description": "Slow and quiet, minimal detection footprint",
        "deauth_count": 3,
        "parallel_attacks": False,
        "retry_on_fail": False,
    },
}


class TargetQueue:
    """
    Dynamic target queue that auto-populates from recon data.

    Maintains a prioritized list of targets with assigned attack vectors,
    target types, and attack profiles. Updates dynamically as new recon
    data becomes available.
    """

    def __init__(self, db, attack_profile: str = "balanced"):
        """
        Initialize the target queue.

        Args:
            db: POSDatabase instance with recon data.
            attack_profile: Default attack profile (aggressive/balanced/stealth).
        """
        self.db = db
        self.default_profile = attack_profile
        self._targets: List[Dict] = []
        self._last_refresh = 0.0
        self._available_tools: Dict[str, bool] = {}
        self._detect_available_tools()

    def refresh(self) -> int:
        """
        Refresh the target list from the database.

        Pulls all APs and their clients, classifies each target,
        assigns applicable attack vectors, and prioritizes the list.

        Returns:
            Number of targets in the queue.
        """
        self._targets.clear()

        try:
            self.db.cursor.execute(
                'SELECT bssid, ssid, vendor, channel, security, rssi, '
                'is_pos_vendor, is_pos_ssid, is_hidden '
                'FROM access_points ORDER BY rssi DESC'
            )
            rows = self.db.cursor.fetchall()
        except Exception as e:
            log.debug(f"TargetQueue refresh error: {e}")
            return 0

        for row in rows:
            bssid = row[0]
            ssid = row[1] or "<hidden>"
            vendor = row[2] or "Unknown"
            channel = row[3]
            security = row[4] or "OPEN"
            rssi = row[5] or -100
            is_pos_vendor = bool(row[6])
            is_pos_ssid = bool(row[7])
            is_hidden = bool(row[8])

            # Get client count for this AP
            client_count = 0
            try:
                clients_data = self.db.get_clients_for_bssid(bssid)
                client_count = len(clients_data) if clients_data else 0
            except Exception:
                pass

            # Classify the target
            target_type = self._classify_target(
                vendor, ssid, is_pos_vendor, is_pos_ssid, security
            )

            # Determine applicable attack vectors
            vectors = self._get_applicable_vectors(
                security, client_count, target_type
            )

            # Assign attack profile based on target type
            profile = self._assign_profile(target_type, rssi)

            # Calculate priority score
            priority = self._calculate_priority(
                rssi, is_pos_vendor, is_pos_ssid, client_count,
                len(vectors), target_type
            )

            target = {
                "bssid": bssid,
                "ssid": ssid,
                "vendor": vendor,
                "channel": channel,
                "security": security,
                "rssi": rssi,
                "is_pos": is_pos_vendor or is_pos_ssid,
                "is_hidden": is_hidden,
                "client_count": client_count,
                "target_type": target_type,
                "target_type_desc": TARGET_TYPES.get(target_type, "Unknown"),
                "attack_vectors": vectors,
                "attack_profile": profile,
                "profile_config": ATTACK_PROFILES.get(profile, {}),
                "priority": priority,
                "status": "queued",
            }
            self._targets.append(target)

        # Sort by priority (highest first)
        self._targets.sort(key=lambda t: t["priority"], reverse=True)
        self._last_refresh = time.time()

        log.debug(f"TargetQueue: {len(self._targets)} targets loaded")
        return len(self._targets)

    def get_prioritized(self) -> List[Dict]:
        """Get the full prioritized target list."""
        if not self._targets or (time.time() - self._last_refresh) > 10.0:
            self.refresh()
        return self._targets

    def get_top_targets(self, count: int = 5) -> List[Dict]:
        """Get the top N highest-priority targets."""
        targets = self.get_prioritized()
        return targets[:count]

    def get_ready_targets(self) -> List[Dict]:
        """Get targets where all prerequisites for at least one vector are met."""
        targets = self.get_prioritized()
        ready = []
        for target in targets:
            ready_vectors = [
                v for v in target["attack_vectors"] if v["ready"]
            ]
            if ready_vectors:
                ready.append(target)
        return ready

    def get_target_by_bssid(self, bssid: str) -> Optional[Dict]:
        """Get a specific target by BSSID."""
        for target in self._targets:
            if target["bssid"].upper() == bssid.upper():
                return target
        return None

    def automate_prerequisites(self, target: Dict) -> List[str]:
        """
        Attempt to automate prerequisite steps for a target's attack vectors.

        Checks which prerequisites are missing and attempts to fulfill them
        (e.g., enabling monitor mode, starting hostapd, etc.).

        Args:
            target: Target dict from the queue.

        Returns:
            List of prerequisites that were successfully automated.
        """
        automated = []
        missing_prereqs = set()

        for vector in target.get("attack_vectors", []):
            if not vector["ready"]:
                for prereq in vector.get("missing_prerequisites", []):
                    missing_prereqs.add(prereq)

        for prereq in missing_prereqs:
            success = self._automate_prerequisite(prereq)
            if success:
                automated.append(prereq)
                log.info(f"TargetQueue: Automated prerequisite '{prereq}'")

        # Re-evaluate vectors after automating prerequisites
        if automated:
            self._detect_available_tools()
            # Update attack vectors for this target
            target["attack_vectors"] = self._get_applicable_vectors(
                target["security"], target["client_count"], target["target_type"]
            )

        return automated

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _classify_target(self, vendor: str, ssid: str,
                         is_pos_vendor: bool, is_pos_ssid: bool,
                         security: str) -> str:
        """Classify a target by its characteristics."""
        if is_pos_vendor or is_pos_ssid:
            return "pos"

        vendor_lower = vendor.lower() if vendor else ""
        ssid_lower = ssid.lower() if ssid else ""

        # IoT indicators
        iot_vendors = ["espressif", "tuya", "shenzhen", "xiaomi"]
        iot_ssids = ["iot", "smart", "sensor", "cam", "bulb", "plug"]
        if any(v in vendor_lower for v in iot_vendors):
            return "iot"
        if any(s in ssid_lower for s in iot_ssids):
            return "iot"

        # Enterprise indicators
        if "802.1X" in security or "EAP" in security:
            return "enterprise"
        enterprise_ssids = ["corp", "enterprise", "office", "internal"]
        if any(s in ssid_lower for s in enterprise_ssids):
            return "enterprise"

        # Printer indicators
        printer_vendors = ["hp", "epson", "canon", "brother", "xerox", "ricoh"]
        printer_ssids = ["print", "direct"]
        if any(v in vendor_lower for v in printer_vendors):
            return "printer"
        if any(s in ssid_lower for s in printer_ssids):
            return "printer"

        # Mobile hotspot indicators
        hotspot_ssids = ["iphone", "android", "galaxy", "pixel", "hotspot"]
        if any(s in ssid_lower for s in hotspot_ssids):
            return "mobile"

        # Repeater/extender indicators
        repeater_ssids = ["ext", "repeater", "range"]
        if any(s in ssid_lower for s in repeater_ssids):
            return "repeater"

        return "consumer"

    def _get_applicable_vectors(self, security: str, client_count: int,
                                target_type: str) -> List[Dict]:
        """Determine which attack vectors apply to this target."""
        vectors = []
        security_upper = security.upper() if security else "OPEN"

        for vec_id, vec_def in ATTACK_VECTORS.items():
            # Check if vector applies to this security type
            applicable = False
            for sec_type in vec_def["applicable_to"]:
                if sec_type in security_upper:
                    applicable = True
                    break

            if not applicable:
                continue

            # Check prerequisites
            prereqs = vec_def["prerequisites"]
            missing = []
            for prereq in prereqs:
                if prereq == "active_clients" and client_count == 0:
                    missing.append(prereq)
                elif prereq == "handshake_captured":
                    missing.append(prereq)  # Requires prior capture
                elif prereq not in ("active_clients", "handshake_captured"):
                    if not self._available_tools.get(prereq, False):
                        missing.append(prereq)

            ready = len(missing) == 0

            vectors.append({
                "id": vec_id,
                "name": vec_def["name"],
                "description": vec_def["description"],
                "ready": ready,
                "missing_prerequisites": missing,
                "prerequisites": prereqs,
            })

        return vectors

    def _assign_profile(self, target_type: str, rssi: int) -> str:
        """Assign an attack profile based on target type and signal."""
        # POS targets get aggressive treatment
        if target_type == "pos":
            return "aggressive"
        # Enterprise targets need stealth
        if target_type == "enterprise":
            return "stealth"
        # Weak signals need aggressive to compensate
        if rssi < -75:
            return "aggressive"
        # IoT and printers are easy targets
        if target_type in ("iot", "printer"):
            return "aggressive"
        return "balanced"

    def _calculate_priority(self, rssi: int, is_pos_vendor: bool,
                            is_pos_ssid: bool, client_count: int,
                            vector_count: int, target_type: str) -> float:
        """Calculate priority score for target ordering."""
        score = 0.0

        # POS targets get highest priority
        if is_pos_vendor:
            score += 100
        if is_pos_ssid:
            score += 80

        # Signal strength (closer = higher priority)
        # RSSI ranges from -100 (far) to 0 (closest)
        signal_score = max(0, (rssi + 100)) * 0.5
        score += signal_score

        # More clients = more interesting target
        score += min(client_count * 5, 30)

        # More available attack vectors = easier target
        score += vector_count * 3

        # Target type bonuses
        type_bonuses = {
            "pos": 50,
            "iot": 20,
            "printer": 15,
            "consumer": 10,
            "mobile": 5,
            "enterprise": 25,
            "repeater": 8,
        }
        score += type_bonuses.get(target_type, 0)

        return score

    def _detect_available_tools(self):
        """Detect which tools/capabilities are available."""
        try:
            from .tools import is_available as tool_available
            self._available_tools["monitor_mode"] = True  # Assume if running
            self._available_tools["ap_interface"] = True  # Checked at runtime
            self._available_tools["hostapd"] = tool_available("hostapd")
            self._available_tools["dnsmasq"] = tool_available("dnsmasq")
            self._available_tools["hcxdumptool"] = tool_available("hcxdumptool")
            self._available_tools["reaver"] = tool_available("reaver")
            self._available_tools["aircrack-ng"] = tool_available("aircrack-ng")
            self._available_tools["hashcat"] = tool_available("hashcat")
            self._available_tools["mdk4"] = tool_available("mdk4")
        except ImportError:
            # If tools module is unavailable, assume basic capabilities
            self._available_tools["monitor_mode"] = True
            self._available_tools["ap_interface"] = True

    def _automate_prerequisite(self, prereq: str) -> bool:
        """
        Attempt to automate a single prerequisite step.

        Args:
            prereq: Prerequisite identifier.

        Returns:
            True if successfully automated.
        """
        if prereq == "monitor_mode":
            # Monitor mode should already be active during recon
            return True

        if prereq == "ap_interface":
            # AP interface is a hardware requirement, can't automate
            return True

        if prereq == "active_clients":
            # Can't force clients to appear, but signal this is a soft prereq
            return False

        if prereq == "handshake_captured":
            # Requires a prior deauth + capture, not automatable as a prereq
            return False

        # For tool-based prerequisites, try to check if installable
        tool_install_map = {
            "hostapd": "hostapd",
            "dnsmasq": "dnsmasq",
            "hcxdumptool": "hcxdumptool",
            "reaver": "reaver",
            "aircrack-ng": "aircrack-ng",
            "hashcat": "hashcat",
            "mdk4": "mdk4",
        }

        if prereq in tool_install_map:
            # Check if tool becomes available (maybe it was just not in cache)
            try:
                from .tools import is_available, which
                # Clear cache and recheck
                from .tools import _tool_cache
                _tool_cache.pop(prereq, None)
                if is_available(prereq):
                    self._available_tools[prereq] = True
                    return True
            except Exception:
                pass

            # Tool is genuinely missing - log what would need to be installed
            pkg = tool_install_map.get(prereq, prereq)
            log.info(f"TargetQueue: prerequisite '{prereq}' requires: "
                     f"apt-get install {pkg}")
            return False

        return False
