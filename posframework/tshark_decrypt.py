"""
tshark Decryption Engine
────────────────────────
Lists tshark decryption capabilities and integrates live decryption
during reconnaissance. Supports WPA/WPA2 with known PSK, 802.11 frame
analysis, and protocol dissection (EAPOL, DNS, HTTP, DHCP, etc.).

This module provides:
  - DECRYPTION_CAPABILITIES: Supported tshark decryption modes
  - PROTOCOL_DISSECTORS: 802.11 and network protocol dissectors
  - TsharkDecryptionEngine: Capability listing and argument building
  - LiveDecryptionSession: Real-time decryption with tshark subprocess
"""

import json
import os
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import IS_LINUX, IS_WINDOWS, log


# ─── Decryption Capabilities ─────────────────────────────────────────────────

DECRYPTION_CAPABILITIES: Dict[str, Dict[str, str]] = {
    "wpa-pwd": {
        "protocol": "WPA/WPA2-PSK",
        "description": "Decrypt WPA/WPA2 traffic using passphrase and SSID",
        "tshark_option": "uat:80211_keys",
        "key_format": "wpa-pwd:<passphrase>:<ssid>",
        "requirements": "Requires captured EAPOL 4-way handshake in traffic",
    },
    "wpa-psk": {
        "protocol": "WPA/WPA2-PSK (raw hex)",
        "description": "Decrypt WPA/WPA2 traffic using raw PSK hex (256-bit)",
        "tshark_option": "uat:80211_keys",
        "key_format": "wpa-psk:<64-hex-char-psk>",
        "requirements": "Requires captured EAPOL 4-way handshake in traffic",
    },
    "wep": {
        "protocol": "WEP",
        "description": "Decrypt WEP-encrypted frames with known key",
        "tshark_option": "uat:80211_keys",
        "key_format": "wep:<hex-key>",
        "requirements": "WEP key (40-bit or 104-bit) in hex",
    },
    "tls-keylog": {
        "protocol": "TLS/SSL",
        "description": "Decrypt TLS traffic using SSLKEYLOGFILE",
        "tshark_option": "tls.keylog_file",
        "key_format": "<path-to-keylog-file>",
        "requirements": "Key log file from browser or application (NSS format)",
    },
}


# ─── Protocol Dissectors ─────────────────────────────────────────────────────

PROTOCOL_DISSECTORS: Dict[str, Dict[str, str]] = {
    "wlan": {
        "field_name": "wlan",
        "display_filter": "wlan",
        "description": "IEEE 802.11 wireless LAN frames - source/destination MACs, "
                       "frame types, sequence numbers, retry flags",
    },
    "wlan_mgt": {
        "field_name": "wlan.mgt",
        "display_filter": "wlan_mgt",
        "description": "802.11 management frames - beacons, probe requests/responses, "
                       "association, authentication, deauthentication",
    },
    "eapol": {
        "field_name": "eapol",
        "display_filter": "eapol",
        "description": "EAPOL (Extensible Authentication Protocol over LAN) - "
                       "WPA/WPA2 4-way handshake key exchange messages",
    },
    "eap": {
        "field_name": "eap",
        "display_filter": "eap",
        "description": "EAP (Extensible Authentication Protocol) - "
                       "802.1X identity, challenge, and response frames",
    },
    "radius": {
        "field_name": "radius",
        "display_filter": "radius",
        "description": "RADIUS authentication/accounting - enterprise WPA credentials, "
                       "user identities, session details",
    },
    "dns": {
        "field_name": "dns",
        "display_filter": "dns",
        "description": "DNS queries and responses - reveals hostnames being resolved, "
                       "useful for identifying POS system communications",
    },
    "http": {
        "field_name": "http",
        "display_filter": "http",
        "description": "HTTP requests and responses - URLs, cookies, form data, "
                       "cleartext credentials, API endpoints",
    },
    "dhcp": {
        "field_name": "dhcp",
        "display_filter": "dhcp",
        "description": "DHCP discover/offer/request/ack - client hostnames, "
                       "MAC-to-IP mappings, lease information, vendor class IDs",
    },
    "dhcpv6": {
        "field_name": "dhcpv6",
        "display_filter": "dhcpv6",
        "description": "DHCPv6 messages - IPv6 address assignment, "
                       "client DUID identifiers, prefix delegation",
    },
    "mdns": {
        "field_name": "mdns",
        "display_filter": "mdns",
        "description": "Multicast DNS - local service discovery, device names, "
                       "printer/POS terminal announcements on the LAN",
    },
    "llmnr": {
        "field_name": "llmnr",
        "display_filter": "llmnr",
        "description": "Link-Local Multicast Name Resolution - Windows name resolution, "
                       "reveals internal hostnames and can be poisoned for MITM",
    },
    "nbns": {
        "field_name": "nbns",
        "display_filter": "nbns",
        "description": "NetBIOS Name Service - legacy Windows name resolution, "
                       "workgroup names, computer names, domain membership",
    },
    "smb": {
        "field_name": "smb",
        "display_filter": "smb",
        "description": "SMB/CIFS file sharing - share access, file operations, "
                       "NTLM authentication hashes, usernames",
    },
    "smb2": {
        "field_name": "smb2",
        "display_filter": "smb2",
        "description": "SMBv2/v3 file sharing - modern share access, "
                       "encryption negotiation, session setup details",
    },
    "ldap": {
        "field_name": "ldap",
        "display_filter": "ldap",
        "description": "LDAP directory queries - Active Directory lookups, "
                       "user enumeration, bind credentials",
    },
    "kerberos": {
        "field_name": "kerberos",
        "display_filter": "kerberos",
        "description": "Kerberos authentication - AS-REQ/AS-REP tickets, "
                       "TGS exchanges, SPNs, roastable service tickets",
    },
    "tls": {
        "field_name": "tls",
        "display_filter": "tls",
        "description": "TLS/SSL handshake and encrypted records - server names (SNI), "
                       "certificate details, cipher suites, JA3 fingerprints",
    },
}


# ─── TsharkDecryptionEngine ──────────────────────────────────────────────────


class TsharkDecryptionEngine:
    """
    Lists tshark decryption capabilities and builds CLI arguments
    for live or offline decryption of 802.11 traffic.

    Usage:
        engine = TsharkDecryptionEngine()
        caps = engine.list_capabilities()
        args = engine.build_decrypt_args(psk="MyPassword", ssid="TargetAP")
    """

    def __init__(self) -> None:
        self._tshark_path: Optional[str] = None

    def _get_tshark_path(self) -> Optional[str]:
        """Find tshark executable on this system."""
        if self._tshark_path:
            return self._tshark_path

        paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "tshark",
        ]
        for path in paths:
            if os.path.exists(path):
                self._tshark_path = path
                return path

        # Try which/where to find tshark in PATH
        try:
            cmd = "where" if IS_WINDOWS else "which"
            result = subprocess.run(
                [cmd, "tshark"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                self._tshark_path = result.stdout.strip().split("\n")[0]
                return self._tshark_path
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass

        return None

    def is_available(self) -> bool:
        """Check if tshark is available on this system."""
        return self._get_tshark_path() is not None

    def list_capabilities(self) -> Dict[str, str]:
        """
        List all supported decryption capabilities with human-readable descriptions.

        Returns:
            Dict mapping capability name to a description string.
        """
        result: Dict[str, str] = {}
        for name, info in DECRYPTION_CAPABILITIES.items():
            result[name] = (
                f"{info['protocol']}: {info['description']} "
                f"(format: {info['key_format']}, {info['requirements']})"
            )
        return result

    def list_dissectors(self) -> Dict[str, str]:
        """
        List all protocol dissectors with descriptions of what they reveal.

        Returns:
            Dict mapping protocol name to description.
        """
        return {name: info["description"] for name, info in PROTOCOL_DISSECTORS.items()}

    def build_decrypt_args(
        self,
        psk: Optional[str] = None,
        ssid: Optional[str] = None,
        wep_keys: Optional[List[str]] = None,
        tls_keylog: Optional[str] = None,
    ) -> List[str]:
        """
        Build tshark command-line arguments for decryption.

        Args:
            psk: WPA/WPA2 passphrase (used with ssid for wpa-pwd mode).
            ssid: SSID of the target network (required for wpa-pwd).
            wep_keys: List of WEP keys in hex format.
            tls_keylog: Path to TLS key log file (NSS SSLKEYLOGFILE format).

        Returns:
            List of tshark CLI arguments for decryption.
        """
        args: List[str] = []

        # Always enable 802.11 decryption when any wireless key is provided
        if psk or wep_keys:
            args.extend(["-o", "wlan.enable_decryption:TRUE"])

        # WPA/WPA2-PSK decryption
        if psk and ssid:
            # Use wpa-pwd format: passphrase:ssid
            key_entry = f"wpa-pwd,{psk}:{ssid}"
            args.extend(["-o", f"uat:80211_keys:\"{key_entry}\""])
        elif psk and not ssid:
            # If no SSID, try raw PSK (assumes 64-char hex)
            if len(psk) == 64 and all(c in "0123456789abcdefABCDEF" for c in psk):
                key_entry = f"wpa-psk,{psk}"
                args.extend(["-o", f"uat:80211_keys:\"{key_entry}\""])
            else:
                log.warning(
                    "PSK provided without SSID. For wpa-pwd mode, SSID is required. "
                    "For wpa-psk mode, key must be 64 hex characters."
                )

        # WEP key decryption
        if wep_keys:
            for wep_key in wep_keys:
                key_entry = f"wep,{wep_key}"
                args.extend(["-o", f"uat:80211_keys:\"{key_entry}\""])

        # TLS keylog file decryption
        if tls_keylog:
            if os.path.isfile(tls_keylog):
                args.extend(["-o", f"tls.keylog_file:{tls_keylog}"])
            else:
                log.warning(f"TLS keylog file not found: {tls_keylog}")

        return args

    def get_dissector_fields(self, protocols: Optional[List[str]] = None) -> List[str]:
        """
        Get tshark -e field arguments for specified protocols.

        Args:
            protocols: List of protocol names to include. If None, uses a
                       default set suitable for recon (dns, http, dhcp, eapol).

        Returns:
            List of -e field arguments for tshark -T fields mode.
        """
        if protocols is None:
            protocols = ["dns", "http", "dhcp", "eapol"]

        fields: List[str] = []
        field_map = {
            "dns": ["dns.qry.name", "dns.resp.name", "dns.a", "dns.aaaa"],
            "http": ["http.host", "http.request.uri", "http.request.method",
                     "http.cookie", "http.user_agent"],
            "dhcp": ["dhcp.option.hostname", "dhcp.option.requested_ip_address",
                     "dhcp.hw.mac_addr", "dhcp.option.vendor_class_id"],
            "eapol": ["eapol.type", "wlan.rsn.pcs.type"],
            "mdns": ["dns.qry.name", "dns.resp.name", "dns.srv.target"],
            "nbns": ["nbns.name", "nbns.addr"],
            "tls": ["tls.handshake.extensions_server_name", "tls.handshake.ciphersuite"],
            "kerberos": ["kerberos.CNameString", "kerberos.realm", "kerberos.SNameString"],
            "ldap": ["ldap.bindDN", "ldap.filter"],
            "smb": ["smb.path", "smb.file", "ntlmssp.auth.username"],
            "smb2": ["smb2.filename", "smb2.share"],
        }
        for proto in protocols:
            if proto in field_map:
                for field in field_map[proto]:
                    fields.extend(["-e", field])
        return fields


# ─── LiveDecryptionSession ────────────────────────────────────────────────────


class LiveDecryptionSession:
    """
    Runs tshark with decryption enabled and parses output in real-time.

    Extracts protocol-specific data from decrypted traffic including:
    DNS queries/responses, HTTP requests/URLs, DHCP leases, EAPOL
    handshake details, and cleartext credentials.

    Usage:
        session = LiveDecryptionSession(callback=my_handler)
        session.start("wlan0mon", psk="password123", ssid="TargetAP")
        # ... recon runs ...
        session.stop()
        summary = session.get_decrypted_summary()
    """

    def __init__(self, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        """
        Initialize the live decryption session.

        Args:
            callback: Optional function called with each parsed decrypted frame.
                      Receives a dict with keys: protocol, data, timestamp.
        """
        self._engine = TsharkDecryptionEngine()
        self._callback = callback
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

        # Decrypted data storage
        self._dns_queries: List[Dict[str, str]] = []
        self._http_requests: List[Dict[str, str]] = []
        self._dhcp_leases: List[Dict[str, str]] = []
        self._eapol_events: List[Dict[str, str]] = []
        self._credentials: List[Dict[str, str]] = []
        self._frame_count = 0
        self._start_time = 0.0

    @property
    def running(self) -> bool:
        """Whether the decryption session is currently active."""
        return self._running

    def start(
        self,
        interface: str,
        psk: Optional[str] = None,
        ssid: Optional[str] = None,
        wep_keys: Optional[List[str]] = None,
        tls_keylog: Optional[str] = None,
    ) -> bool:
        """
        Start a live tshark decryption session.

        Args:
            interface: Network interface in monitor mode.
            psk: WPA/WPA2 passphrase.
            ssid: Target network SSID.
            wep_keys: Optional WEP keys.
            tls_keylog: Optional TLS key log file path.

        Returns:
            True if tshark started successfully, False otherwise.
        """
        tshark_path = self._engine._get_tshark_path()
        if not tshark_path:
            log.warning("tshark not found - live decryption unavailable")
            return False

        # Build command
        cmd: List[str] = [tshark_path, "-i", interface, "-T", "json", "-l"]

        # Add decryption arguments
        decrypt_args = self._engine.build_decrypt_args(
            psk=psk, ssid=ssid, wep_keys=wep_keys, tls_keylog=tls_keylog
        )
        cmd.extend(decrypt_args)

        # Add display filter for interesting protocols
        display_filter = (
            "dns or http or dhcp or eapol or "
            "mdns or nbns or tls.handshake.extensions_server_name"
        )
        cmd.extend(["-Y", display_filter])

        log.info(f"Starting live decryption: {' '.join(cmd)}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except (OSError, FileNotFoundError) as e:
            log.error(f"Failed to start tshark for decryption: {e}")
            return False

        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(
            target=self._reader_loop, daemon=True, name="tshark-decrypt"
        )
        self._thread.start()

        log.info("Live decryption session started")
        return True

    def stop(self) -> None:
        """Stop the live decryption session and clean up."""
        self._running = False

        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log.warning("tshark did not terminate gracefully, killing")
                self._proc.kill()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
            finally:
                self._proc = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
            self._thread = None

        elapsed = time.time() - self._start_time if self._start_time else 0
        log.info(
            f"Live decryption session stopped. "
            f"Frames: {self._frame_count}, Duration: {elapsed:.1f}s"
        )

    def get_decrypted_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all decrypted data collected during the session.

        Returns:
            Dict with keys: dns_queries, http_requests, dhcp_leases,
            eapol_events, credentials, frame_count, duration_seconds.
        """
        with self._lock:
            return {
                "dns_queries": list(self._dns_queries),
                "http_requests": list(self._http_requests),
                "dhcp_leases": list(self._dhcp_leases),
                "eapol_events": list(self._eapol_events),
                "credentials": list(self._credentials),
                "frame_count": self._frame_count,
                "duration_seconds": time.time() - self._start_time if self._start_time else 0,
            }

    def _reader_loop(self) -> None:
        """Background thread reading tshark JSON output line by line."""
        if not self._proc or not self._proc.stdout:
            return

        json_buffer = ""
        bracket_depth = 0

        try:
            for line in self._proc.stdout:
                if not self._running:
                    break

                stripped = line.strip()
                if not stripped:
                    continue

                # Track JSON object boundaries
                for ch in stripped:
                    if ch == "{":
                        bracket_depth += 1
                    elif ch == "}":
                        bracket_depth -= 1

                json_buffer += stripped

                # Complete JSON object detected
                if bracket_depth == 0 and json_buffer.startswith("{"):
                    self._parse_json_frame(json_buffer)
                    json_buffer = ""
                elif bracket_depth < 0:
                    # Reset on malformed output
                    json_buffer = ""
                    bracket_depth = 0

        except (IOError, OSError):
            if self._running:
                log.warning("tshark output stream closed unexpectedly")
        except Exception as e:
            if self._running:
                log.error(f"Error in decryption reader loop: {e}")

    def _parse_json_frame(self, json_str: str) -> None:
        """Parse a single JSON frame from tshark output."""
        try:
            frame = json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return

        self._frame_count += 1

        # Extract layers from tshark JSON format
        layers = frame.get("_source", {}).get("layers", {})
        if not layers:
            # Alternative tshark JSON format
            layers = frame.get("layers", {})
        if not layers:
            return

        # Process each protocol layer
        if "dns" in layers:
            self._extract_dns(layers["dns"])
        if "http" in layers:
            self._extract_http(layers["http"])
        if "dhcp" in layers:
            self._extract_dhcp(layers["dhcp"])
        if "eapol" in layers:
            self._extract_eapol(layers.get("eapol", {}), layers.get("wlan", {}))

    def _extract_dns(self, dns_layer: Any) -> None:
        """Extract DNS query/response data."""
        if not isinstance(dns_layer, dict):
            return

        entry: Dict[str, str] = {"timestamp": str(time.time())}

        # Query name
        qry_name = dns_layer.get("dns.qry.name", "")
        if isinstance(qry_name, list):
            qry_name = qry_name[0] if qry_name else ""
        entry["query"] = str(qry_name)

        # Response address
        resp_addr = dns_layer.get("dns.a", "")
        if isinstance(resp_addr, list):
            resp_addr = resp_addr[0] if resp_addr else ""
        entry["response"] = str(resp_addr)

        # Response name
        resp_name = dns_layer.get("dns.resp.name", "")
        if isinstance(resp_name, list):
            resp_name = resp_name[0] if resp_name else ""
        entry["response_name"] = str(resp_name)

        if entry["query"] or entry["response"]:
            with self._lock:
                self._dns_queries.append(entry)
            self._dispatch_callback("dns", entry)

    def _extract_http(self, http_layer: Any) -> None:
        """Extract HTTP request data."""
        if not isinstance(http_layer, dict):
            return

        entry: Dict[str, str] = {"timestamp": str(time.time())}

        entry["host"] = str(http_layer.get("http.host", ""))
        entry["method"] = str(http_layer.get("http.request.method", ""))
        entry["uri"] = str(http_layer.get("http.request.uri", ""))
        entry["user_agent"] = str(http_layer.get("http.user_agent", ""))
        entry["cookie"] = str(http_layer.get("http.cookie", ""))

        # Check for credentials in Authorization header
        auth_header = str(http_layer.get("http.authorization", ""))
        if auth_header:
            entry["authorization"] = auth_header
            cred_entry = {
                "protocol": "http",
                "type": "authorization_header",
                "value": auth_header,
                "host": entry["host"],
                "timestamp": entry["timestamp"],
            }
            with self._lock:
                self._credentials.append(cred_entry)

        if entry["host"] or entry["uri"]:
            with self._lock:
                self._http_requests.append(entry)
            self._dispatch_callback("http", entry)

    def _extract_dhcp(self, dhcp_layer: Any) -> None:
        """Extract DHCP lease information."""
        if not isinstance(dhcp_layer, dict):
            return

        entry: Dict[str, str] = {"timestamp": str(time.time())}

        entry["hostname"] = str(dhcp_layer.get("dhcp.option.hostname", ""))
        entry["requested_ip"] = str(dhcp_layer.get("dhcp.option.requested_ip_address", ""))
        entry["mac_addr"] = str(dhcp_layer.get("dhcp.hw.mac_addr", ""))
        entry["vendor_class"] = str(dhcp_layer.get("dhcp.option.vendor_class_id", ""))

        if entry["hostname"] or entry["requested_ip"] or entry["mac_addr"]:
            with self._lock:
                self._dhcp_leases.append(entry)
            self._dispatch_callback("dhcp", entry)

    def _extract_eapol(self, eapol_layer: Any, wlan_layer: Any) -> None:
        """Extract EAPOL handshake details."""
        if not isinstance(eapol_layer, dict):
            return

        entry: Dict[str, str] = {"timestamp": str(time.time())}

        entry["type"] = str(eapol_layer.get("eapol.type", ""))

        # Get source/destination from wlan layer
        if isinstance(wlan_layer, dict):
            entry["source"] = str(wlan_layer.get("wlan.sa", ""))
            entry["destination"] = str(wlan_layer.get("wlan.da", ""))
            entry["bssid"] = str(wlan_layer.get("wlan.bssid", ""))

        if entry["type"]:
            with self._lock:
                self._eapol_events.append(entry)
            self._dispatch_callback("eapol", entry)

    def _dispatch_callback(self, protocol: str, data: Dict[str, str]) -> None:
        """Dispatch parsed data to the registered callback."""
        if self._callback:
            try:
                self._callback({
                    "protocol": protocol,
                    "data": data,
                    "timestamp": time.time(),
                })
            except Exception as e:
                log.error(f"Decryption callback error: {e}")

    def __enter__(self) -> "LiveDecryptionSession":
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()
