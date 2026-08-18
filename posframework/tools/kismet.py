"""
Kismet Integration
──────────────────
WiFi intelligence gathering via Kismet:
  - Discovers all wireless devices (APs, clients, probes)
  - REST API integration for querying device data
  - Live vector loading of discovered networks and clients
  - Background server management

Kismet is a wireless network and device detector, sniffer, wardriving
tool, and WIDS (wireless intrusion detection) framework. It operates
passively and provides a rich REST API for querying discovered devices.
"""

import json
import os
import signal
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from posframework.config import log
from posframework.tools import is_available, which


@dataclass
class KismetDevice:
    """Represents a device discovered by Kismet."""
    mac: str
    device_type: str = "unknown"
    name: str = ""
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    signal_dbm: int = -100
    manufacturer: str = ""
    encryption: str = ""
    last_seen: float = field(default_factory=time.time)
    packets: int = 0
    clients: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for live vector loading and JSON serialization."""
        return {
            "mac": self.mac,
            "device_type": self.device_type,
            "name": self.name,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "signal_dbm": self.signal_dbm,
            "manufacturer": self.manufacturer,
            "encryption": self.encryption,
            "last_seen": self.last_seen,
            "packets": self.packets,
            "clients": self.clients,
        }


class KismetClient:
    """
    Kismet server wrapper for WiFi intelligence gathering.

    Manages the Kismet server process and provides methods to query the
    REST API for discovered devices, SSIDs, and network topology.
    Results are loaded live for real-time vector updates.

    Usage:
        kismet = KismetClient("wlan0mon")
        kismet.start_server()
        time.sleep(10)  # Let it discover devices
        devices = kismet.get_devices()
        ssids = kismet.get_ssids()
        kismet.stop()
    """

    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 2501
    DEFAULT_USER = os.environ.get("KISMET_USER", "posframework")
    DEFAULT_PASSWORD = os.environ.get("KISMET_PASSWORD", "posframework")

    def __init__(
        self,
        interface: Optional[str] = None,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        username: str = DEFAULT_USER,
        password: str = DEFAULT_PASSWORD,
    ):
        if not is_available("kismet"):
            raise FileNotFoundError(
                "kismet not installed. Install: apt-get install kismet"
            )
        self.interface = interface
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._proc: Optional[subprocess.Popen] = None
        self._base_url = f"http://{host}:{port}"
        self._devices: Dict[str, KismetDevice] = {}

    @property
    def running(self) -> bool:
        """Check if kismet server process is running."""
        return self._proc is not None and self._proc.poll() is None

    def start_server(self, interface: Optional[str] = None) -> bool:
        """
        Start the Kismet server with the specified interface as a capture source.

        Args:
            interface: WiFi interface in monitor mode (overrides constructor arg).

        Returns:
            True if Kismet server started successfully.
        """
        iface = interface or self.interface
        if not iface:
            log.error("kismet: No interface specified")
            return False

        self.stop()

        path = which("kismet")
        if not path:
            return False

        # Kismet args: source interface, no ncurses UI, REST API access
        args = [
            "-c", iface,
            "--no-ncurses",
            "--no-logging",
            "--override", f"httpd_username={self.username}",
            "--override", f"httpd_password={self.password}",
            "--override", f"httpd_port={self.port}",
        ]

        cmd = [path] + args
        log.info(f"kismet: Starting server on {iface} (API: {self._base_url})")
        log.debug(f"kismet: {' '.join(cmd)}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Give kismet time to start the REST API
            time.sleep(2.0)
            if self._proc.poll() is not None:
                log.error("kismet: Server failed to start")
                self._proc = None
                return False
            return True
        except Exception as e:
            log.error(f"kismet start error: {e}")
            self._proc = None
            return False

    def stop(self):
        """Stop the Kismet server."""
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=3)
            except OSError:
                pass
            self._proc = None

    def get_devices(self) -> List[KismetDevice]:
        """
        Query Kismet REST API for all discovered devices.
        Results are loaded live each time this is called.

        Returns:
            List of KismetDevice objects.
        """
        endpoint = "/devices/all_devices.ekjson"
        data = self._api_request(endpoint)
        if data is None:
            return list(self._devices.values())

        self._parse_devices(data)
        return list(self._devices.values())

    def get_devices_live(self) -> List[Dict]:
        """
        Get devices as live-loadable vector dicts for attack input auto-fill.

        Returns:
            List of dicts suitable for live vector loading.
        """
        devices = self.get_devices()
        return [d.to_dict() for d in devices]

    def get_ssids(self) -> List[Dict[str, Any]]:
        """
        Get all discovered SSIDs with associated information.
        Loaded live from Kismet API.

        Returns:
            List of dicts with SSID info: {ssid, bssid, channel, encryption, signal}.
        """
        endpoint = "/devices/all_devices.ekjson"
        data = self._api_request(endpoint)
        if data is None:
            # Return cached SSIDs
            return [
                {"ssid": d.ssid, "bssid": d.mac, "channel": d.channel,
                 "encryption": d.encryption, "signal": d.signal_dbm}
                for d in self._devices.values() if d.ssid
            ]

        self._parse_devices(data)
        ssids = []
        for device in self._devices.values():
            if device.ssid and device.device_type in ("AP", "Wi-Fi AP"):
                ssids.append({
                    "ssid": device.ssid,
                    "bssid": device.mac,
                    "channel": device.channel,
                    "encryption": device.encryption,
                    "signal": device.signal_dbm,
                })
        return ssids

    def get_device_by_mac(self, mac: str) -> Optional[KismetDevice]:
        """
        Get detailed info for a specific device by MAC address.

        Args:
            mac: Device MAC address.

        Returns:
            KismetDevice if found, None otherwise.
        """
        # Try cache first
        mac_upper = mac.upper()
        if mac_upper in self._devices:
            return self._devices[mac_upper]

        # Query API
        endpoint = f"/devices/by-mac/{mac_upper}/devices.ekjson"
        data = self._api_request(endpoint)
        if data:
            self._parse_devices(data)
        return self._devices.get(mac_upper)

    def _api_request(self, endpoint: str) -> Optional[str]:
        """
        Make a request to the Kismet REST API.

        Args:
            endpoint: API endpoint path.

        Returns:
            Response body string, or None on failure.
        """
        url = f"{self._base_url}{endpoint}"

        # Set up basic auth
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, self._base_url, self.username, self.password)
        auth_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
        opener = urllib.request.build_opener(auth_handler)

        try:
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            response = opener.open(req, timeout=5)
            return response.read().decode("utf-8", errors="ignore")
        except urllib.error.URLError as e:
            log.debug(f"kismet API error ({endpoint}): {e}")
            return None
        except Exception as e:
            log.debug(f"kismet API request failed: {e}")
            return None

    def _parse_devices(self, data: str):
        """
        Parse Kismet ekjson (one JSON object per line) device data.

        Args:
            data: Raw ekjson response string.
        """
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            mac = obj.get("kismet.device.base.macaddr", "").upper()
            if not mac:
                continue

            device = self._devices.get(mac, KismetDevice(mac=mac))

            # Parse device type
            dev_type = obj.get("kismet.device.base.type", "")
            if dev_type:
                device.device_type = dev_type

            # Parse name/SSID
            device.name = obj.get("kismet.device.base.name", device.name)
            # SSID from dot11 subsystem
            dot11 = obj.get("dot11.device", {})
            if isinstance(dot11, dict):
                last_ssid = dot11.get("dot11.device.last_beaconed_ssid", "")
                if last_ssid:
                    device.ssid = last_ssid

            # Channel and frequency
            device.channel = obj.get("kismet.device.base.channel", device.channel)
            try:
                device.channel = int(device.channel) if device.channel else 0
            except (ValueError, TypeError):
                pass
            device.frequency = obj.get("kismet.device.base.frequency", device.frequency)

            # Signal
            signal_data = obj.get("kismet.device.base.signal", {})
            if isinstance(signal_data, dict):
                device.signal_dbm = signal_data.get(
                    "kismet.common.signal.last_signal", device.signal_dbm
                )

            # Manufacturer
            device.manufacturer = obj.get(
                "kismet.device.base.manuf", device.manufacturer
            )

            # Encryption
            crypt = obj.get("kismet.device.base.crypt", "")
            if crypt:
                device.encryption = crypt

            # Packet count
            device.packets = obj.get("kismet.device.base.packets.total", device.packets)

            device.last_seen = time.time()
            self._devices[mac] = device

    def clear_cache(self):
        """Clear the local device cache."""
        self._devices.clear()

    def __del__(self):
        try:
            self.stop()
        except AttributeError:
            pass
