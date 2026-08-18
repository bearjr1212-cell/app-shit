"""
Intel Enricher - Live Background Intelligence During Recon
----------------------------------------------------------
Manages the lifecycle of external intelligence tools (p0f, horst, kismet)
that run alongside the ReconEngine and feed their findings back into the
database in real-time.

When recon starts, the IntelEnricher spawns available tools as background
threads. Each tool periodically polls its results and enriches the existing
AP/client entries in the database with OS fingerprints, device types, signal
data, and other intelligence.

Usage:
    enricher = IntelEnricher(interface="wlan0mon", db=db)
    enricher.start()   # Spawns background intel threads
    # ... recon runs ...
    enricher.stop()    # Gracefully stops all tools
"""

import threading
import time
from typing import Dict, List, Optional

from .config import log


class IntelEnricher:
    """
    Manages background intelligence tools that enrich recon data in real-time.

    Spawns p0f (OS fingerprinting), horst (link-layer scanning), and
    kismet (WiFi device intel) as background processes, then periodically
    polls their output and updates the database with enriched information.
    """

    # How often to poll tools for new results (seconds)
    POLL_INTERVAL = 5.0

    def __init__(self, interface: str, db, enable_p0f: bool = True,
                 enable_horst: bool = True, enable_kismet: bool = True):
        """
        Initialize the IntelEnricher.

        Args:
            interface: Network interface in monitor mode.
            db: POSDatabase instance to enrich with intel data.
            enable_p0f: Whether to start p0f for OS fingerprinting.
            enable_horst: Whether to start horst for link-layer scanning.
            enable_kismet: Whether to start kismet for WiFi intel.
        """
        self.interface = interface
        self.db = db
        self._enable_p0f = enable_p0f
        self._enable_horst = enable_horst
        self._enable_kismet = enable_kismet

        self._running = False
        self._threads: List[threading.Thread] = []

        # Tool instances (created on start)
        self._p0f = None
        self._horst = None
        self._kismet = None

        # Accumulated intel results
        self._os_fingerprints: Dict[str, dict] = {}
        self._signal_data: Dict[str, dict] = {}
        self._device_types: Dict[str, str] = {}

    @property
    def running(self) -> bool:
        """Check if the enricher is currently running."""
        return self._running

    def start(self) -> int:
        """
        Start all enabled intelligence tools as background threads.

        Returns:
            Number of tools successfully started.
        """
        if self._running:
            return 0

        self._running = True
        tools_started = 0

        # Start p0f for passive OS fingerprinting
        if self._enable_p0f:
            if self._start_p0f():
                tools_started += 1

        # Start horst for link-layer scanning
        if self._enable_horst:
            if self._start_horst():
                tools_started += 1

        # Start kismet for WiFi device intel
        if self._enable_kismet:
            if self._start_kismet():
                tools_started += 1

        if tools_started > 0:
            # Start the polling thread that feeds results into DB
            poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True, name="IntelEnricher-Poll"
            )
            poll_thread.start()
            self._threads.append(poll_thread)
            log.info(f"IntelEnricher: {tools_started} tool(s) running, "
                     f"polling every {self.POLL_INTERVAL}s")
        else:
            self._running = False
            log.warning("IntelEnricher: No tools available, enrichment disabled")

        return tools_started

    def stop(self):
        """Stop all running intelligence tools and the polling thread."""
        if not self._running:
            return

        self._running = False

        # Stop each tool
        if self._p0f:
            try:
                self._p0f.stop()
                log.info("IntelEnricher: p0f stopped")
            except Exception as e:
                log.debug(f"IntelEnricher: p0f stop error: {e}")
            self._p0f = None

        if self._horst:
            try:
                self._horst.stop()
                log.info("IntelEnricher: horst stopped")
            except Exception as e:
                log.debug(f"IntelEnricher: horst stop error: {e}")
            self._horst = None

        if self._kismet:
            try:
                self._kismet.stop()
                log.info("IntelEnricher: kismet stopped")
            except Exception as e:
                log.debug(f"IntelEnricher: kismet stop error: {e}")
            self._kismet = None

        # Wait for threads to finish
        for t in self._threads:
            t.join(timeout=3.0)
        self._threads.clear()

        # Log final enrichment stats
        log.info(
            f"IntelEnricher stopped: "
            f"{len(self._os_fingerprints)} OS fingerprints, "
            f"{len(self._signal_data)} signal entries, "
            f"{len(self._device_types)} device types collected"
        )

    def get_os_fingerprint(self, ip: str) -> Optional[dict]:
        """Get OS fingerprint data for a specific IP."""
        return self._os_fingerprints.get(ip)

    def get_signal_data(self, mac: str) -> Optional[dict]:
        """Get signal/link data for a specific MAC."""
        return self._signal_data.get(mac.upper())

    def get_device_type(self, mac: str) -> Optional[str]:
        """Get device type classification for a MAC."""
        return self._device_types.get(mac.upper())

    def get_summary(self) -> dict:
        """Get a summary of all collected intel."""
        return {
            "running": self._running,
            "os_fingerprints": len(self._os_fingerprints),
            "signal_entries": len(self._signal_data),
            "device_types": len(self._device_types),
            "p0f_active": self._p0f is not None and self._p0f.running,
            "horst_active": self._horst is not None and self._horst.running,
            "kismet_active": self._kismet is not None and self._kismet.running,
        }

    # ------------------------------------------------------------------
    # Private: Tool startup
    # ------------------------------------------------------------------

    def _start_p0f(self) -> bool:
        """Attempt to start p0f. Returns True on success."""
        try:
            from .tools.p0f import P0F
            self._p0f = P0F(interface=self.interface)
            if self._p0f.start():
                log.info("IntelEnricher: p0f started (passive OS fingerprinting)")
                return True
            else:
                self._p0f = None
                return False
        except (FileNotFoundError, ImportError) as e:
            log.debug(f"IntelEnricher: p0f not available: {e}")
            self._p0f = None
            return False

    def _start_horst(self) -> bool:
        """Attempt to start horst. Returns True on success."""
        try:
            from .tools.horst import Horst
            self._horst = Horst(interface=self.interface)
            if self._horst.start():
                log.info("IntelEnricher: horst started (link-layer scanning)")
                return True
            else:
                self._horst = None
                return False
        except (FileNotFoundError, ImportError) as e:
            log.debug(f"IntelEnricher: horst not available: {e}")
            self._horst = None
            return False

    def _start_kismet(self) -> bool:
        """Attempt to start kismet. Returns True on success."""
        try:
            from .tools.kismet import KismetClient
            self._kismet = KismetClient(interface=self.interface)
            if self._kismet.start_server():
                log.info("IntelEnricher: kismet started (WiFi intel)")
                return True
            else:
                self._kismet = None
                return False
        except (FileNotFoundError, ImportError) as e:
            log.debug(f"IntelEnricher: kismet not available: {e}")
            self._kismet = None
            return False

    # ------------------------------------------------------------------
    # Private: Polling and enrichment
    # ------------------------------------------------------------------

    def _poll_loop(self):
        """Background thread that periodically polls tools and enriches the DB."""
        while self._running:
            try:
                self._poll_p0f()
                self._poll_horst()
                self._poll_kismet()
            except Exception as e:
                log.debug(f"IntelEnricher poll error: {e}")

            # Sleep in small increments so we can stop quickly
            for _ in range(int(self.POLL_INTERVAL * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def _poll_p0f(self):
        """Poll p0f for new OS fingerprints and enrich the database."""
        if not self._p0f or not self._p0f.running:
            return

        try:
            results = self._p0f.get_results()
            for result in results:
                ip = result.ip
                if ip not in self._os_fingerprints or self._os_fingerprints[ip] != result.to_dict():
                    self._os_fingerprints[ip] = result.to_dict()
                    log.debug(
                        f"IntelEnricher [p0f]: {ip} -> "
                        f"{result.os} {result.os_flavor} "
                        f"(dist={result.distance}, link={result.link_type})"
                    )
                    # Store as intel event in the database
                    self._store_intel_event("p0f", {
                        "ip": ip,
                        "os": result.os,
                        "os_flavor": result.os_flavor,
                        "distance": result.distance,
                        "link_type": result.link_type,
                        "uptime": result.uptime,
                    })
        except Exception as e:
            log.debug(f"IntelEnricher: p0f poll error: {e}")

    def _poll_horst(self):
        """Poll horst for discovered nodes and enrich signal data."""
        if not self._horst or not self._horst.running:
            return

        try:
            nodes = self._horst.get_nodes()
            for node in nodes:
                mac = node.mac.upper()
                node_dict = node.to_dict()
                if mac not in self._signal_data or self._signal_data[mac] != node_dict:
                    self._signal_data[mac] = node_dict
                    log.debug(
                        f"IntelEnricher [horst]: {mac} "
                        f"signal={node.signal}dBm ch={node.channel} "
                        f"mode={node.mode} pkts={node.packet_count}"
                    )
                    # Enrich client entry in database with signal data
                    self._enrich_client_signal(mac, node)
                    # Infer device type from mode
                    if node.mode:
                        self._device_types[mac] = node.mode
        except Exception as e:
            log.debug(f"IntelEnricher: horst poll error: {e}")

    def _poll_kismet(self):
        """Poll kismet for discovered devices and enrich the database."""
        if not self._kismet or not self._kismet.running:
            return

        try:
            devices = self._kismet.get_devices()
            for device in devices:
                mac = device.mac.upper()
                # Track device type
                if device.device_type and device.device_type != "unknown":
                    self._device_types[mac] = device.device_type

                # Enrich AP entries
                if device.device_type in ("AP", "Wi-Fi AP") and device.ssid:
                    self._enrich_ap_from_kismet(device)

                # Enrich client entries
                if device.device_type in ("Wi-Fi Client", "Client", "STA"):
                    self._enrich_client_from_kismet(device)

                log.debug(
                    f"IntelEnricher [kismet]: {mac} "
                    f"type={device.device_type} "
                    f"name={device.name} ssid={device.ssid} "
                    f"signal={device.signal_dbm}dBm"
                )
        except Exception as e:
            log.debug(f"IntelEnricher: kismet poll error: {e}")

    def _enrich_client_signal(self, mac: str, node):
        """Update client signal data in the database from horst node."""
        try:
            # Update RSSI for the client if we have a better reading
            self.db.update_client(
                mac=mac,
                vendor=None,
                rssi=node.signal,
                is_pos=False,
            )
        except Exception as e:
            log.debug(f"IntelEnricher: client signal update failed for {mac}: {e}")

    def _enrich_ap_from_kismet(self, device):
        """Update AP entry in database from kismet device data."""
        try:
            self.db.update_ap(
                bssid=device.mac,
                ssid=device.ssid,
                vendor=device.manufacturer or None,
                channel=device.channel or None,
                security=device.encryption or None,
                rssi=device.signal_dbm,
                is_pos=False,
                is_hidden=False,
            )
        except Exception as e:
            log.debug(f"IntelEnricher: AP enrichment failed for {device.mac}: {e}")

    def _enrich_client_from_kismet(self, device):
        """Update client entry in database from kismet device data."""
        try:
            self.db.update_client(
                mac=device.mac,
                vendor=device.manufacturer or None,
                rssi=device.signal_dbm,
                is_pos=False,
            )
        except Exception as e:
            log.debug(f"IntelEnricher: client enrichment failed for {device.mac}: {e}")

    def _store_intel_event(self, source: str, data: dict):
        """Store an intel event in the database if supported."""
        try:
            if hasattr(self.db, 'log_intel_event'):
                self.db.log_intel_event(source, data)
        except Exception:
            pass
