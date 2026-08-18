"""
Passive Reconnaissance Engine
─────────────────────────────
Real-world 802.11 passive monitor. Identifies Point-of-Sale terminals,
payment infrastructure, and retail networking gear by correlating OUI
vendor lookups, SSID heuristics, RSN/WPA information element parsing,
and EAPOL handshake detection.

This is the core scanner — it populates the database that attack modules
consume for automated targeting.
"""

import struct
import subprocess
import time
import threading
import sys
from collections import defaultdict
from functools import lru_cache

from scapy.all import sniff, raw, conf, Raw
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
    Dot11Elt, Dot11Deauth, Dot11Disas,
    Dot11AssoReq, Dot11ReassoReq, Dot11QoS,
)
from scapy.layers.eap import EAPOL
from manuf import manuf

from .config import (
    CHANNELS_24GHZ, CHANNEL_HOP_INTERVAL, STATUS_INTERVAL,
    DEAUTH_THRESHOLD, DEAUTH_WINDOW, WIFI_BROADCAST, IS_WINDOWS, IS_LINUX, log,
)
from .intel import is_pos_vendor, is_pos_ssid
from .crypto import parse_rsn_ie, parse_wpa_ie, classify_security
from .tshark_decrypt import TsharkDecryptionEngine, LiveDecryptionSession, WiresharkCapture
from .pywhat_analyzer import PyWhatAnalyzer, PyWhatCallback
from .monitor_mode import (
    setup_monitor_mode, teardown_monitor_mode,
    WindowsMonitorManager, check_npcap_monitor_support
)

# Native C channel hopping — falls back to subprocess if unavailable
try:
    from .native.channel_hop import set_channel as native_set_channel
    _HAS_NATIVE_CHANNEL_HOP = True
except ImportError:
    _HAS_NATIVE_CHANNEL_HOP = False


# ANSI color codes for terminal output (Windows 10+ compatible)
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @classmethod
    def supports_color(cls):
        if IS_WINDOWS:
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return sys.stdout.isatty()

    @classmethod
    def color(cls, text, color_code):
        if cls.supports_color():
            return f"{color_code}{text}{cls.ENDC}"
        return text


class ReconEngine:
    """
    Passive 802.11 monitor engine.

    Discovers:
        - Access points (SSID, BSSID, channel, security, vendor, POS flag)
        - Clients (MAC, vendor, associated AP, probed SSIDs, POS flag)
        - EAPOL 4-way handshakes
        - Deauthentication floods

    All data is written to the database and made available for the attack
    modules to query for automated target selection.
    """

    def __init__(self, interface, db, channels=None, channel_hop=True,
                 tshark_psk=None, tshark_ssid=None, pywhat_enabled=False,
                 intel_enricher=None):
        self.interface = interface
        self.db = db
        self.channels = channels or CHANNELS_24GHZ
        self.channel_hop = channel_hop
        self.running = False
        self._stop_event = threading.Event()
        self.parser = manuf.MacParser(update=False)
        self._deauth_times = defaultdict(list)
        self._eapol_tracker = defaultdict(set)
        self._packets_processed = 0
        self._start_time = 0.0
        self._verbose = False
        # Packet type counters for summary stats
        self._pkt_stats = defaultdict(int)
        # Signal targeting integration
        self.signal_targeting = None
        # Monitor mode manager
        self._monitor_manager = None
        # tshark live decryption
        self._tshark_psk = tshark_psk
        self._tshark_ssid = tshark_ssid
        self._decrypt_session: 'LiveDecryptionSession | None' = None
        # pyWhat attack surface analysis
        self._pywhat_enabled = pywhat_enabled
        self._pywhat_callback: 'PyWhatCallback | None' = None
        # Intel enricher for background tool integration
        self._intel_enricher = intel_enricher

    _VENDOR_CACHE_MAX = 1024

    @lru_cache(maxsize=1024)
    def _get_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC OUI with LRU caching (O(1) eviction).

        Uses functools.lru_cache with maxsize=1024 for automatic
        least-recently-used eviction. No manual TTL — the manuf database
        doesn't change at runtime so cached entries remain valid.
        """
        try:
            v = self.parser.get_manuf(mac)
            return v if v else "Unknown"
        except Exception:
            return "Unknown"

    def _set_channel(self, channel: int):
        """Set channel — uses native C wrapper for speed, falls back to iw subprocess."""
        if IS_WINDOWS:
            return  # Windows Npcap doesn't support manual channel hopping
        if _HAS_NATIVE_CHANNEL_HOP:
            try:
                native_set_channel(self.interface, channel)
                return
            except Exception:
                pass  # Fall through to subprocess
        try:
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def _filter_supported_channels(self):
        """Query the adapter for supported channels and filter the channel list."""
        try:
            import subprocess
            result = subprocess.run(
                ["iw", "phy", "phy0", "channels"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                # Try alternative: iw dev <iface> info to get phy, then query
                result = subprocess.run(
                    ["iw", "dev", self.interface, "info"],
                    capture_output=True, text=True, timeout=5
                )
                phy = None
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if "wiphy" in line:
                            phy_num = line.strip().split()[-1]
                            phy = f"phy{phy_num}"
                            break
                if phy:
                    result = subprocess.run(
                        ["iw", "phy", phy, "channels"],
                        capture_output=True, text=True, timeout=5
                    )

            if result.returncode == 0 and result.stdout:
                import re
                supported = set()
                for line in result.stdout.splitlines():
                    # Match lines like "* 2412 MHz [1]" or "Channel 1"
                    m = re.search(r'\[(\d+)\]', line)
                    if m:
                        ch = int(m.group(1))
                        # Skip disabled channels
                        if 'disabled' not in line.lower() and 'no IR' not in line:
                            supported.add(ch)
                if supported:
                    original_len = len(self.channels)
                    self.channels = [ch for ch in self.channels if ch in supported]
                    if len(self.channels) < original_len:
                        removed = original_len - len(self.channels)
                        log.info(f"Filtered {removed} unsupported channels. Using: {self.channels}")
                    if not self.channels:
                        # Fallback to standard 1-11
                        self.channels = list(range(1, 12))
                        log.warning("No channels detected, defaulting to 1-11")
        except Exception as e:
            # If we can't query, just use 1-11 as safe default
            log.debug(f"Channel query failed ({e}), filtering to 1-11")
            self.channels = [ch for ch in self.channels if ch <= 11]

    def _hop_channels(self):
        idx = 0
        while self.running:
            try:
                self._set_channel(self.channels[idx])
            except Exception as e:
                log.error(f"Channel hop failed: {e}")
            idx = (idx + 1) % len(self.channels)
            time.sleep(CHANNEL_HOP_INTERVAL)

    def _get_security(self, pkt) -> str:
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        has_privacy = "privacy" in cap
        rsn_info, wpa_info = {}, {}
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48:
                rsn_info = parse_rsn_ie(elt.info)
            elif elt.ID == 221 and elt.info and elt.info[:4] == b'\x00\x50\xf2\x01':
                wpa_info = parse_wpa_ie(elt.info)
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        return classify_security(rsn_info, wpa_info, has_privacy)

    def _get_channel_from_ie(self, pkt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3 and elt.info and len(elt.info) >= 1:
                return elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        return None

    def _detect_deauth_flood(self, bssid: str) -> bool:
        now = time.time()
        ts = self._deauth_times[bssid]
        cutoff = now - DEAUTH_WINDOW
        while ts and ts[0] < cutoff:
            ts.pop(0)
        ts.append(now)
        if len(ts) >= DEAUTH_THRESHOLD:
            log.warning(f"DEAUTH FLOOD: {bssid} -- {len(ts)} frames in {DEAUTH_WINDOW}s")
            return True
        return False

    def _identify_eapol_message(self, eapol_raw: bytes) -> int:
        """
        Identify EAPOL-Key message number from raw EAPOL frame.

        Handles:
          - Standard 4-way handshake (messages 1-4)
          - Group Key handshake (messages 5-6 for GK M1/M2)
          - FT reassociation handshakes (same bit patterns as standard)

        Key Info field bits (IEEE 802.11-2020 Section 12.7.2):
          Bit 3: Pairwise (1=pairwise, 0=group)
          Bit 6: Install
          Bit 7: Key Ack
          Bit 8: Key MIC
          Bit 9: Secure
          Bit 12: Encrypted Key Data
        """
        if len(eapol_raw) < 10:
            return 0
        # Use memoryview for zero-copy slicing
        mv = memoryview(eapol_raw) if not isinstance(eapol_raw, memoryview) else eapol_raw
        key_info = struct.unpack(">H", mv[5:7])[0]
        key_ack = (key_info >> 7) & 1
        key_mic = (key_info >> 8) & 1
        secure = (key_info >> 9) & 1
        install = (key_info >> 6) & 1
        pairwise = (key_info >> 3) & 1
        encrypted = (key_info >> 12) & 1

        # Extract key data length for additional validation
        key_data_length = 0
        if len(eapol_raw) >= 99:
            key_data_length = struct.unpack(">H", mv[97:99])[0]

        # Group Key Handshake (2-way, pairwise bit = 0)
        if not pairwise:
            if key_ack and key_mic and secure:
                return 5  # Group Key Message 1 (AP -> Client)
            if not key_ack and key_mic and secure:
                return 6  # Group Key Message 2 (Client -> AP)
            return 0

        # Standard 4-way handshake (also covers FT reassociation)
        # Message 1: AP sends ANonce (Ack set, no MIC, no Install)
        if key_ack and not key_mic:
            return 1
        # Message 2: Client sends SNonce (MIC set, no Ack, not Secure)
        if not key_ack and key_mic and not secure:
            return 2
        # Message 3: AP sends GTK (Ack + MIC + Install + Secure + Encrypted)
        if key_ack and key_mic and install:
            return 3
        # Message 4: Client confirms (MIC + Secure, no Ack, no Install)
        if not key_ack and key_mic and secure:
            return 4
        return 0

    def packet_handler(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        # ── Packet pre-filtering: skip frame types we don't process ──
        dot11 = pkt.getlayer(Dot11)
        ftype = dot11.type
        fsubtype = dot11.subtype
        # Type 0 = Management, Type 2 = Data
        # Skip Control frames (type 1) entirely — we never process them
        if ftype == 1:
            return
        # For management frames, only process subtypes we handle:
        #   0=AssocReq, 2=ReassoReq, 4=ProbeReq, 5=ProbeResp, 8=Beacon,
        #   10=Disassoc, 12=Deauth
        if ftype == 0 and fsubtype not in (0, 2, 4, 5, 8, 10, 12):
            return

        self._packets_processed += 1
        rssi = -100
        if hasattr(pkt, 'dBm_AntSignal'):
            rssi = pkt.dBm_AntSignal
        elif hasattr(pkt, 'notdecoded'):
            try:
                nd = pkt.notdecoded
                nd_view = memoryview(nd) if isinstance(nd, (bytes, bytearray)) else nd
                rssi = -(256 - max(nd_view[-4], nd_view[-2]))
            except (TypeError, IndexError):
                pass

        # Show verbose packet info if enabled
        if self._verbose:
            self._log_verbose_packet(pkt, rssi)

        if pkt.haslayer(EAPOL):
            self._handle_eapol(pkt, rssi)
            return
        if pkt.haslayer(Dot11Beacon):
            self._handle_beacon(pkt, rssi)
        elif pkt.haslayer(Dot11ProbeReq):
            self._handle_probe_req(pkt, rssi)
        elif pkt.haslayer(Dot11ProbeResp):
            self._handle_probe_resp(pkt, rssi)
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self._handle_deauth(pkt, rssi)
        elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            self._handle_association(pkt, rssi)
        elif ftype == 2:
            self._handle_data(pkt, rssi)

    def _log_verbose_packet(self, pkt, rssi):
        """Log detailed info for every packet with color coding."""
        frame_type = "Data"
        color = Colors.OKCYAN
        
        # Determine frame type and color
        if pkt.haslayer(Dot11Beacon):
            frame_type = "Beacon"
            color = Colors.OKGREEN
            self._pkt_stats["Beacon"] += 1
        elif pkt.haslayer(Dot11ProbeReq):
            frame_type = "ProbeReq"
            color = Colors.OKBLUE
            self._pkt_stats["ProbeReq"] += 1
        elif pkt.haslayer(Dot11ProbeResp):
            frame_type = "ProbeResp"
            color = Colors.OKGREEN
            self._pkt_stats["ProbeResp"] += 1
        elif pkt.haslayer(Dot11Deauth):
            frame_type = "Deauth"
            color = Colors.FAIL
            self._pkt_stats["Deauth"] += 1
        elif pkt.haslayer(Dot11Disas):
            frame_type = "Disassoc"
            color = Colors.FAIL
            self._pkt_stats["Disassoc"] += 1
        elif pkt.haslayer(EAPOL):
            frame_type = "EAPOL"
            color = Colors.WARNING
            self._pkt_stats["EAPOL"] += 1
        elif pkt.haslayer(Dot11AssoReq):
            frame_type = "AssocReq"
            color = Colors.OKBLUE
            self._pkt_stats["AssocReq"] += 1
        elif pkt.haslayer(Dot11ReassoReq):
            frame_type = "ReassocReq"
            color = Colors.OKBLUE
            self._pkt_stats["ReassocReq"] += 1
        
        # Get BSSID and SSID info
        bssid = pkt.addr3 if hasattr(pkt, 'addr3') else "N/A"
        
        # Extract SSID if present
        ssid = ""
        if pkt.haslayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode(errors='ignore')
                    except Exception:
                        ssid = ""
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        
        # Color code the output
        if frame_type == "Beacon" and ssid:
            color = Colors.OKGREEN
        elif frame_type in ("Deauth", "Disassoc"):
            color = Colors.FAIL
        elif frame_type == "EAPOL":
            color = Colors.WARNING
        
        pkt_str = f"[{frame_type}] RSSI:{rssi}dBm | {bssid}"
        if ssid:
            pkt_str += f" | '{ssid}'"
        
        log.debug(Colors.color(pkt_str, color))

    def _handle_beacon(self, pkt, rssi):
        bssid = pkt.addr3
        if not bssid:
            return
        ssid_elt = pkt.getlayer(Dot11Elt)
        ssid = ""
        if ssid_elt and ssid_elt.ID == 0 and ssid_elt.info:
            ssid = ssid_elt.info.decode(errors='ignore')
        is_hidden = not ssid or all(c == '\x00' for c in ssid)
        vendor = self._get_vendor(bssid)
        security = self._get_security(pkt)
        channel = self._get_channel_from_ie(pkt)
        pos_flag = is_pos_vendor(vendor)
        self.db.update_ap(bssid, ssid, vendor, channel, security, rssi, pos_flag, is_hidden)
        if pos_flag:
            log.info(f"POS AP: {vendor} | {bssid} | '{ssid}' | Ch:{channel} | {security} | {rssi}dBm")
        elif is_pos_ssid(ssid):
            log.info(f"POS SSID: '{ssid}' | {bssid} | {vendor} | {rssi}dBm")

    def _handle_probe_req(self, pkt, rssi):
        client_mac = pkt.addr2
        if not client_mac:
            return
        ssid_elt = pkt.getlayer(Dot11Elt)
        probed_ssid = ""
        if ssid_elt and ssid_elt.ID == 0 and ssid_elt.info:
            probed_ssid = ssid_elt.info.decode(errors='ignore')
        vendor = self._get_vendor(client_mac)
        pos_flag = is_pos_vendor(vendor)
        self.db.update_client(client_mac, vendor, rssi, pos_flag, probed_ssid=probed_ssid or None)
        # Pass RSSI to signal targeting
        if self.signal_targeting:
            self.signal_targeting.add_sample(client_mac, None, rssi)
        if pos_flag:
            log.info(f"POS Probe: {vendor} | {client_mac} | '{probed_ssid}'")
        elif self._verbose:
            log.info(f"Probe: {client_mac} | '{probed_ssid}' | {vendor}")

    def _handle_probe_resp(self, pkt, rssi):
        bssid = pkt.addr3
        if not bssid:
            return
        ssid_elt = pkt.getlayer(Dot11Elt)
        ssid = ""
        if ssid_elt and ssid_elt.ID == 0 and ssid_elt.info:
            ssid = ssid_elt.info.decode(errors='ignore')
        if ssid:
            vendor = self._get_vendor(bssid)
            pos_flag = is_pos_vendor(vendor)
            self.db.update_ap(bssid, ssid, vendor, None, None, rssi, pos_flag, False)

    def _handle_deauth(self, pkt, rssi):
        src = pkt.addr2 or "unknown"
        dst = pkt.addr1 or WIFI_BROADCAST
        bssid = pkt.addr3 or src
        reason = 0
        if pkt.haslayer(Dot11Deauth):
            reason = pkt.getlayer(Dot11Deauth).reason
        elif pkt.haslayer(Dot11Disas):
            reason = pkt.getlayer(Dot11Disas).reason
        self.db.log_deauth(src, dst, bssid, reason)
        self._detect_deauth_flood(bssid)

    def _handle_eapol(self, pkt, rssi):
        ds_flags = pkt.FCfield & 0x3
        if ds_flags == 0x1:
            client_mac, bssid = pkt.addr2, pkt.addr1
        elif ds_flags == 0x2:
            client_mac, bssid = pkt.addr1, pkt.addr2
        else:
            client_mac, bssid = pkt.addr2, (pkt.addr3 or pkt.addr1)
        if not client_mac or not bssid:
            return
        eapol_layer = pkt.getlayer(EAPOL)
        if not eapol_layer:
            return
        eapol_raw = raw(eapol_layer)
        msg_num = self._identify_eapol_message(eapol_raw)
        if msg_num == 0:
            return
        key = (client_mac, bssid)
        # Only track pairwise handshake messages (1-4) in the 4-way tracker
        # Group key messages (5, 6) are logged but not added to the tracker
        if msg_num <= 4:
            self._eapol_tracker[key].add(msg_num)
        self.db.log_eapol(client_mac, bssid, msg_num)
        vendor = self._get_vendor(client_mac)
        captured = sorted(self._eapol_tracker[key])
        if len(self._eapol_tracker[key]) >= 4:
            log.info(f"FULL HANDSHAKE: {client_mac} ({vendor}) <-> {bssid} | M{captured}")
            del self._eapol_tracker[key]
        elif len(self._eapol_tracker[key]) >= 2:
            log.info(f"EAPOL M{msg_num}: {client_mac} ({vendor}) <-> {bssid} | {captured}")
            if is_pos_vendor(vendor):
                log.warning(f"POS HANDSHAKE: {vendor} | {client_mac} <-> {bssid}")

    def _handle_association(self, pkt, rssi):
        client_mac = pkt.addr2
        bssid = pkt.addr3 or pkt.addr1
        if not client_mac or not bssid or client_mac == bssid:
            return
        vendor = self._get_vendor(client_mac)
        pos_flag = is_pos_vendor(vendor)
        self.db.update_client(client_mac, vendor, rssi, pos_flag, associated_bssid=bssid)
        # Pass RSSI to signal targeting
        if self.signal_targeting:
            self.signal_targeting.add_sample(client_mac, bssid, rssi)
        if pos_flag:
            log.info(f"POS Association: {vendor} | {client_mac} -> {bssid}")

    def _handle_data(self, pkt, rssi):
        client_mac = pkt.addr2
        bssid = pkt.addr3
        if not client_mac or not bssid or client_mac == bssid or bssid == WIFI_BROADCAST:
            return
        vendor = self._get_vendor(client_mac)
        pos_flag = is_pos_vendor(vendor)
        self.db.update_client(client_mac, vendor, rssi, pos_flag, associated_bssid=bssid)
        # Pass RSSI to signal targeting
        if self.signal_targeting:
            self.signal_targeting.add_sample(client_mac, bssid, rssi)
        
        # Extract SSID from data frame for verbose output
        if self._verbose:
            elt = pkt.getlayer(Dot11Elt)
            ssid = ""
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode(errors='ignore')
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            if ssid:
                log.debug(Colors.color(f"[Data] {client_mac} -> {bssid} | '{ssid}'", Colors.OKCYAN))

    def _print_status(self):
        elapsed = time.time() - self._start_time
        if elapsed <= 0:
            return
        stats = self.db.get_stats()
        pps = self._packets_processed / elapsed
        
        # Build packet type summary
        pkt_summary = " | ".join(f"{k}:{v}" for k, v in sorted(self._pkt_stats.items()))
        if pkt_summary:
            pkt_summary = " | " + pkt_summary
        
        log.info(
            f"[STATUS] {elapsed:.0f}s | {self._packets_processed} pkts ({pps:.0f}/s) | "
            f"APs:{stats['access_points']} (POS:{stats['pos_access_points']}) | "
            f"Clients:{stats['clients']} (POS:{stats['pos_clients']}) | "
            f"Deauths:{stats['deauth_events']} | EAPOL:{stats['eapol_frames']} | "
            f"Creds:{stats['credentials']}{pkt_summary}"
        )

    def _status_loop(self):
        while self.running:
            time.sleep(STATUS_INTERVAL)
            if self.running:
                self._print_status()

    def start(self, timeout=None):
        self.running = True
        self._stop_event.clear()
        self._start_time = time.time()
        self._packets_processed = 0
        
        # Setup monitor mode (platform-appropriate)
        if IS_WINDOWS or IS_LINUX:
            platform_name = "Windows" if IS_WINDOWS else "Linux"
            log.info(f"Configuring {platform_name} monitor mode...")
            from .monitor_mode import setup_monitor_mode
            success, manager = setup_monitor_mode(self.interface)
            if success:
                self._monitor_manager = manager
                # Update interface name if it was renamed (Linux monitor mode)
                if hasattr(manager, 'interface'):
                    self.interface = manager.interface
                log.info(f"{platform_name} monitor mode configured successfully")
            else:
                log.warning("Monitor mode setup failed, using native capture mode")
        
        # Start live decryption session if PSK is provided
        if self._tshark_psk:
            self._start_decrypt_session()

        # Start intel enricher if provided
        if self._intel_enricher:
            try:
                tools_started = self._intel_enricher.start()
                if tools_started > 0:
                    log.info(f"Intel enrichment active: {tools_started} background tool(s)")
            except Exception as e:
                log.warning(f"Intel enricher failed to start: {e}")
        
        log.info(f"Recon active on {self.interface} | Channels: {self.channels}")
        if self.channel_hop:
            # Filter channels to only those the adapter supports
            self._filter_supported_channels()
            threading.Thread(target=self._hop_channels, daemon=True).start()
        threading.Thread(target=self._status_loop, daemon=True).start()
        try:
            # Try tshark first, fall back to scapy
            if self._try_tshark_capture(timeout):
                log.info("Using Wireshark/tshark for packet capture")
            else:
                log.info("Using scapy for packet capture")
                sniff(iface=self.interface, prn=self.packet_handler, store=0,
                      timeout=timeout,
                      stop_filter=lambda _: self._stop_event.is_set())
        except SystemExit:
            pass
        finally:
            try:
                self.db.flush()
            except Exception:
                pass

    def _try_tshark_capture(self, timeout):
        """Attempt to use tshark for capture, return True if successful."""
        try:
            capture = WiresharkCapture(self.interface, timeout=timeout)
            if capture.start():
                # Run capture for specified timeout
                if timeout:
                    # Sleep in small increments to allow early stop
                    end_time = time.time() + timeout
                    while self.running and not self._stop_event.is_set():
                        remaining = end_time - time.time()
                        if remaining <= 0:
                            break
                        time.sleep(min(0.5, remaining))
                else:
                    while self.running and not self._stop_event.is_set():
                        time.sleep(0.5)
                capture.stop()
                # Process captured packets
                for pkt in capture.get_packets():
                    self.packet_handler(pkt)
                return True
        except Exception as e:
            log.warning(f"tshark capture failed: {e}")
        return False

    def stop(self):
        self.running = False
        self._stop_event.set()
        self._print_status()

        # Stop intel enricher
        if self._intel_enricher:
            try:
                self._intel_enricher.stop()
            except Exception as e:
                log.debug(f"Intel enricher stop error: {e}")
        
        # Stop live decryption session
        if self._decrypt_session:
            log.info("Stopping live decryption session...")
            self._decrypt_session.stop()
            summary = self._decrypt_session.get_decrypted_summary()
            log.info(
                f"Decryption summary: {summary['frame_count']} frames, "
                f"{len(summary['dns_queries'])} DNS, "
                f"{len(summary['http_requests'])} HTTP, "
                f"{len(summary['dhcp_leases'])} DHCP, "
                f"{len(summary['credentials'])} credentials"
            )
            # Log pyWhat attack surface findings if enabled
            if self._pywhat_callback:
                surfaces = self._pywhat_callback.analyzer.get_attack_surfaces()
                total_findings = sum(len(v) for v in surfaces.values())
                if total_findings > 0:
                    log.info(
                        f"[PYWHAT] Attack surfaces identified: {total_findings} total - "
                        f"creds:{len(surfaces['credentials'])}, "
                        f"keys:{len(surfaces['keys'])}, "
                        f"network:{len(surfaces['network'])}, "
                        f"hashes:{len(surfaces['hashes'])}, "
                        f"financial:{len(surfaces['financial'])}, "
                        f"crypto:{len(surfaces['crypto'])}"
                    )
                self._pywhat_callback = None
            self._decrypt_session = None
        
        # Teardown monitor mode (both platforms)
        if self._monitor_manager:
            platform_name = "Windows" if IS_WINDOWS else "Linux"
            log.info(f"Tearing down {platform_name} monitor mode...")
            from .monitor_mode import teardown_monitor_mode
            teardown_monitor_mode(self._monitor_manager)
            self._monitor_manager = None

    def set_signal_targeting(self, signal_targeting):
        """Set the signal targeting instance for RSSI sample collection."""
        self.signal_targeting = signal_targeting

    def _start_decrypt_session(self):
        """Start a live tshark decryption session alongside the scapy sniffer."""
        # Determine callback: use PyWhatCallback wrapping our handler if enabled
        if self._pywhat_enabled:
            self._pywhat_callback = PyWhatCallback(
                chain=self._handle_decrypted_data
            )
            callback = self._pywhat_callback
            log.info("pyWhat attack surface analysis enabled for decrypted traffic")
        else:
            callback = self._handle_decrypted_data

        session = LiveDecryptionSession(callback=callback)
        started = session.start(
            interface=self.interface,
            psk=self._tshark_psk,
            ssid=self._tshark_ssid,
        )
        if started:
            self._decrypt_session = session
            log.info(
                f"Live decryption active (SSID: {self._tshark_ssid or 'auto'})"
            )
        else:
            log.warning("Live decryption session failed to start")

    def _handle_decrypted_data(self, event):
        """
        Callback for LiveDecryptionSession decrypted data.

        Logs decrypted traffic summaries and stores them in the database.

        Args:
            event: Dict with keys: protocol, data, timestamp.
        """
        protocol = event.get("protocol", "")
        data = event.get("data", {})

        if protocol == "dns":
            query = data.get("query", "")
            response = data.get("response", "")
            if query:
                log.info(f"[DECRYPT] DNS: {query} -> {response}")
        elif protocol == "http":
            host = data.get("host", "")
            method = data.get("method", "")
            uri = data.get("uri", "")
            if host:
                log.info(f"[DECRYPT] HTTP: {method} {host}{uri}")
        elif protocol == "dhcp":
            hostname = data.get("hostname", "")
            mac = data.get("mac_addr", "")
            if hostname:
                log.info(f"[DECRYPT] DHCP: {hostname} ({mac})")
        elif protocol == "eapol":
            source = data.get("source", "")
            bssid = data.get("bssid", "")
            log.info(f"[DECRYPT] EAPOL: {source} <-> {bssid}")

        # Store decrypted event in database
        try:
            self.db.log_decrypted_event(protocol, data)
        except (AttributeError, TypeError):
            # Database does not implement log_decrypted_event;
            # data is retained in the LiveDecryptionSession summary instead.
            log.debug(f"[DECRYPT] Stored event: {protocol}")
    
    def enable_verbose(self):
        """Enable verbose mode to show all packets, not just POS."""
        self._verbose = True
        self._pkt_stats.clear()
        log.info("Verbose mode enabled - showing all packets")
