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
from functools import lru_cache
from collections import defaultdict

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
from .wireshark_capture import WiresharkCapture
from .monitor_mode import (
    setup_monitor_mode, teardown_monitor_mode,
    WindowsMonitorManager, check_npcap_monitor_support
)


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

    def __init__(self, interface, db, channels=None, channel_hop=True):
        self.interface = interface
        self.db = db
        self.channels = channels or CHANNELS_24GHZ
        self.channel_hop = channel_hop
        self.running = False
        self.parser = manuf.MacParser(update=False)
        self._deauth_times = defaultdict(list)
        self._eapol_tracker = defaultdict(set)
        self._packets_processed = 0
        self._start_time = 0.0
        self._verbose = False
        # Packet type counters for summary stats
        self._pkt_stats = defaultdict(int)
        
        # Monitor mode manager
        self._monitor_manager = None

    @lru_cache(maxsize=16384)
    def _get_vendor(self, mac: str) -> str:
        try:
            v = self.parser.get_manuf(mac)
            return v if v else "Unknown"
        except Exception:
            return "Unknown"

    def _set_channel(self, channel: int):
        """Set channel — Linux uses iw, Windows skips (Npcap handles it)."""
        if IS_WINDOWS:
            return  # Windows Npcap doesn't support manual channel hopping
        try:
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def _hop_channels(self):
        idx = 0
        while self.running:
            self._set_channel(self.channels[idx])
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
        if len(eapol_raw) < 10:
            return 0
        key_info = struct.unpack(">H", eapol_raw[5:7])[0]
        key_ack = (key_info >> 7) & 1
        key_mic = (key_info >> 8) & 1
        secure = (key_info >> 9) & 1
        install = (key_info >> 6) & 1
        if key_ack and not key_mic:
            return 1
        if not key_ack and key_mic and not secure:
            return 2
        if key_ack and key_mic and install:
            return 3
        if not key_ack and key_mic and secure:
            return 4
        return 0

    def packet_handler(self, pkt):
        if not pkt.haslayer(Dot11):
            return
        self._packets_processed += 1
        rssi = -100
        if hasattr(pkt, 'dBm_AntSignal'):
            rssi = pkt.dBm_AntSignal
        elif hasattr(pkt, 'notdecoded'):
            try:
                rssi = -(256 - max(ord(pkt.notdecoded[-4:-3]), ord(pkt.notdecoded[-2:-1])))
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
        elif pkt.type == 2:
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
        
        print(Colors.color(pkt_str, color))

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
                print(Colors.color(f"[Data] {client_mac} -> {bssid} | '{ssid}'", Colors.OKCYAN))

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
        self._start_time = time.time()
        self._packets_processed = 0
        
        # Setup monitor mode on Windows
        if IS_WINDOWS:
            log.info("Configuring Windows monitor mode...")
            from .monitor_mode import setup_monitor_mode
            success, manager = setup_monitor_mode(self.interface)
            if success:
                self._monitor_manager = manager
                log.info("Windows monitor mode configured successfully")
            else:
                log.warning("Monitor mode setup failed, using native capture mode")
        
        log.info(f"Recon active on {self.interface} | Channels: {self.channels}")
        if self.channel_hop:
            threading.Thread(target=self._hop_channels, daemon=True).start()
        threading.Thread(target=self._status_loop, daemon=True).start()
        try:
            # Try tshark first, fall back to scapy
            if self._try_tshark_capture(timeout):
                log.info("Using Wireshark/tshark for packet capture")
            else:
                log.info("Using scapy for packet capture")
                sniff(iface=self.interface, prn=self.packet_handler, store=0, timeout=timeout)
        finally:
            self.db.flush()

    def _try_tshark_capture(self, timeout):
        """Attempt to use tshark for capture, return True if successful."""
        try:
            capture = WiresharkCapture(self.interface, timeout=timeout)
            if capture.start():
                # Run capture for specified timeout
                if timeout:
                    time.sleep(timeout)
                else:
                    while self.running:
                        time.sleep(1)
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
        self._print_status()
        
        # Teardown monitor mode on Windows
        if IS_WINDOWS and self._monitor_manager:
            log.info("Tearing down Windows monitor mode...")
            from .monitor_mode import teardown_monitor_mode
            teardown_monitor_mode(self._monitor_manager)
            self._monitor_manager = None

    def enable_verbose(self):
        """Enable verbose mode to show all packets, not just POS."""
        self._verbose = True
        self._pkt_stats.clear()
        log.info("Verbose mode enabled - showing all packets")
