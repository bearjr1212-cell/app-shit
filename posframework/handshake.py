"""
WPA Handshake Capture to PCAP
─────────────────────────────
Capture EAPOL 4-way handshake frames and write to PCAP file
for offline cracking with hashcat or aircrack-ng.

Includes:
  - HandshakeCapture: storage/export class for handshake frames
  - HandshakeSniffer: autonomous real-time sniffer with auto-assembly
  - build_eapol_frame: synthetic EAPOL frame builder

Enhanced features:
  - Handshake deduplication (skip already-exported pairs)
  - Hashcat .hccapx (mode 2500) and .22000 (mode 22000) export
  - FT (802.11r / Fast Transition) handshake detection
  - Beacon frame caching and prepend to PCAP exports
"""

import os
import time
import struct
import threading

from scapy.all import wrpcap, Raw, ARP, IP, TCP, UDP, sendp, sniff, raw
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL

from .config import log


class HandshakeCapture:
    """
    Capture WPA 4-way handshakes and export to PCAP file.
    Records client MAC, BSSID, and all 4 handshake messages.

    Enhanced with:
      - Deduplication: tracks already-exported pairs to prevent re-export
      - Hashcat export: .hccapx (mode 2500) and .22000 (mode 22000) formats
      - Beacon cache: stores beacon frames per BSSID for PCAP prepend
    """

    def __init__(self, output_dir="handshakes"):
        self.output_dir = output_dir
        self._capture = {}  # (client_mac, bssid) -> {messages: set(), frames: []}
        self._started_at = time.time()
        self._exported_pairs = set()  # dedup: (client_mac, bssid) already exported
        self._beacon_cache = {}  # bssid -> beacon_frame
        self._essid_cache = {}  # bssid -> essid string
        os.makedirs(output_dir, exist_ok=True)

    def add_frame(self, client_mac, bssid, frame, msg_num):
        """Add an EAPOL frame to the handshake capture."""
        key = (client_mac, bssid)
        # Dedup check: skip if already exported
        if key in self._exported_pairs:
            log.info(f"Handshake dedup: skipping {client_mac} <-> {bssid} (already exported)")
            return
        if key not in self._capture:
            self._capture[key] = {"messages": set(), "frames": []}
        self._capture[key]["messages"].add(msg_num)
        self._capture[key]["frames"].append(frame)
        log.info(f"Handshake captured: {client_mac} <-> {bssid} (Message {msg_num})")

    def add_beacon(self, bssid, beacon_frame, essid=None):
        """Cache a beacon frame for a BSSID."""
        bssid = bssid.lower()
        self._beacon_cache[bssid] = beacon_frame
        if essid:
            self._essid_cache[bssid] = essid

    def get_handshake_status(self, client_mac, bssid):
        """Check handshake progress for a client/AP pair."""
        key = (client_mac, bssid)
        if key not in self._capture:
            return 0, []
        return len(self._capture[key]["messages"]), self._capture[key]["frames"]

    def is_complete(self, client_mac, bssid):
        """Check if all 4 handshake messages were captured."""
        key = (client_mac, bssid)
        if key not in self._capture:
            return False
        return len(self._capture[key]["messages"]) >= 4

    def export_pcap(self, client_mac, bssid):
        """
        Export captured handshake to PCAP file.
        Prepends cached beacon frame if available.
        Returns None if pair was already exported (dedup).
        """
        key = (client_mac, bssid)
        if key not in self._capture:
            return None

        # Dedup: if already exported, return None
        if key in self._exported_pairs:
            return None

        filename = os.path.join(
            self.output_dir,
            f"hs_{client_mac.replace(':', '')}_{bssid.replace(':', '')}_{int(time.time())}.pcap"
        )

        frames = []
        # Prepend beacon frame if cached for this BSSID
        if bssid.lower() in self._beacon_cache:
            frames.append(self._beacon_cache[bssid.lower()])
        frames.extend(self._capture[key]["frames"])

        wrpcap(filename, frames)
        log.critical(f"Handshake PCAP saved: {filename}")

        # Mark as exported for dedup
        self._exported_pairs.add(key)
        del self._capture[key]
        return filename

    def export_hccapx(self, client_mac, bssid, filename=None):
        """
        Export captured handshake in hashcat .hccapx format (mode 2500).

        Binary format fields:
            - Signature: HCCAPX\\x04 (7 bytes)
            - ESSID length (4 bytes LE)
            - ESSID (32 bytes padded)
            - Key version (1 byte)
            - Key MIC (16 bytes)
            - MAC AP (6 bytes)
            - MAC STA (6 bytes)
            - ANonce (32 bytes)
            - SNonce (32 bytes)
            - EAPOL length (2 bytes LE)
            - EAPOL data (256 bytes padded)
            - Message pair (1 byte)

        Args:
            client_mac: Client MAC address
            bssid: AP BSSID
            filename: Output filename. If None, auto-generated.

        Returns:
            Output filename or None if handshake not found/incomplete.
        """
        key = (client_mac, bssid)
        if key not in self._capture:
            return None

        data = self._capture[key]
        if len(data["messages"]) < 2:
            return None

        frames = data["frames"]

        # Extract ANonce, SNonce, key MIC and EAPOL from frames
        anonce = b"\x00" * 32
        snonce = b"\x00" * 32
        keymic = b"\x00" * 16
        keyver = 0
        eapol_frame_data = b""

        for frame in frames:
            if frame.haslayer(EAPOL):
                eapol_data = raw(frame.getlayer(EAPOL))
                if len(eapol_data) < 99:
                    continue

                key_info = (eapol_data[5] << 8) | eapol_data[6]
                ack = bool(key_info & 0x0080)
                mic = bool(key_info & 0x0100)

                # Key version from bits 0-2
                keyver = key_info & 0x0007

                # ANonce from Message 1 or 3 (ACK set)
                if ack and not mic:
                    # Message 1
                    anonce = eapol_data[17:49]
                elif ack and mic:
                    # Message 3
                    anonce = eapol_data[17:49]

                # SNonce from Message 2 (no ACK, has MIC)
                if not ack and mic:
                    snonce = eapol_data[17:49]
                    keymic = eapol_data[81:97]
                    eapol_frame_data = eapol_data

        if filename is None:
            filename = os.path.join(
                self.output_dir,
                f"hs_{client_mac.replace(':', '')}_{bssid.replace(':', '')}_{int(time.time())}.hccapx"
            )

        # Get ESSID
        essid = self._essid_cache.get(bssid.lower(), "")
        essid_bytes = essid.encode("utf-8")[:32]

        # Build hccapx binary structure
        hccapx = b""
        # Signature: HCCAPX\x04
        hccapx += b"HCCAPX\x04"
        # ESSID length (4 bytes LE)
        hccapx += struct.pack("<I", len(essid_bytes))
        # ESSID (32 bytes padded)
        hccapx += essid_bytes.ljust(32, b"\x00")
        # Key version (1 byte)
        hccapx += struct.pack("B", keyver)
        # Key MIC (16 bytes)
        hccapx += keymic[:16].ljust(16, b"\x00")
        # MAC AP (6 bytes)
        mac_ap_bytes = bytes.fromhex(bssid.replace(":", ""))
        hccapx += mac_ap_bytes[:6].ljust(6, b"\x00")
        # MAC STA (6 bytes)
        mac_sta_bytes = bytes.fromhex(client_mac.replace(":", ""))
        hccapx += mac_sta_bytes[:6].ljust(6, b"\x00")
        # ANonce (32 bytes)
        hccapx += anonce[:32].ljust(32, b"\x00")
        # SNonce (32 bytes)
        hccapx += snonce[:32].ljust(32, b"\x00")
        # EAPOL length (2 bytes LE)
        eapol_len = len(eapol_frame_data)
        hccapx += struct.pack("<H", min(eapol_len, 256))
        # EAPOL data (256 bytes padded)
        hccapx += eapol_frame_data[:256].ljust(256, b"\x00")
        # Message pair (1 byte) - derived from actual captured messages
        # 0 = M1+M2, 2 = M2+M3, 5 = M3+M4
        messages = data["messages"]
        if 1 in messages and 2 in messages:
            msg_pair = 0  # M1+M2 pair
        elif 2 in messages and 3 in messages:
            msg_pair = 2  # M2+M3 pair
        elif 3 in messages and 4 in messages:
            msg_pair = 5  # M3+M4 pair
        else:
            msg_pair = 0  # default fallback
        hccapx += struct.pack("B", msg_pair)

        with open(filename, "wb") as f:
            f.write(hccapx)

        log.critical(f"Handshake hccapx saved: {filename}")
        return filename

    def export_22000(self, client_mac, bssid, filename=None):
        """
        Export captured handshake in hashcat mode 22000 format.

        Format: WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL

        Args:
            client_mac: Client MAC address
            bssid: AP BSSID
            filename: Output filename. If None, auto-generated.

        Returns:
            Output filename or None if handshake not found/incomplete.
        """
        key = (client_mac, bssid)
        if key not in self._capture:
            return None

        data = self._capture[key]
        if len(data["messages"]) < 2:
            return None

        frames = data["frames"]

        # Extract ANonce, MIC, and EAPOL from frames
        anonce_hex = "0" * 64
        mic_hex = "0" * 32
        eapol_hex = ""

        for frame in frames:
            if frame.haslayer(EAPOL):
                eapol_data = raw(frame.getlayer(EAPOL))
                if len(eapol_data) < 99:
                    continue

                key_info = (eapol_data[5] << 8) | eapol_data[6]
                ack = bool(key_info & 0x0080)
                mic = bool(key_info & 0x0100)

                # ANonce from Message 1 or 3
                if ack and not mic:
                    anonce_hex = eapol_data[17:49].hex()
                elif ack and mic:
                    anonce_hex = eapol_data[17:49].hex()

                # MIC and EAPOL from Message 2
                if not ack and mic:
                    mic_hex = eapol_data[81:97].hex()
                    # Zero out MIC in EAPOL for hashcat
                    eapol_zeroed = bytearray(eapol_data)
                    eapol_zeroed[81:97] = b"\x00" * 16
                    eapol_hex = bytes(eapol_zeroed).hex()

        if not eapol_hex:
            return None

        if filename is None:
            filename = os.path.join(
                self.output_dir,
                f"hs_{client_mac.replace(':', '')}_{bssid.replace(':', '')}_{int(time.time())}.22000"
            )

        # Get ESSID
        essid = self._essid_cache.get(bssid.lower(), "")
        essid_hex = essid.encode("utf-8").hex() if essid else ""

        mac_ap_hex = bssid.replace(":", "")
        mac_sta_hex = client_mac.replace(":", "")

        line = f"WPA*02*{mic_hex}*{mac_ap_hex}*{mac_sta_hex}*{essid_hex}*{anonce_hex}*{eapol_hex}"

        with open(filename, "w") as f:
            f.write(line + "\n")

        log.critical(f"Handshake hashcat 22000 saved: {filename}")
        return filename

    def clear_dedup(self):
        """Reset the deduplication tracking set."""
        self._exported_pairs.clear()
        log.info("Handshake dedup state cleared")

    def export_all(self):
        """Export all complete handshakes."""
        exported = []
        for key, data in list(self._capture.items()):
            if len(data["messages"]) >= 4:
                client_mac, bssid = key
                filename = self.export_pcap(client_mac, bssid)
                if filename:
                    exported.append(filename)
        return exported

    def has_handshake_for_bssid(self, bssid, min_frames=2):
        """
        Check if a handshake (at least min_frames EAPOL messages) exists
        for any client associated with the given BSSID.

        This is the stable public API for checking handshake availability.
        Consumers should use this instead of accessing internal _capture dict.

        Args:
            bssid: AP BSSID to check (case-insensitive).
            min_frames: Minimum number of EAPOL messages required (default 2
                        for M1+M2, set to 4 for full 4-way handshake).

        Returns:
            True if a handshake meeting the threshold exists.
        """
        bssid_lower = bssid.lower()
        for (client_mac, cap_bssid), data in self._capture.items():
            if cap_bssid.lower() == bssid_lower:
                if len(data["messages"]) >= min_frames:
                    return True
        return False

    def export_pcap_for_bssid(self, bssid):
        """
        Export handshake PCAP for the first complete capture matching a BSSID.

        Args:
            bssid: AP BSSID to export for (case-insensitive).

        Returns:
            Filename of the exported PCAP, or None if no suitable capture found.
        """
        bssid_lower = bssid.lower()
        for (client_mac, cap_bssid), data in list(self._capture.items()):
            if cap_bssid.lower() == bssid_lower and len(data["messages"]) >= 2:
                return self.export_pcap(client_mac, cap_bssid)
        return None

    def get_stats(self):
        """Return capture statistics."""
        total = sum(1 for d in self._capture.values() if len(d["messages"]) >= 4)
        partial = sum(1 for d in self._capture.values() if 1 <= len(d["messages"]) < 4)
        return {
            "complete": total,
            "partial": partial,
            "total_entries": len(self._capture),
            "exported_pairs": len(self._exported_pairs),
            "cached_beacons": len(self._beacon_cache)
        }


class HandshakeSniffer:
    """
    Autonomous real-time EAPOL handshake sniffer.

    Monitors a wireless interface for EAPOL 4-way handshake frames,
    automatically identifies message numbers, tracks assembly per
    (client_mac, bssid) pair, and exports complete handshakes to PCAP.

    Usage:
        sniffer = HandshakeSniffer("wlan0mon", target_bssid="AA:BB:CC:DD:EE:FF")
        sniffer.start()
        # ... wait for handshakes ...
        sniffer.stop()
        print(sniffer.get_stats())
    """

    def __init__(self, interface, target_bssid=None, output_dir="handshakes",
                 callback=None):
        """
        Initialize handshake sniffer.

        Args:
            interface: Wireless interface in monitor mode
            target_bssid: Optional BSSID filter (only capture for this AP)
            output_dir: Directory for PCAP output files
            callback: Optional callable(client_mac, bssid, filename) invoked
                      when a complete 4-way handshake is captured
        """
        self.interface = interface
        self.target_bssid = target_bssid.lower() if target_bssid else None
        self.output_dir = output_dir
        self.callback = callback
        self.running = False
        self._thread = None
        self._capture = HandshakeCapture(output_dir=output_dir)
        self._completed = []  # list of completed handshake filenames
        self._lock = threading.Lock()
        self._beacon_cache = {}  # bssid -> beacon_frame
        self._ft_handshakes = {}  # (client_mac, bssid) -> {frame, timestamp}

    def start(self):
        """Start the handshake sniffer thread."""
        if self.running:
            log.warning("HandshakeSniffer is already running")
            return

        self.running = True
        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )
        self._thread.start()
        log.info(
            f"HandshakeSniffer started on {self.interface}"
            f"{' (target: ' + self.target_bssid + ')' if self.target_bssid else ''}"
        )

    def _sniff_loop(self):
        """Main sniff loop - captures EAPOL frames and processes them."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_frame,
                store=False,
                filter="ether proto 0x888e",
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            if self.running:
                log.error(f"HandshakeSniffer sniff error: {e}")
                # Fallback: sniff without BPF filter and manually filter
                try:
                    sniff(
                        iface=self.interface,
                        prn=self._process_frame_unfiltered,
                        store=False,
                        stop_filter=lambda x: not self.running
                    )
                except Exception as e2:
                    log.error(f"HandshakeSniffer fallback sniff failed: {e2}")

    def _process_frame_unfiltered(self, pkt):
        """Process frames without BPF filter - manually check for EAPOL, beacons, FT."""
        # Capture beacon frames for ESSID extraction and PCAP prepend
        if pkt.haslayer(Dot11Beacon):
            self._cache_beacon(pkt)

        # Detect FT (802.11r) reassociation frames
        if pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            # Reassociation Request: type=0 (Management), subtype=2
            if dot11.type == 0 and dot11.subtype == 2:
                self._process_ft_frame(pkt)

        if pkt.haslayer(EAPOL):
            self._process_frame(pkt)

    def _process_frame(self, pkt):
        """
        Process a captured frame containing EAPOL data.
        Identifies the message number and adds to assembly tracking.
        """
        if not pkt.haslayer(EAPOL):
            return

        # Extract MAC addresses from Dot11 layer
        if pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            # Determine client and BSSID based on frame direction
            # To-DS: addr1=BSSID, addr2=client, addr3=destination
            # From-DS: addr1=client, addr2=BSSID, addr3=source
            fc_field = dot11.FCfield if hasattr(dot11, 'FCfield') else 0
            to_ds = fc_field & 0x01
            from_ds = fc_field & 0x02

            if to_ds and not from_ds:
                # Client to AP
                bssid = dot11.addr1
                client_mac = dot11.addr2
            elif from_ds and not to_ds:
                # AP to Client
                client_mac = dot11.addr1
                bssid = dot11.addr2
            else:
                # Fallback: addr1=dest, addr2=src, addr3=bssid
                bssid = dot11.addr3 if dot11.addr3 else dot11.addr1
                client_mac = dot11.addr2
        else:
            # No Dot11 layer - cannot determine MACs
            return

        if not bssid or not client_mac:
            return

        bssid = bssid.lower()
        client_mac = client_mac.lower()

        # Apply target BSSID filter
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Get EAPOL data and identify message number
        eapol_data = raw(pkt.getlayer(EAPOL))
        msg_num = self._identify_eapol_msg(eapol_data)

        if msg_num is None:
            return

        # Add frame to capture
        with self._lock:
            self._capture.add_frame(client_mac, bssid, pkt, msg_num)

            # Check if handshake is complete
            if self._capture.is_complete(client_mac, bssid):
                filename = self._capture.export_pcap(client_mac, bssid)
                if filename:
                    self._completed.append(filename)
                    log.critical(
                        f"Complete 4-way handshake captured: "
                        f"{client_mac} <-> {bssid} -> {filename}"
                    )
                    # Invoke callback if provided
                    if self.callback:
                        try:
                            self.callback(client_mac, bssid, filename)
                        except Exception as e:
                            log.error(f"Handshake callback error: {e}")

    def _identify_eapol_msg(self, eapol_data):
        """
        Identify EAPOL message number from key info field.

        Key Info bit layout (after EAPOL header):
            Bit 3: Install
            Bit 6: ACK (set by AP in Messages 1 and 3)
            Bit 8: MIC (set when MIC is present, Messages 2, 3, 4)
            Bit 9: Secure (set in Message 4)

        Returns message number (1-4) or None if unidentifiable.
        """
        try:
            if len(eapol_data) < 7:
                return None

            # EAPOL-Key frame structure:
            # Byte 0-3: EAPOL header (version, type, length)
            # Byte 4: Key Descriptor Type
            # Byte 5-6: Key Information (big-endian in wire format)
            key_info = (eapol_data[5] << 8) | eapol_data[6]

            # Extract relevant bits
            install = bool(key_info & 0x0040)  # Bit 6 (Install)
            ack = bool(key_info & 0x0080)      # Bit 7 (ACK)
            mic = bool(key_info & 0x0100)      # Bit 8 (MIC)
            secure = bool(key_info & 0x0200)   # Bit 9 (Secure)

            if ack and not mic:
                return 1  # Message 1: ACK set, no MIC (AP -> Client)
            elif not ack and mic and not install:
                return 2  # Message 2: MIC set, no ACK, no Install (Client -> AP)
            elif ack and mic and install:
                return 3  # Message 3: ACK, MIC, Install (AP -> Client)
            elif not ack and mic and secure:
                return 4  # Message 4: MIC, Secure, no ACK (Client -> AP)

        except (IndexError, TypeError):
            pass

        return None

    def _cache_beacon(self, pkt):
        """
        Cache beacon frames for BSSID ESSID extraction and PCAP prepend.

        Stores the most recent beacon frame per BSSID and forwards
        it to the HandshakeCapture instance for PCAP export prepend.
        """
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        if not bssid:
            return

        bssid = bssid.lower()

        # Apply target BSSID filter
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Extract ESSID from information elements
        essid = None
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID parameter set
                try:
                    essid = elt.info.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    pass
                break
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None

        with self._lock:
            self._beacon_cache[bssid] = pkt
            self._capture.add_beacon(bssid, pkt, essid=essid)

        log.info(f"Beacon cached for {bssid} (ESSID: {essid or 'hidden'})")

    def _process_ft_frame(self, pkt):
        """
        Detect 802.11r (Fast Transition) reassociation frames.

        FT handshakes use reassociation frames (management type=0, subtype=2)
        with FT authentication algorithm (auth_algo=2). These frames contain
        FTIE (Fast Transition IE), MDIE (Mobility Domain IE), and RSNIE
        that constitute a valid FT handshake without the standard 4-way.

        Detected FT handshakes are stored separately and logged.
        """
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        # Reassociation Request: type=0 (Management), subtype=2
        if dot11.type != 0 or dot11.subtype != 2:
            return

        # Extract addresses from reassociation frame
        # addr1=BSSID (destination AP), addr2=client (source), addr3=BSSID
        bssid = dot11.addr1
        client_mac = dot11.addr2

        if not bssid or not client_mac:
            return

        bssid = bssid.lower()
        client_mac = client_mac.lower()

        # Apply target BSSID filter
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Check for FT-specific Information Elements in the frame body
        # Look for MDIE (ID=54), FTIE (ID=55), RSNIE (ID=48)
        has_mdie = False
        has_ftie = False
        has_rsnie = False

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 54:   # Mobility Domain IE (MDIE)
                has_mdie = True
            elif elt.ID == 55:  # Fast Transition IE (FTIE)
                has_ftie = True
            elif elt.ID == 48:  # RSN IE
                has_rsnie = True
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None

        # Valid FT handshake requires at least MDIE
        if not has_mdie:
            return

        key = (client_mac, bssid)
        with self._lock:
            self._ft_handshakes[key] = {
                "frame": pkt,
                "timestamp": time.time(),
                "has_mdie": has_mdie,
                "has_ftie": has_ftie,
                "has_rsnie": has_rsnie,
                "type": "ft_handshake"
            }

        log.critical(
            f"FT (802.11r) handshake detected: {client_mac} -> {bssid} "
            f"(MDIE={'Y' if has_mdie else 'N'} FTIE={'Y' if has_ftie else 'N'} "
            f"RSNIE={'Y' if has_rsnie else 'N'})"
        )

    def get_ft_handshakes(self):
        """Return all detected FT (802.11r) handshakes."""
        with self._lock:
            return dict(self._ft_handshakes)

    def stop(self):
        """Stop the handshake sniffer and wait for thread cleanup."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        log.info("HandshakeSniffer stopped")

    def get_completed(self):
        """Return list of completed handshake PCAP filenames."""
        with self._lock:
            return list(self._completed)

    def get_stats(self):
        """Return sniffer statistics."""
        with self._lock:
            capture_stats = self._capture.get_stats()
        return {
            "running": self.running,
            "interface": self.interface,
            "target_bssid": self.target_bssid,
            "completed_handshakes": len(self._completed),
            "ft_handshakes": len(self._ft_handshakes),
            "cached_beacons": len(self._beacon_cache),
            "capture": capture_stats
        }


def build_eapol_frame(msg_num, key_info_bits, client_mac, bssid, nonce, replay_counter=1):
    """
    Build a synthetic EAPOL-Key frame for PCAP export or testing.

    Key Info: bits 0-15
        bit 6: Install
        bit 7: Key ACK
        bit 8: Key MIC
        bit 9: Secure

    Args:
        msg_num: EAPOL message number (1-4, for logging)
        key_info_bits: Raw key_info value
        client_mac: Client MAC address string
        bssid: AP BSSID string
        nonce: 32-byte nonce (ANonce or SNonce)
        replay_counter: 8-byte replay counter value

    Returns:
        Scapy packet (RadioTap/Dot11/Raw with EAPOL data)
    """
    # EAPOL header: version=1, type=3 (EAPOL-Key), length=125
    eapol_header = struct.pack(">BBH", 1, 3, 125)

    # EAPOL-Key header
    key_type = 2  # WPA2 (RSN)
    key_info = struct.pack("<H", key_info_bits)
    key_length = struct.pack(">H", 16)  # AES-CCMP
    replay_bytes = struct.pack(">Q", replay_counter)
    nonce = nonce[:32] if len(nonce) >= 32 else nonce + b"\x00" * (32 - len(nonce))
    key_iv = b"\x00" * 16
    key_rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    key_signature = b"\x00" * 16

    eapol_key = (
        struct.pack("B", key_type) +
        key_info + key_length + replay_bytes +
        nonce + key_iv + key_rsc + key_id + key_signature
    )

    # RadioTap header
    radiotap = RadioTap()

    # Dot11 frame (data frame type for EAPOL)
    dot11 = Dot11(
        type=2,      # Data frame
        subtype=0,
        addr1=bssid,
        addr2=client_mac,
        addr3=bssid
    )

    # EAPOL layer as raw bytes
    eapol = Raw(load=eapol_header + eapol_key)

    frame = radiotap / dot11 / eapol
    return frame
