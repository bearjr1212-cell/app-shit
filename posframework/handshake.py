"""
WPA Handshake Capture to PCAP
─────────────────────────────
Capture EAPOL 4-way handshake frames and write to PCAP file
for offline cracking with hashcat or aircrack-ng.

Includes:
  - HandshakeCapture: storage/export class for handshake frames
  - HandshakeSniffer: autonomous real-time sniffer with auto-assembly
  - build_eapol_frame: synthetic EAPOL frame builder
"""

import os
import time
import struct
import threading

from scapy.all import wrpcap, Raw, ARP, IP, TCP, UDP, sendp, sniff, raw
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.eap import EAPOL

from .config import log


class HandshakeCapture:
    """
    Capture WPA 4-way handshakes and export to PCAP file.
    Records client MAC, BSSID, and all 4 handshake messages.
    """

    def __init__(self, output_dir="handshakes"):
        self.output_dir = output_dir
        self._capture = {}  # (client_mac, bssid) -> {messages: set(), frames: []}
        self._started_at = time.time()
        os.makedirs(output_dir, exist_ok=True)

    def add_frame(self, client_mac, bssid, frame, msg_num):
        """Add an EAPOL frame to the handshake capture."""
        key = (client_mac, bssid)
        if key not in self._capture:
            self._capture[key] = {"messages": set(), "frames": []}
        self._capture[key]["messages"].add(msg_num)
        self._capture[key]["frames"].append(frame)
        log.info(f"Handshake captured: {client_mac} <-> {bssid} (Message {msg_num})")

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
        """Export captured handshake to PCAP file."""
        key = (client_mac, bssid)
        if key not in self._capture:
            return None

        filename = os.path.join(
            self.output_dir,
            f"hs_{client_mac.replace(':', '')}_{bssid.replace(':', '')}_{int(time.time())}.pcap"
        )
        frames = self._capture[key]["frames"]
        wrpcap(filename, frames)
        log.critical(f"Handshake PCAP saved: {filename}")
        del self._capture[key]
        return filename

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

    def get_stats(self):
        """Return capture statistics."""
        total = sum(1 for d in self._capture.values() if len(d["messages"]) >= 4)
        partial = sum(1 for d in self._capture.values() if 1 <= len(d["messages"]) < 4)
        return {"complete": total, "partial": partial, "total_entries": len(self._capture)}


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
        """Process frames without BPF filter - manually check for EAPOL."""
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
