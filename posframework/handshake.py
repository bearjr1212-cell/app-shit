"""
WPA Handshake Capture to PCAP
─────────────────────────────
Capture EAPOL 4-way handshake frames and write to PCAP file
for offline cracking with hashcat or aircrack-ng.
"""

import os
import time
import struct
from scapy.all import wrpcap, Raw,ARP,IP,TCP,UDP,sendp
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

        filename = f"{self.output_dir}/hs_{client_mac.replace(':', '')}_{bssid.replace(':', '')}_{int(time.time())}.pcap"
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


def build_eapol_frame(msg_num, key_info_bits, client_mac, bssid, nonce, replay_counter=1):
    """
    Build a synthetic EAPOL-Key frame for PCAP export.
    Key Info: bits 0-15 (little-endian)
        bit 7: Key ACK (1)
        bit 8: Key MIC (1)
        bit 9: Secure (1)
        bit 6: Install (1)
    """
    # EAPOL header: version=1, type=3 (EAPOL-Key), length=125
    eapol_header = struct.pack(">BBH", 1, 3, 125)

    # EAPOL-Key header
    key_type = 2  # WPA2
    key_info = struct.pack("<H", key_info_bits)
    key_length = struct.pack(">H", 16)  # AES-CCMP
    replay_counter = struct.pack(">Q", replay_counter)
    nonce = nonce[:32] if len(nonce) >= 32 else nonce + b"\x00" * (32 - len(nonce))
    key_iv = b"\x00" * 16
    key_rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    key_signature = b"\x00" * 16

    eapol_key = (
        struct.pack("B", key_type) +
        key_info + key_length + replay_counter +
        nonce + key_iv + key_rsc + key_id + key_signature
    )

    # RadioTap header
    radiotap = RadioTap()

    # Dot11 frame
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1=bssid,
        addr2=client_mac,
        addr3=bssid
    )

    # EAPOL layer
    eapol = Raw(load=eapol_header + eapol_key)

    frame = radiotap / dot11 / eapol
    return frame
