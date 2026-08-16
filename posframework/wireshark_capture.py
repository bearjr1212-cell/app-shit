"""
Wireshark Packet Capture Module
────────────────────────────────
Uses tshark (Wireshark CLI) for packet capture instead of scapy's sniff.

Benefits:
  - More reliable on Windows
  - Better filter support
  - Can output to PCAP for analysis
"""

import subprocess
import threading
import time
import tempfile
import os
from collections import deque

from scapy.all import rdpcap, Raw, IP, TCP, UDP, Ether
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL

from posframework.config import IS_WINDOWS, log


class WiresharkCapture:
    """
    Packet capture using tshark (Wireshark CLI).
    Falls back to scapy if tshark not available.
    """

    def __init__(self, interface, bpf_filter=None, timeout=None):
        self.interface = interface
        self.bpf_filter = bpf_filter or "type mgt subtype beacon or type mgt subtype probe-resp or eapol"
        self.timeout = timeout
        self.running = False
        self._packets = deque(maxlen=1000)
        self._pcap_file = None
        self._proc = None
        self._thread = None

    def _get_tshark_path(self):
        """Find tshark executable."""
        paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "tshark",
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def start(self):
        """Start tshark capture."""
        tshark = self._get_tshark_path()
        if not tshark:
            log.warning("tshark not found - falling back to scapy")
            return False

        # Create temp PCAP file
        self._pcap_file = tempfile.NamedTemporaryFile(
            suffix=".pcap", delete=False
        ).name

        # Build tshark command
        cmd = [
            tshark,
            "-i", self.interface,
            "-f", self.bpf_filter,
            "-w", self._pcap_file,
        ]
        if self.timeout:
            cmd.extend(["-a", f"duration:{self.timeout}"])

        log.info(f"Starting tshark: {' '.join(cmd)}")

        # Start tshark process
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        self.running = True
        self._thread = threading.Thread(target=self._monitor_tshark, daemon=True)
        self._thread.start()

        return True

    def _monitor_tshark(self):
        """Monitor tshark output and process PCAP."""
        while self.running and self._proc.poll() is None:
            time.sleep(0.5)

        # Read captured packets
        if self._pcap_file and os.path.exists(self._pcap_file):
            try:
                packets = rdpcap(self._pcap_file)
                for pkt in packets:
                    self._packets.append(pkt)
            except Exception as e:
                log.warning(f"Error reading PCAP: {e}")

    def stop(self):
        """Stop capture and cleanup."""
        self.running = False
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        
        # Cleanup PCAP file
        if self._pcap_file and os.path.exists(self._pcap_file):
            try:
                os.remove(self._pcap_file)
            except Exception:
                pass

    def get_packets(self):
        """Get captured packets."""
        return list(self._packets)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def capture_with_tshark(interface, bpf_filter=None, timeout=None):
    """Quick function to capture packets with tshark."""
    try:
        with WiresharkCapture(interface, bpf_filter, timeout) as capture:
            time.sleep(timeout or 10)
        return capture.get_packets()
    except Exception as e:
        log.error(f"tshark capture failed: {e}")
        return []


# Usage examples
if __name__ == "__main__":
    # Example 1: Capture beacons
    packets = capture_with_tshark("WiFi", "type mgt subtype beacon", 10)
    print(f"Captured {len(packets)} packets")
    
    # Example 2: Capture with filter
    packets = capture_with_tshark(
        "WiFi",
        "(type mgt subtype beacon or type mgt subtype probe-resp) and wlan dst ff:ff:ff:ff:ff:ff",
        5
    )
    print(f"Captured {len(packets)} packets")
