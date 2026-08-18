"""
P0F Integration
───────────────
Passive OS fingerprinting via p0f:
  - Identifies remote OS, link type, distance, and uptime
  - Runs passively on a network interface (no active probes)
  - Parses p0f output for structured fingerprint data
  - Supports live vector loading for real-time target intel

p0f analyzes TCP/IP stack behavior to identify the operating system
of remote hosts without sending any packets. Ideal for stealthy
intelligence gathering before launching targeted attacks.
"""

import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from posframework.config import log
from posframework.tools import is_available, which, run_tool_background


@dataclass
class P0FResult:
    """Parsed p0f fingerprint result for a single host."""
    ip: str
    os: str = "unknown"
    os_flavor: str = ""
    distance: int = -1
    link_type: str = "unknown"
    uptime: str = ""
    language: str = ""
    raw_sig: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization and live vector loading."""
        return {
            "ip": self.ip,
            "os": self.os,
            "os_flavor": self.os_flavor,
            "distance": self.distance,
            "link_type": self.link_type,
            "uptime": self.uptime,
            "language": self.language,
            "raw_sig": self.raw_sig,
            "timestamp": self.timestamp,
        }


class P0F:
    """
    P0F passive OS fingerprinting wrapper.

    Runs p0f in background mode, captures output, and parses fingerprint
    results into structured P0FResult objects. Results are loaded live as
    they are captured.

    Usage:
        p0f = P0F("wlan0mon")
        p0f.start()
        time.sleep(30)  # Let it gather fingerprints
        results = p0f.get_results()
        for r in results:
            print(f"{r.ip} -> {r.os} ({r.link_type}, hop distance: {r.distance})")
        p0f.stop()
    """

    def __init__(self, interface: Optional[str] = None):
        if not is_available("p0f"):
            raise FileNotFoundError(
                "p0f not installed. Install: apt-get install p0f"
            )
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._output_file: Optional[str] = None
        self._results: Dict[str, P0FResult] = {}
        self._running = False

    @property
    def running(self) -> bool:
        """Check if p0f process is currently running."""
        return self._proc is not None and self._proc.poll() is None

    def start(self, interface: Optional[str] = None) -> bool:
        """
        Start p0f passive fingerprinting on the given interface.

        Args:
            interface: Network interface to listen on (overrides constructor arg).

        Returns:
            True if started successfully.
        """
        iface = interface or self.interface
        if not iface:
            log.error("p0f: No interface specified")
            return False

        self.stop()

        # Create temp file for output
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".p0f.log", delete=False, prefix="pos_p0f_"
        )
        self._output_file = tmp.name
        tmp.close()

        path = which("p0f")
        if not path:
            return False

        # p0f args: -i interface -o output_file -p (promiscuous)
        args = ["-i", iface, "-o", self._output_file, "-p"]

        cmd = [path] + args
        log.info(f"p0f: Starting passive fingerprinting on {iface}")
        log.debug(f"p0f: {' '.join(cmd)}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read().decode(errors="ignore")
                log.error(f"p0f failed to start: {stderr}")
                self._proc = None
                return False
            self._running = True
            return True
        except Exception as e:
            log.error(f"p0f start error: {e}")
            self._proc = None
            return False

    def stop(self):
        """Stop the running p0f process."""
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
        self._running = False

    def get_results(self) -> List[P0FResult]:
        """
        Parse p0f output file and return all fingerprinted hosts.

        Results are loaded live from the output file each time this is called,
        reflecting the latest captured fingerprints.

        Returns:
            List of P0FResult objects for all discovered hosts.
        """
        self._parse_output()
        return list(self._results.values())

    def get_results_live(self) -> List[Dict]:
        """
        Get results as live-loadable vector dicts for attack input auto-fill.

        Returns:
            List of dicts with host intel for live vector loading.
        """
        self._parse_output()
        return [r.to_dict() for r in self._results.values()]

    def get_host(self, ip: str) -> Optional[P0FResult]:
        """
        Get fingerprint result for a specific IP.

        Args:
            ip: Target IP address.

        Returns:
            P0FResult if host was fingerprinted, None otherwise.
        """
        self._parse_output()
        return self._results.get(ip)

    def _parse_output(self):
        """Parse the p0f output log file for fingerprint results."""
        if not self._output_file or not os.path.isfile(self._output_file):
            return

        try:
            with open(self._output_file, "r") as f:
                content = f.read()
        except (IOError, OSError) as e:
            log.debug(f"p0f: Could not read output file: {e}")
            return

        # p0f output format (log mode):
        # .-[ 1.2.3.4/1234 -> 5.6.7.8/80 (syn) ]-
        # | client   = 1.2.3.4/1234
        # | os       = Linux 3.x
        # | dist     = 2
        # | params   = none
        # | raw_sig  = 4:64+2:0:1460:mss*44,7:mss,sok,...
        # `----

        # Parse blocks
        blocks = re.split(r'\.-\[', content)
        for block in blocks:
            if not block.strip():
                continue
            self._parse_block(block)

    def _parse_block(self, block: str):
        """Parse a single p0f output block."""
        # Extract client IP
        ip_match = re.search(r'client\s*=\s*(\d+\.\d+\.\d+\.\d+)', block)
        if not ip_match:
            # Try the header line format
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)/\d+\s*->', block)
        if not ip_match:
            return

        ip = ip_match.group(1)
        result = self._results.get(ip, P0FResult(ip=ip))

        # Parse OS
        os_match = re.search(r'os\s*=\s*(.+?)(?:\n|\r|$)', block)
        if os_match:
            os_str = os_match.group(1).strip()
            # Split into base OS and flavor (e.g., "Linux 3.x" -> os=Linux, flavor=3.x)
            parts = os_str.split(None, 1)
            result.os = parts[0] if parts else os_str
            result.os_flavor = parts[1] if len(parts) > 1 else ""

        # Parse distance
        dist_match = re.search(r'dist\s*=\s*(\d+)', block)
        if dist_match:
            result.distance = int(dist_match.group(1))

        # Parse link type
        link_match = re.search(r'link\s*=\s*(.+?)(?:\n|\r|$)', block)
        if link_match:
            result.link_type = link_match.group(1).strip()

        # Parse uptime
        uptime_match = re.search(r'uptime\s*=\s*(.+?)(?:\n|\r|$)', block)
        if uptime_match:
            result.uptime = uptime_match.group(1).strip()

        # Parse language
        lang_match = re.search(r'language\s*=\s*(.+?)(?:\n|\r|$)', block)
        if lang_match:
            result.language = lang_match.group(1).strip()

        # Parse raw signature
        sig_match = re.search(r'raw_sig\s*=\s*(.+?)(?:\n|\r|$)', block)
        if sig_match:
            result.raw_sig = sig_match.group(1).strip()

        result.timestamp = time.time()
        self._results[ip] = result

    def clear_results(self):
        """Clear all cached fingerprint results."""
        self._results.clear()

    def __del__(self):
        try:
            self.stop()
            # Clean up temp file
            if self._output_file and os.path.isfile(self._output_file):
                try:
                    os.unlink(self._output_file)
                except OSError:
                    pass
        except AttributeError:
            pass
