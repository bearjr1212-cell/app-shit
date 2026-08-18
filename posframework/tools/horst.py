"""
Horst Integration
─────────────────
Lightweight 802.11 link-layer analyzer via horst:
  - Real-time node discovery on wireless interfaces
  - Signal strength and noise floor monitoring
  - Packet type classification (management, control, data)
  - Channel utilization analysis
  - Live vector loading of discovered nodes

Horst is a small, lightweight IEEE802.11 WLAN analyzer with a
text interface. It captures and analyzes wireless frames to provide
information about signal quality, node presence, and channel usage.
Ideal for live reconnaissance with minimal resource overhead.
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
from posframework.tools import is_available, which


@dataclass
class HorstNode:
    """A wireless node discovered by horst."""
    mac: str
    signal: int = -100
    noise: int = -95
    snr: int = 0
    packet_count: int = 0
    packet_types: Dict[str, int] = field(default_factory=dict)
    channel: int = 0
    mode: str = ""  # AP, STA, IBSS, etc.
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        """Convert to dictionary for live vector loading and serialization."""
        return {
            "mac": self.mac,
            "signal": self.signal,
            "noise": self.noise,
            "snr": self.snr,
            "packet_count": self.packet_count,
            "packet_types": self.packet_types,
            "channel": self.channel,
            "mode": self.mode,
            "last_seen": self.last_seen,
        }


@dataclass
class HorstStats:
    """Channel/link statistics from horst."""
    total_packets: int = 0
    mgmt_packets: int = 0
    ctrl_packets: int = 0
    data_packets: int = 0
    channel_utilization: float = 0.0
    avg_signal: int = -100
    noise_floor: int = -95

    def to_dict(self) -> Dict:
        """Convert to dictionary for live vector loading."""
        return {
            "total_packets": self.total_packets,
            "mgmt_packets": self.mgmt_packets,
            "ctrl_packets": self.ctrl_packets,
            "data_packets": self.data_packets,
            "channel_utilization": self.channel_utilization,
            "avg_signal": self.avg_signal,
            "noise_floor": self.noise_floor,
        }


class Horst:
    """
    Horst lightweight link-layer scanner wrapper.

    Runs horst in background mode to capture 802.11 frames and analyze
    link-layer traffic. Parses output for signal strength, noise, packet
    types, and node discovery. Results are available live.

    Usage:
        horst = Horst("wlan0mon")
        horst.start()
        time.sleep(10)  # Let it scan
        nodes = horst.get_nodes()
        for node in nodes:
            print(f"{node.mac} signal={node.signal}dBm packets={node.packet_count}")
        stats = horst.get_stats()
        print(f"Channel utilization: {stats.channel_utilization:.1f}%")
        horst.stop()
    """

    def __init__(self, interface: Optional[str] = None):
        if not is_available("horst"):
            raise FileNotFoundError(
                "horst not installed. Install: apt-get install horst"
            )
        self.interface = interface
        self._proc: Optional[subprocess.Popen] = None
        self._output_file: Optional[str] = None
        self._nodes: Dict[str, HorstNode] = {}
        self._stats = HorstStats()
        self._running = False

    @property
    def running(self) -> bool:
        """Check if horst process is currently running."""
        return self._proc is not None and self._proc.poll() is None

    def start(self, interface: Optional[str] = None, channel: Optional[int] = None) -> bool:
        """
        Start horst scanning on the specified interface.

        Args:
            interface: WiFi interface in monitor mode (overrides constructor arg).
            channel: Lock to specific channel (None = scan all).

        Returns:
            True if started successfully.
        """
        iface = interface or self.interface
        if not iface:
            log.error("horst: No interface specified")
            return False

        self.stop()

        # Create temp file for output
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".horst.log", delete=False, prefix="pos_horst_"
        )
        self._output_file = tmp.name
        tmp.close()

        path = which("horst")
        if not path:
            return False

        # horst args: -i interface -o output_file -q (quiet mode for parsing)
        args = ["-i", iface, "-o", self._output_file, "-q"]

        if channel:
            args.extend(["-c", str(channel)])

        cmd = [path] + args
        log.info(f"horst: Starting link-layer scan on {iface}")
        log.debug(f"horst: {' '.join(cmd)}")

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read().decode(errors="ignore")
                log.error(f"horst failed to start: {stderr}")
                self._proc = None
                return False
            self._running = True
            return True
        except Exception as e:
            log.error(f"horst start error: {e}")
            self._proc = None
            return False

    def stop(self):
        """Stop the running horst process."""
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

    def get_nodes(self) -> List[HorstNode]:
        """
        Get all discovered wireless nodes.
        Parses live from output file each call.

        Returns:
            List of HorstNode objects for all discovered nodes.
        """
        self._parse_output()
        return list(self._nodes.values())

    def get_nodes_live(self) -> List[Dict]:
        """
        Get nodes as live-loadable vector dicts for attack input auto-fill.

        Returns:
            List of dicts suitable for live vector loading.
        """
        self._parse_output()
        return [n.to_dict() for n in self._nodes.values()]

    def get_stats(self) -> HorstStats:
        """
        Get link-layer statistics.
        Parsed live from output.

        Returns:
            HorstStats with packet counts and channel utilization.
        """
        self._parse_output()
        return self._stats

    def get_stats_live(self) -> Dict:
        """
        Get stats as a live-loadable vector dict.

        Returns:
            Dict with channel statistics.
        """
        return self.get_stats().to_dict()

    def get_node(self, mac: str) -> Optional[HorstNode]:
        """
        Get info for a specific node by MAC.

        Args:
            mac: Node MAC address.

        Returns:
            HorstNode if found, None otherwise.
        """
        self._parse_output()
        return self._nodes.get(mac.upper())

    def _parse_output(self):
        """Parse the horst output file for node and statistics data."""
        if not self._output_file or not os.path.isfile(self._output_file):
            return

        try:
            with open(self._output_file, "r") as f:
                content = f.read()
        except (IOError, OSError) as e:
            log.debug(f"horst: Could not read output file: {e}")
            return

        total = 0
        mgmt = 0
        ctrl = 0
        data = 0
        signals = []

        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Parse horst output format
            # Typical line: TIMESTAMP SIGNAL NOISE MAC TYPE CHANNEL [extra]
            # Example: 1234567890 -45 -95 AA:BB:CC:DD:EE:FF MGMT 6
            parsed = self._parse_line(line)
            if parsed is None:
                continue

            mac, sig, noise, pkt_type, channel = parsed
            total += 1

            # Classify packet type
            pkt_type_upper = pkt_type.upper()
            if "MGMT" in pkt_type_upper or "BEACON" in pkt_type_upper or "PROBE" in pkt_type_upper:
                mgmt += 1
                pkt_category = "mgmt"
            elif "CTRL" in pkt_type_upper or "ACK" in pkt_type_upper or "CTS" in pkt_type_upper:
                ctrl += 1
                pkt_category = "ctrl"
            else:
                data += 1
                pkt_category = "data"

            if sig > -100:
                signals.append(sig)

            # Update node
            node = self._nodes.get(mac, HorstNode(mac=mac))
            node.signal = sig
            node.noise = noise
            node.snr = sig - noise if noise < 0 else 0
            node.packet_count += 1
            node.channel = channel
            node.last_seen = time.time()

            # Track packet types per node
            node.packet_types[pkt_category] = node.packet_types.get(pkt_category, 0) + 1

            # Infer mode from packet types
            if "BEACON" in pkt_type_upper:
                node.mode = "AP"
            elif "PROBE_REQ" in pkt_type_upper:
                node.mode = "STA"

            self._nodes[mac] = node

        # Update stats
        self._stats.total_packets = total
        self._stats.mgmt_packets = mgmt
        self._stats.ctrl_packets = ctrl
        self._stats.data_packets = data
        self._stats.avg_signal = int(sum(signals) / len(signals)) if signals else -100
        self._stats.noise_floor = -95  # Default noise floor

        # Rough channel utilization (packets vs time-based, simplified)
        if total > 0:
            # Heuristic: assume higher packet counts = more utilization
            self._stats.channel_utilization = min(100.0, total * 0.1)

    def _parse_line(self, line: str) -> Optional[tuple]:
        """
        Parse a single line of horst output.

        Expected formats:
            TIMESTAMP SIG NOISE MAC TYPE CH
            or tab-separated fields

        Returns:
            Tuple of (mac, signal, noise, packet_type, channel) or None.
        """
        # Try space/tab separated format
        parts = re.split(r'[\s\t]+', line)
        if len(parts) < 5:
            return None

        # Find MAC address in parts (XX:XX:XX:XX:XX:XX pattern)
        mac = None
        mac_idx = -1
        for i, part in enumerate(parts):
            if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', part):
                mac = part.upper()
                mac_idx = i
                break

        if mac is None:
            return None

        # Extract signal (look for negative dBm value before MAC)
        signal = -100
        noise = -95
        for i in range(mac_idx):
            try:
                val = int(parts[i])
                if -120 <= val <= 0:
                    if signal == -100:
                        signal = val
                    else:
                        noise = val
            except ValueError:
                continue

        # Packet type (after MAC)
        pkt_type = parts[mac_idx + 1] if mac_idx + 1 < len(parts) else "DATA"

        # Channel (after type)
        channel = 0
        if mac_idx + 2 < len(parts):
            try:
                channel = int(parts[mac_idx + 2])
            except ValueError:
                pass

        return mac, signal, noise, pkt_type, channel

    def clear_nodes(self):
        """Clear all cached node data."""
        self._nodes.clear()
        self._stats = HorstStats()

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
