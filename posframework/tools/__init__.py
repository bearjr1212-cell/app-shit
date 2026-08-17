"""
External Tool Integration Layer
────────────────────────────────
Detects availability of system tools and provides a unified interface
for invoking them from the framework.

Supported tools:
  aircrack-ng   — WPA/WEP handshake cracking
  hashcat       — GPU-accelerated password cracking
  mdk4          — Advanced WiFi DoS (beacon flood, auth flood, deauth)
  macchanger    — MAC address randomization
  nmap          — Network scanning and service enumeration
  reaver/bully  — WPS PIN brute force
  hcxdumptool   — PMKID clientless handshake capture
  hcxpcapngtool — Convert pcapng to hashcat format
  tshark        — Packet capture and analysis
  hostapd       — Access point management
  dnsmasq       — DHCP/DNS for rogue AP
"""

import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from posframework.config import log


# ─── Tool Registry ────────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    # Aircrack-ng suite
    "aircrack-ng": {"binary": "aircrack-ng", "category": "cracking", "required_for": ["wpa_crack", "wep_crack"]},
    "airmon-ng": {"binary": "airmon-ng", "category": "interface", "required_for": ["monitor_mode"]},
    "airodump-ng": {"binary": "airodump-ng", "category": "recon", "required_for": ["capture"]},
    "aireplay-ng": {"binary": "aireplay-ng", "category": "injection", "required_for": ["deauth", "injection"]},
    # Cracking
    "hashcat": {"binary": "hashcat", "category": "cracking", "required_for": ["gpu_crack"]},
    # DoS / Disruption
    "mdk4": {"binary": "mdk4", "category": "dos", "required_for": ["advanced_dos"]},
    # MAC spoofing
    "macchanger": {"binary": "macchanger", "category": "evasion", "required_for": ["mac_spoof"]},
    # Network scanning
    "nmap": {"binary": "nmap", "category": "scanning", "required_for": ["network_scan", "service_enum"]},
    # WPS attacks
    "reaver": {"binary": "reaver", "category": "wps", "required_for": ["wps_crack"]},
    "bully": {"binary": "bully", "category": "wps", "required_for": ["wps_crack"]},
    "pixiewps": {"binary": "pixiewps", "category": "wps", "required_for": ["pixie_dust"]},
    "wash": {"binary": "wash", "category": "wps", "required_for": ["wps_scan"]},
    # PMKID capture
    "hcxdumptool": {"binary": "hcxdumptool", "category": "capture", "required_for": ["pmkid_capture"]},
    "hcxpcapngtool": {"binary": "hcxpcapngtool", "category": "conversion", "required_for": ["pmkid_convert"]},
    # Packet analysis
    "tshark": {"binary": "tshark", "category": "analysis", "required_for": ["packet_analysis"]},
    # AP infrastructure
    "hostapd": {"binary": "hostapd", "category": "ap", "required_for": ["rogue_ap"]},
    "dnsmasq": {"binary": "dnsmasq", "category": "ap", "required_for": ["rogue_ap", "dns"]},
    # System networking
    "iw": {"binary": "iw", "category": "interface", "required_for": ["wireless_config"]},
    "ip": {"binary": "ip", "category": "interface", "required_for": ["network_config"]},
    "iptables": {"binary": "iptables", "category": "firewall", "required_for": ["nat", "redirect"]},
    "tcpdump": {"binary": "tcpdump", "category": "capture", "required_for": ["raw_capture"]},
}


# ─── Tool Detection ──────────────────────────────────────────────────────────

_tool_cache: Dict[str, Optional[str]] = {}


def which(tool_name: str) -> Optional[str]:
    """
    Find the full path of a tool binary. Results are cached.

    Args:
        tool_name: Tool name from TOOL_REGISTRY or arbitrary binary name.

    Returns:
        Full path to the binary, or None if not found.
    """
    if tool_name in _tool_cache:
        return _tool_cache[tool_name]

    # Look up actual binary name from registry
    entry = TOOL_REGISTRY.get(tool_name)
    binary = entry["binary"] if entry else tool_name

    path = shutil.which(binary)
    _tool_cache[tool_name] = path
    return path


def is_available(tool_name: str) -> bool:
    """Check if a tool is installed and in PATH."""
    return which(tool_name) is not None


def get_version(tool_name: str) -> Optional[str]:
    """
    Get the version string of an installed tool.

    Returns:
        Version string or None if tool not found or version can't be determined.
    """
    path = which(tool_name)
    if not path:
        return None

    # Different tools have different version flags
    version_flags = ["--version", "-V", "-v", "version"]
    for flag in version_flags:
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout.strip() or result.stderr.strip()
            if output and len(output) < 500:
                # Extract first line that looks like a version
                for line in output.split("\n"):
                    line = line.strip()
                    if line and any(c.isdigit() for c in line):
                        return line
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

    return None


def detect_all() -> Dict[str, Dict]:
    """
    Detect all tools and return their availability status.

    Returns:
        Dict mapping tool_name -> {available: bool, path: str|None, version: str|None}
    """
    results = {}
    for name, info in TOOL_REGISTRY.items():
        path = which(name)
        results[name] = {
            "available": path is not None,
            "path": path,
            "category": info["category"],
            "required_for": info["required_for"],
        }
    return results


def check_requirements(feature: str) -> Tuple[bool, List[str]]:
    """
    Check if all tools required for a feature are available.

    Args:
        feature: Feature name (e.g., 'wpa_crack', 'pmkid_capture', 'wps_crack')

    Returns:
        Tuple of (all_available: bool, missing_tools: list)
    """
    missing = []
    for name, info in TOOL_REGISTRY.items():
        if feature in info["required_for"]:
            if not is_available(name):
                missing.append(name)
    return len(missing) == 0, missing


def print_tool_status():
    """Print a formatted table of all tool availability."""
    results = detect_all()
    categories = {}
    for name, info in results.items():
        cat = info["category"]
        categories.setdefault(cat, []).append((name, info))

    lines = []
    lines.append(f"{'Tool':<16} {'Status':<10} {'Path'}")
    lines.append("-" * 60)

    for category in sorted(categories.keys()):
        lines.append(f"\n  [{category.upper()}]")
        for name, info in sorted(categories[category]):
            status = "OK" if info["available"] else "MISSING"
            path = info["path"] or ""
            marker = "+" if info["available"] else "-"
            lines.append(f"  {marker} {name:<14} {status:<10} {path}")

    return "\n".join(lines)


# ─── Subprocess Runner ────────────────────────────────────────────────────────

def run_tool(
    tool_name: str,
    args: List[str],
    timeout: Optional[int] = None,
    capture_output: bool = True,
    input_data: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """
    Run an external tool with proper error handling.

    Args:
        tool_name: Tool name from registry.
        args: Command-line arguments (excluding the binary itself).
        timeout: Timeout in seconds (None = no timeout).
        capture_output: Whether to capture stdout/stderr.
        input_data: Optional stdin data.

    Returns:
        CompletedProcess result.

    Raises:
        FileNotFoundError: If tool is not installed.
        subprocess.TimeoutExpired: If execution exceeds timeout.
    """
    path = which(tool_name)
    if not path:
        raise FileNotFoundError(
            f"Tool '{tool_name}' not found. Install it with: "
            f"apt-get install {tool_name}"
        )

    cmd = [path] + args
    log.debug(f"Running: {' '.join(cmd)}")

    return subprocess.run(
        cmd,
        capture_output=capture_output,
        text=True,
        timeout=timeout,
        input=input_data,
    )


def run_tool_background(
    tool_name: str,
    args: List[str],
    stdout_file: Optional[str] = None,
) -> subprocess.Popen:
    """
    Start a tool as a background process.

    Args:
        tool_name: Tool name from registry.
        args: Command-line arguments.
        stdout_file: Optional file path to redirect stdout.

    Returns:
        Popen process handle.

    Raises:
        FileNotFoundError: If tool is not installed.
    """
    path = which(tool_name)
    if not path:
        raise FileNotFoundError(f"Tool '{tool_name}' not found.")

    cmd = [path] + args
    log.debug(f"Starting background: {' '.join(cmd)}")

    stdout = open(stdout_file, "w") if stdout_file else subprocess.DEVNULL
    stderr = subprocess.DEVNULL

    proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
    return proc
