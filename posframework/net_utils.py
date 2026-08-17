"""
Network Utilities (Shared)
──────────────────────────
Common helper functions used across multiple modules.
"""

import socket
import subprocess


def parse_cidr(cidr):
    """
    Parse CIDR notation into a list of host IP addresses.

    Supports /24 and larger subnets, but limits output to one /24
    block (254 hosts) to avoid excessive scanning.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        List of host IP strings (excludes network and broadcast addresses)
    """
    hosts = []
    try:
        if "/" not in cidr:
            return [cidr]
        base, prefix = cidr.split("/")
        parts = base.split(".")
        if len(parts) != 4:
            return []
        prefix = int(prefix)
        # Generate host IPs for first /24 block
        for i in range(1, 255):
            hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
    except (ValueError, IndexError):
        pass
    return hosts


def get_interface_ip(interface):
    """
    Get the IPv4 address assigned to a network interface.

    Args:
        interface: Network interface name (e.g., 'eth0', 'wlan0')

    Returns:
        IP address string or None if not found
    """
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("inet "):
                ip = line.split()[1].split("/")[0]
                return ip
    except (subprocess.TimeoutExpired, OSError, IndexError):
        pass
    return None
