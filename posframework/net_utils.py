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

    Respects the prefix length to generate the correct number of hosts:
      - /32: single host (the address itself)
      - /31: 2 hosts (point-to-point, no network/broadcast exclusion)
      - /28: 14 hosts (excludes network and broadcast)
      - /24: 254 hosts
      - /16 and larger: clamped to 1024 hosts to avoid excessive scanning

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        List of host IP strings (excludes network and broadcast addresses
        for prefixes /30 and smaller)
    """
    hosts = []
    try:
        if "/" not in cidr:
            return [cidr]
        base, prefix_str = cidr.split("/")
        parts = base.split(".")
        if len(parts) != 4:
            return []
        prefix = int(prefix_str)
        if prefix < 0 or prefix > 32:
            return []

        # Convert base IP to integer
        ip_int = (int(parts[0]) << 24) | (int(parts[1]) << 16) | \
                 (int(parts[2]) << 8) | int(parts[3])

        # Calculate network address and host count from prefix
        if prefix == 32:
            return [base]

        host_bits = 32 - prefix
        num_addresses = 1 << host_bits  # total addresses in subnet
        network_mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
        network_addr = ip_int & network_mask

        if prefix == 31:
            # Point-to-point link (RFC 3021): both addresses are hosts
            for offset in range(2):
                addr = network_addr + offset
                hosts.append(f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}."
                             f"{(addr >> 8) & 0xFF}.{addr & 0xFF}")
        else:
            # Standard subnet: exclude network (first) and broadcast (last)
            num_hosts = num_addresses - 2
            if num_hosts <= 0:
                return []

            # Clamp to 1024 hosts max for large subnets (/16 and bigger)
            max_hosts = 1024
            num_hosts = min(num_hosts, max_hosts)

            for offset in range(1, num_hosts + 1):
                addr = network_addr + offset
                hosts.append(f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}."
                             f"{(addr >> 8) & 0xFF}.{addr & 0xFF}")
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
