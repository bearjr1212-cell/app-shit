#!/usr/bin/env python3
"""List all available network interfaces"""
from scapy.arch.windows import get_windows_if_list

ifaces = get_windows_if_list()
print("\nAvailable interfaces:")
for i, iface in enumerate(ifaces):
    name = iface.get("name", "Unknown")
    desc = iface.get("description", "")
    print(f"  [{i}] {name}")
    print(f"       {desc}")
print()
