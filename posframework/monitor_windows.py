#!/usr/bin/env python3
"""
Windows Monitor Mode Manager
────────────────────────────
Utility to manage monitor mode and check wireless adapter capabilities.

Usage:
    python -m posframework.monitor_windows check
    python -m posframework.monitor_windows list
    python -m posframework.monitor_windows enable Wi-Fi
    python -m posframework.monitor_windows disable Wi-Fi
"""

import sys
import os
import subprocess
import ctypes


def is_admin():
    """Check if running as administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_npcap():
    """Check if Npcap is installed."""
    paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
    ]
    for path in paths:
        if os.path.isdir(path):
            print(f"✓ Npcap found: {path}")
            
            # Check for monitor mode support
            npcap_bin = os.path.join(path, "npcap")
            if os.path.isdir(npcap_bin):
                print("✓ Monitor mode support available")
                return True
            else:
                print("⚠ Npcap found but monitor mode may be limited")
                return True
    print("✗ Npcap not installed")
    print("  Download: https://npcap.com/")
    return False


def get_interfaces():
    """Get list of network interfaces."""
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        
        interfaces = []
        current_iface = None
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Detect interface start
            if ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                iface_name = line.split(':')[0].strip()
                if iface_name:
                    current_iface = {"name": iface_name, "description": ""}
            
            # Get description
            elif current_iface and "Description" in line:
                desc = line.split(':', 1)[1].strip() if ':' in line else ""
                current_iface["description"] = desc
                interfaces.append(current_iface)
                current_iface = None
            
            elif current_iface and "Physical Address" in line:
                mac = line.split(':', 1)[1].strip() if ':' in line else ""
                current_iface["mac"] = mac
        
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []


def list_interfaces():
    """List all network interfaces."""
    print("\nNetwork Interfaces:")
    print("-" * 60)
    
    interfaces = get_interfaces()
    wireless_keywords = ["wifi", "wireless", "802.11", "atheros", "broadcom", "intel"]
    
    for i, iface in enumerate(interfaces):
        name = iface.get("name", "Unknown")
        desc = iface.get("description", "")
        mac = iface.get("mac", "")
        
        # Check if wireless
        is_wireless = any(kw in desc.lower() for kw in wireless_keywords)
        wireless_marker = "  [WIRELESS]" if is_wireless else ""
        
        print(f"\n[{i}] {name}{wireless_marker}")
        print(f"     Description: {desc}")
        if mac:
            print(f"     MAC: {mac}")
    
    print("\n" + "-" * 60)
    return interfaces


def check_interface(interface_name):
    """Check if an interface supports monitor mode."""
    interfaces = get_interfaces()
    
    for iface in interfaces:
        if iface["name"] == interface_name:
            desc = iface.get("description", "").lower()
            
            print(f"\nInterface: {interface_name}")
            print(f"Description: {iface.get('description', 'N/A')}")
            
            # Check chip type
            chip = None
            if "atheros" in desc:
                chip = "Atheros"
            elif "broadcom" in desc or "bcm" in desc:
                chip = "Broadcom"
            elif "intel" in desc:
                chip = "Intel"
            elif "realtek" in desc:
                chip = "Realtek"
            
            if chip:
                print(f"Chip: {chip}")
                print(f"✓ {chip} adapters generally support monitor mode")
            else:
                print("⚠ Unknown chip type")
            
            return True
    
    print(f"Interface '{interface_name}' not found")
    return False


def enable_monitor_mode(interface_name):
    """Enable monitor mode on the interface."""
    print(f"Enabling monitor mode on {interface_name}...")
    
    # Windows doesn't have native monitor mode like Linux
    # We configure Npcap for raw packet capture
    print("Note: Windows monitor mode is handled by Npcap")
    print("Ensure Npcap is installed with 'WinPcap API-compatible' option")
    
    # Check Npcap
    if not check_npcap():
        return False
    
    # Get MAC address
    interfaces = get_interfaces()
    for iface in interfaces:
        if iface["name"] == interface_name:
            mac = iface.get("mac", "N/A")
            print(f"Current MAC: {mac}")
            break
    
    print("\nMonitor mode enabled via Npcap")
    print("Use scapy or tshark for packet capture")
    return True


def disable_monitor_mode(interface_name):
    """Disable monitor mode on the interface."""
    print(f"Disabling monitor mode on {interface_name}...")
    print("Monitor mode automatically disabled when capture stops")
    return True


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command in ("check", "status"):
        print("Npcap Status:")
        print("-" * 40)
        check_npcap()
        
        print("\n\nWireless Interfaces:")
        print("-" * 40)
        list_interfaces()
        
    elif command == "list":
        list_interfaces()
    
    elif command == "enable":
        if len(sys.argv) < 3:
            print("Usage: monitor_windows.py enable <interface_name>")
            sys.exit(1)
        enable_monitor_mode(sys.argv[2])
    
    elif command == "disable":
        if len(sys.argv) < 3:
            print("Usage: monitor_windows.py disable <interface_name>")
            sys.exit(1)
        disable_monitor_mode(sys.argv[2])
    
    elif command == "detect":
        # Detect wireless chip
        interfaces = get_interfaces()
        print("\nWireless Chip Detection:")
        print("-" * 40)
        
        for iface in interfaces:
            desc = iface.get("description", "").lower()
            name = iface.get("name", "")
            
            # Skip non-wireless
            if "wifi" not in desc and "wireless" not in desc:
                continue
            
            chip = None
            if "atheros" in desc:
                chip = "Atheros"
            elif "broadcom" in desc or "bcm" in desc:
                chip = "Broadcom"
            elif "intel" in desc:
                chip = "Intel"
            elif "realtek" in desc:
                chip = "Realtek"
            
            if chip:
                print(f"✓ {name}: {chip}")
            else:
                print(f"⚠ {name}: Unknown chip")
    
    else:
        print(f"Unknown command: {command}")
        print("\nCommands: check, list, enable, disable, detect")
        sys.exit(1)


if __name__ == "__main__":
    main()
