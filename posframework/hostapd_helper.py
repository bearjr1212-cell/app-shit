#!/usr/bin/env python3
"""
Enhanced Rogue AP Configuration Helper for POSFramework
Provides templates and utilities for advanced hostapd/dnsmasq configuration
"""

import os
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
from enum import Enum


class NetworkMode(Enum):
    """WiFi network security modes"""
    OPEN = "open"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    WPA_MIXED = "wpa_mixed"


class ChannelBand(Enum):
    """WiFi frequency bands"""
    BAND_24GHZ = "g"
    BAND_5GHZ = "a"
    BAND_6GHZ = "ax"


@dataclass
class HostapdConfig:
    """Hostapd configuration parameters"""
    interface: str
    driver: str = "nl80211"
    country_code: str = "US"
    ssid: str = "FreeWiFi"
    channel: int = 6
    hw_mode: str = "g"
    ieee80211n: bool = True
    ieee80211ac: bool = False
    ieee80211ax: bool = False
    wmm_enabled: bool = True
    max_num_sta: int = 255
    beacon_int: int = 100
    rts_threshold: int = 2347
    frag_threshold: int = 2346
    
    # Security
    network_mode: NetworkMode = NetworkMode.OPEN
    wpa_passphrase: Optional[str] = None
    wpa_key_mgmt: str = "WPA-PSK"
    rsn_pairwise: str = "CCMP"
    
    # Advanced
    ap_isolate: bool = False
    ignore_broadcast_ssid: bool = False
    auth_algs: int = 1
    macaddr_acl: int = 0
    
    def to_hostapd_conf(self) -> str:
        """Generate hostapd configuration string"""
        config_lines = [
            f"# Auto-generated hostapd configuration",
            f"interface={self.interface}",
            f"driver={self.driver}",
            f"country_code={self.country_code}",
            f"ssid={self.ssid}",
            f"channel={self.channel}",
            f"hw_mode={self.hw_mode}",
            f"beacon_int={self.beacon_int}",
            f"wmm_enabled={'1' if self.wmm_enabled else '0'}",
            f"ignore_broadcast_ssid={'1' if self.ignore_broadcast_ssid else '0'}",
            f"auth_algs={self.auth_algs}",
            f"macaddr_acl={self.macaddr_acl}",
            f"max_num_sta={self.max_num_sta}",
            f"rts_threshold={self.rts_threshold}",
            f"frag_threshold={self.frag_threshold}",
        ]
        
        if self.ieee80211n:
            config_lines.append("ieee80211n=1")
        if self.ieee80211ac:
            config_lines.append("ieee80211ac=1")
        if self.ieee80211ax:
            config_lines.append("ieee80211ax=1")
        
        if self.ap_isolate:
            config_lines.append("ap_isolate=1")
        
        # Security configuration
        if self.network_mode == NetworkMode.OPEN:
            config_lines.append("wpa=0")
        elif self.network_mode == NetworkMode.WPA2:
            config_lines.extend([
                "wpa=2",
                f"wpa_passphrase={self.wpa_passphrase}",
                f"wpa_key_mgmt={self.wpa_key_mgmt}",
                f"rsn_pairwise={self.rsn_pairwise}",
            ])
        elif self.network_mode == NetworkMode.WPA_MIXED:
            config_lines.extend([
                "wpa=3",
                f"wpa_passphrase={self.wpa_passphrase}",
                f"wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256",
                f"rsn_pairwise={self.rsn_pairwise}",
            ])
        
        return "\n".join(config_lines) + "\n"


@dataclass
class DnsmasqConfig:
    """Dnsmasq DNS/DHCP configuration"""
    interface: str
    gateway_ip: str = "10.0.0.1"
    dhcp_start: str = "10.0.0.2"
    dhcp_end: str = "10.0.0.100"
    dhcp_lease: str = "12h"
    enable_logging: bool = True
    cache_size: int = 1024
    wildcard_dns: bool = True
    
    def to_dnsmasq_conf(self) -> str:
        """Generate dnsmasq configuration string"""
        config_lines = [
            f"# Auto-generated dnsmasq configuration",
            f"no-resolv",
            f"interface={self.interface}",
            f"bind-interfaces",
            f"dhcp-range={self.dhcp_start},{self.dhcp_end},{self.dhcp_lease}",
            f"dhcp-option=option:router,{self.gateway_ip}",
            f"dhcp-option=option:dns-server,{self.gateway_ip}",
            f"cache-size={self.cache_size}",
        ]
        
        if self.wildcard_dns:
            config_lines.append(f"address=/#/{self.gateway_ip}")
        
        if self.enable_logging:
            config_lines.extend([
                "log-queries",
                "log-facility=/var/log/dnsmasq.log",
            ])
        
        return "\n".join(config_lines) + "\n"


class RogueAPConfigurator:
    """Helper class for configuring rogue AP infrastructure"""
    
    def __init__(self, config_dir: str = "/tmp/posframework_ap"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_hostapd_config(
        self,
        interface: str,
        ssid: str,
        channel: int = 6,
        network_mode: NetworkMode = NetworkMode.OPEN,
        passphrase: Optional[str] = None,
        country_code: str = "US",
    ) -> str:
        """Generate and save hostapd configuration"""
        config = HostapdConfig(
            interface=interface,
            ssid=ssid,
            channel=channel,
            country_code=country_code,
            network_mode=network_mode,
            wpa_passphrase=passphrase,
        )
        
        config_text = config.to_hostapd_conf()
        config_file = self.config_dir / f"hostapd-{ssid}.conf"
        config_file.write_text(config_text)
        
        return str(config_file)
    
    def generate_dnsmasq_config(
        self,
        interface: str,
        gateway_ip: str = "10.0.0.1",
        dhcp_start: str = "10.0.0.2",
        dhcp_end: str = "10.0.0.100",
    ) -> str:
        """Generate and save dnsmasq configuration"""
        config = DnsmasqConfig(
            interface=interface,
            gateway_ip=gateway_ip,
            dhcp_start=dhcp_start,
            dhcp_end=dhcp_end,
        )
        
        config_text = config.to_dnsmasq_conf()
        config_file = self.config_dir / "dnsmasq.conf"
        config_file.write_text(config_text)
        
        return str(config_file)
    
    def validate_hostapd(self) -> Dict[str, bool]:
        """Check if hostapd is properly installed and configured"""
        results = {}
        
        # Check binary exists
        try:
            subprocess.run(["which", "hostapd"], capture_output=True, check=True)
            results["binary_exists"] = True
        except subprocess.CalledProcessError:
            results["binary_exists"] = False
        
        # Check version
        try:
            output = subprocess.run(["hostapd", "-v"], capture_output=True, text=True)
            results["version_check"] = len(output.stdout) > 0
        except Exception:
            results["version_check"] = False
        
        # Check nl80211 kernel module
        try:
            output = subprocess.run(["lsmod"], capture_output=True, text=True)
            results["nl80211_loaded"] = "nl80211" in output.stdout
        except Exception:
            results["nl80211_loaded"] = False
        
        # Check for AP-capable interfaces
        try:
            output = subprocess.run(["iw", "list"], capture_output=True, text=True)
            results["ap_capable"] = "AP" in output.stdout
        except Exception:
            results["ap_capable"] = False
        
        return results
    
    def get_wireless_interfaces(self) -> List[str]:
        """Get list of wireless interfaces"""
        try:
            output = subprocess.run(["iwconfig"], capture_output=True, text=True)
            interfaces = []
            for line in output.stdout.split("\n"):
                if line and not line.startswith(" "):
                    interface = line.split()[0]
                    interfaces.append(interface)
            return interfaces
        except Exception:
            return []
    
    def test_hostapd_config(self, config_file: str) -> bool:
        """Test hostapd configuration syntax"""
        try:
            output = subprocess.run(
                ["hostapd", "-dd", config_file],
                capture_output=True,
                timeout=2,
                text=True
            )
            # hostapd with -dd will print config and try to start
            # Check for obvious errors
            return "error" not in output.stderr.lower() or output.returncode == 0
        except subprocess.TimeoutExpired:
            return True  # Timeout means it tried to start (good sign)
        except Exception:
            return False


def generate_quick_config(
    interface: str,
    ssid: str,
    channel: int = 6,
    passphrase: Optional[str] = None,
    gateway_ip: str = "10.0.0.1",
) -> Dict[str, str]:
    """Generate complete AP configuration in one call"""
    
    configurator = RogueAPConfigurator()
    
    # Determine network mode
    network_mode = NetworkMode.WPA2 if passphrase else NetworkMode.OPEN
    
    # Generate configs
    hostapd_conf = configurator.generate_hostapd_config(
        interface=interface,
        ssid=ssid,
        channel=channel,
        network_mode=network_mode,
        passphrase=passphrase,
    )
    
    dnsmasq_conf = configurator.generate_dnsmasq_config(
        interface=interface,
        gateway_ip=gateway_ip,
    )
    
    return {
        "hostapd_config": hostapd_conf,
        "dnsmasq_config": dnsmasq_conf,
        "gateway_ip": gateway_ip,
        "interface": interface,
        "ssid": ssid,
        "channel": str(channel),
        "network_mode": network_mode.value,
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 hostapd_helper.py <command> [args...]")
        print("\nCommands:")
        print("  validate                    - Check hostapd installation")
        print("  generate <ssid> <channel>   - Generate configs for SSID on channel")
        print("  interfaces                  - List wireless interfaces")
        print("  quick <interface> <ssid>    - Generate quick config")
        sys.exit(1)
    
    command = sys.argv[1]
    configurator = RogueAPConfigurator()
    
    if command == "validate":
        print("[*] Validating hostapd installation...")
        results = configurator.validate_hostapd()
        for check, result in results.items():
            status = "[✓]" if result else "[✗]"
            print(f"{status} {check}: {result}")
    
    elif command == "interfaces":
        print("[*] Available wireless interfaces:")
        interfaces = configurator.get_wireless_interfaces()
        for iface in interfaces:
            print(f"  - {iface}")
    
    elif command == "generate" and len(sys.argv) >= 4:
        ssid = sys.argv[2]
        channel = int(sys.argv[3])
        passphrase = sys.argv[4] if len(sys.argv) > 4 else None
        
        print(f"[*] Generating configs for '{ssid}' on channel {channel}...")
        configs = generate_quick_config(
            interface="wlan1",
            ssid=ssid,
            channel=channel,
            passphrase=passphrase,
        )
        
        print("[+] Hostapd config:", configs["hostapd_config"])
        print("[+] Dnsmasq config:", configs["dnsmasq_config"])
        print(json.dumps({k: v for k, v in configs.items() if k not in ["hostapd_config", "dnsmasq_config"]}, indent=2))
    
    elif command == "quick" and len(sys.argv) >= 4:
        interface = sys.argv[2]
        ssid = sys.argv[3]
        
        print(f"[*] Generating quick config for '{ssid}' on {interface}...")
        configs = generate_quick_config(interface=interface, ssid=ssid)
        print(json.dumps(configs, indent=2))
