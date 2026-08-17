"""
POS Reconnaissance & Attack Framework
──────────────────────────────────────
Real-world 802.11 passive monitor that identifies POS terminals, payment
infrastructure, and retail networking gear — then automatically feeds
discovered targets into active attack modules.

RECON (Passive Scanner):
    OUI vendor lookups, SSID heuristics, RSN/WPA IE parsing,
    EAPOL handshake detection, deauth flood monitoring.

ATTACK (Auto-targeted from recon data):
    Evil Twin AP, targeted deauthentication, known beacon flooding,
    captive portal credential harvesting.

Additional Modules:
    MITM: Man-in-the-middle with ARP poisoning
    SSL Strip: HTTPS to HTTP downgrade
    DNS Spoof: DNS redirection attacks
    Credential Harvester: HTTP/FTP/IMAP credential capture
    Network Disruption: Deauth storms, jamming, rate limiting
    Post Attack: Post-attack analysis and next steps generation

Advanced WiFi Attacks:
    AP Clone: Auto-clone target AP SSID after deauth
    KRACK: Key reinstallation attack (CVE-2017-13077/13078)
    WiFi DoS: CTS flood, beacon exhaust, QoS null, fragmentation
    Client Isolation: Subtle disassociation and handoff forcing

Printer Exploitation:
    Printer Recon: mDNS/SNMP/HTTP printer discovery
    IPP Scanner: Port 631 fingerprinting and queue enumeration
    Print Interceptor: ARP spoof print traffic interception
    Printer Credential Harvester: SMB/SNMP/HTTP credential capture

Package modules:
    config       - Constants, thresholds, channel lists, logging
    intel        - POS vendor/SSID intelligence matching
    crypto       - RSN/WPA IE byte-level parsing (IEEE 802.11-2020)
    database     - SQLite layer (WAL, batched commits, indexed)
    recon        - Passive scanner engine
    deauth       - Deauth frame injection
    beacons      - Known beacon flood
    rogueap      - Rogue AP + captive portal
    orchestrator - Auto-targeting attack pipeline
    mitm         - Man-in-the-middle attack
    ssl_strip    - SSL stripping (HTTPS downgrade)
    dns_spoof    - DNS spoofing/redirect
    cred_harvester - Credential harvesting
    network_disruption - Deauth/jamming attacks
    post_attack  - Post-attack analysis & next steps
    ap_clone     - AP auto-clone after deauth
    krack        - KRACK key reinstallation attack
    dos_wifi     - WiFi denial of service (multiple modes)
    client_isolation - Client disassociation/isolation
    printer_recon - Network printer discovery
    ipp_scanner  - IPP protocol scanner
    print_interceptor - Print job interception
    printer_creds - Printer credential harvesting
    monitor_mode - Windows monitor mode management
    monitor_windows - Windows monitor mode utility
    __main__     - CLI entry point
"""

__version__ = "2.1.0"

from .config import DB_NAME, CHANNELS_24GHZ, CHANNELS_5GHZ, log
from .database import POSDatabase
from .recon import ReconEngine
from .deauth import DeauthEngine
from .beacons import KnownBeaconsEngine
from .rogueap import RogueAPEngine
from .orchestrator import AttackOrchestrator
from .mitm import MITMEngine
from .ssl_strip import SSLStripper
from .dns_spoof import DNSSpoofEngine
from .cred_harvester import CredentialHarvester
from .network_disruption import NetworkDisruption, DeauthStorm
from .post_attack import PostAttackAnalyzer
from .monitor_mode import (
    setup_monitor_mode, teardown_monitor_mode,
    WindowsMonitorManager, LinuxMonitorManager,
    ChipMonitorManager, WindowsChipMonitorManager,
    check_npcap_monitor_support, get_available_interfaces,
    get_interface_mac, MonitorModeError, MonitorManagerInterface
)
from .ap_clone import APCloneEngine
from .krack import KRACKEngine
from .dos_wifi import WiFiDoSEngine, DoSMode
from .client_isolation import ClientIsolationEngine
from .printer_recon import PrinterRecon
from .ipp_scanner import IPPScanner
from .print_interceptor import PrintJobInterceptor
from .printer_creds import PrinterCredentialHarvester as PrinterCredHarvester
