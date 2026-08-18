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
    event_bus    - Async pub/sub event system
    plugin_system - Modern plugin architecture with lifecycle management
    capability_manager - Hardware-aware feature gating
    models       - Domain dataclasses (AccessPoint, Client, Target, etc.)
    config_loader - YAML configuration loader
    target_scorer - Target scoring and ranking
    attack_selector - Attack chain selection logic
    attack_flow - Recon-to-attack flow orchestration
    pmkid        - PMKID clientless capture
    multi_ap_capture - Multi-AP parallel handshake capture
    https_intercept - HTTPS TLS interception with dynamic cert generation
    session_hijacker - Cookie/JWT/OAuth/API key session capture
    ntlm_capture - NTLM/NTLMv2 hash capture (Responder-style)
    kerberos_capture - Kerberos AS-REP/TGS-REP ticket capture
    ldap_capture - LDAP simple bind credential capture
    cloud_cred_detector - AWS/GCP/Azure credential detection
    cert_auth_detector - Certificate-based auth interception detection
    cred_sprayer     - Credential spray/reuse testing across services
    cred_enrichment  - Credential metadata enrichment
    auto_pivot       - Auto-pivot with cracked credentials
    browser_cred_extract - Browser autofill credential extraction
    hashcat_integration - Hashcat WPA cracking integration
    cred_correlation - Cross-protocol credential correlation engine
    client_profiler  - Per-client device profiling
    vlan_scanner     - VLAN discovery via 802.1Q/CDP/LLDP/DTP
    network_mapper   - Network segmentation mapping
    __main__     - CLI entry point

Subpackages (new capabilities):
    ble/         - BLE scanning, beacon spoofing, GATT exploitation, HID injection
    sdr/         - SDR device management, spectrum analysis, signal decoding
    gps/         - Async gpsd client, haversine distance, position tracking
    wpa3/        - WPA3 detection (RSN IE parsing), downgrade attacks, SAE flood
    john_integration - John the Ripper CLI wrapper for password cracking
    tkip         - TKIP (Temporal Key Integrity Protocol) encryption/decryption
    ccmp         - CCMP (AES-CCM) encryption/decryption
    wpa2         - WPA2 4-way handshake state machine and key derivation
"""

__version__ = "3.0.0"

from .config import DB_NAME, CHANNELS_24GHZ, CHANNELS_5GHZ, log
from .database import POSDatabase

# All module imports are guarded with try/except since they depend on
# optional external libraries (scapy, bleak, pyrtlsdr, pywhat, etc.)

try:
    from .recon import ReconEngine
except ImportError:
    ReconEngine = None

try:
    from .deauth import DeauthEngine
except ImportError:
    DeauthEngine = None

try:
    from .beacons import KnownBeaconsEngine
except ImportError:
    KnownBeaconsEngine = None

try:
    from .rogueap import RogueAPEngine
except ImportError:
    RogueAPEngine = None

try:
    from .orchestrator import AttackOrchestrator
except ImportError:
    AttackOrchestrator = None

try:
    from .mitm import MITMEngine
except ImportError:
    MITMEngine = None

try:
    from .ssl_strip import SSLStripper
except ImportError:
    SSLStripper = None

try:
    from .dns_spoof import DNSSpoofEngine
except ImportError:
    DNSSpoofEngine = None

try:
    from .cred_harvester import CredentialHarvester
except ImportError:
    CredentialHarvester = None

try:
    from .network_disruption import NetworkDisruption, DeauthStorm
except ImportError:
    NetworkDisruption = None
    DeauthStorm = None

try:
    from .post_attack import PostAttackAnalyzer
except ImportError:
    PostAttackAnalyzer = None

try:
    from .monitor_mode import (
        setup_monitor_mode, teardown_monitor_mode,
        enhanced_setup_monitor_mode,
        WindowsMonitorManager, LinuxMonitorManager,
        ChipMonitorManager, WindowsChipMonitorManager,
        check_npcap_monitor_support, get_available_interfaces,
        get_interface_mac, MonitorModeError, MonitorManagerInterface
    )
except ImportError:
    setup_monitor_mode = None
    teardown_monitor_mode = None
    enhanced_setup_monitor_mode = None
    WindowsMonitorManager = None
    LinuxMonitorManager = None
    ChipMonitorManager = None
    WindowsChipMonitorManager = None
    check_npcap_monitor_support = None
    get_available_interfaces = None
    get_interface_mac = None
    MonitorModeError = None
    MonitorManagerInterface = None

try:
    from .chip_detector import ChipDetector, ChipInfo, MonitorMethodSelector
except ImportError:
    ChipDetector = None
    ChipInfo = None
    MonitorMethodSelector = None

try:
    from .monitor_manager import EnhancedMonitorManager
except ImportError:
    EnhancedMonitorManager = None

try:
    from .tshark_decrypt import TsharkDecryptionEngine, LiveDecryptionSession
except ImportError:
    TsharkDecryptionEngine = None
    LiveDecryptionSession = None

try:
    from .pywhat_analyzer import PyWhatAnalyzer, PyWhatCallback
except ImportError:
    PyWhatAnalyzer = None
    PyWhatCallback = None

try:
    from .ap_clone import APCloneEngine
except ImportError:
    APCloneEngine = None

try:
    from .krack import KRACKEngine
except ImportError:
    KRACKEngine = None

try:
    from .dos_wifi import WiFiDoSEngine, DoSMode
except ImportError:
    WiFiDoSEngine = None
    DoSMode = None

try:
    from .client_isolation import ClientIsolationEngine
except ImportError:
    ClientIsolationEngine = None

try:
    from .printer_recon import PrinterRecon
except ImportError:
    PrinterRecon = None

try:
    from .ipp_scanner import IPPScanner
except ImportError:
    IPPScanner = None

try:
    from .print_interceptor import PrintJobInterceptor
except ImportError:
    PrintJobInterceptor = None

try:
    from .printer_creds import PrinterCredentialHarvester as PrinterCredHarvester
except ImportError:
    PrinterCredHarvester = None

try:
    from .plugin_system import BasePlugin, PluginManager, PluginMetadata, PluginState, PluginType
except ImportError:
    BasePlugin = None
    PluginManager = None
    PluginMetadata = None
    PluginState = None
    PluginType = None

try:
    from .event_bus import EventBus, EventType, Event, get_event_bus
except ImportError:
    EventBus = None
    EventType = None
    Event = None
    get_event_bus = None

try:
    from .capability_manager import CapabilityManager, HardwareRequirement, MockCapabilityManager
except ImportError:
    CapabilityManager = None
    HardwareRequirement = None
    MockCapabilityManager = None

try:
    from .models import AccessPoint, Client, Handshake, Credential, Target, EncryptionType
except ImportError:
    AccessPoint = None
    Client = None
    Handshake = None
    Credential = None
    Target = None
    EncryptionType = None

try:
    from .config_loader import ConfigLoader
except ImportError:
    ConfigLoader = None

try:
    from .target_scorer import TargetScorer, ScoredTarget
except ImportError:
    TargetScorer = None
    ScoredTarget = None

try:
    from .attack_selector import AttackSelector, AttackChain, AttackStep
except ImportError:
    AttackSelector = None
    AttackChain = None
    AttackStep = None

try:
    from .attack_flow import ReconAttackFlow, FlowPhase
except ImportError:
    ReconAttackFlow = None
    FlowPhase = None

try:
    from .pmkid import PMKIDCapture
except ImportError:
    PMKIDCapture = None

try:
    from .multi_ap_capture import MultiAPCapture
except ImportError:
    MultiAPCapture = None

try:
    from .https_intercept import HTTPSInterceptor
except ImportError:
    HTTPSInterceptor = None

try:
    from .session_hijacker import SessionHijacker
except ImportError:
    SessionHijacker = None

try:
    from .ntlm_capture import NTLMCapture
except ImportError:
    NTLMCapture = None

try:
    from .kerberos_capture import KerberosCapture
except ImportError:
    KerberosCapture = None

try:
    from .ldap_capture import LDAPCapture
except ImportError:
    LDAPCapture = None

try:
    from .cloud_cred_detector import CloudCredentialDetector
except ImportError:
    CloudCredentialDetector = None

try:
    from .cert_auth_detector import CertAuthDetector
except ImportError:
    CertAuthDetector = None

try:
    from .cred_sprayer import CredentialSprayer
except ImportError:
    CredentialSprayer = None

try:
    from .cred_enrichment import CredentialEnrichment
except ImportError:
    CredentialEnrichment = None

try:
    from .auto_pivot import AutoPivot
except ImportError:
    AutoPivot = None

try:
    from .browser_cred_extract import BrowserCredentialExtractor
except ImportError:
    BrowserCredentialExtractor = None

try:
    from .hashcat_integration import HashcatIntegration
except ImportError:
    HashcatIntegration = None

try:
    from .cred_correlation import CredentialCorrelationEngine
except ImportError:
    CredentialCorrelationEngine = None

try:
    from .client_profiler import ClientProfiler
except ImportError:
    ClientProfiler = None

try:
    from .vlan_scanner import VLANScanner
except ImportError:
    VLANScanner = None

try:
    from .network_mapper import NetworkSegmentationMapper
except ImportError:
    NetworkSegmentationMapper = None

try:
    from .john_integration import JohnManager, JohnMode, JohnStatus
except ImportError:
    JohnManager = None
    JohnMode = None
    JohnStatus = None

try:
    from .tkip import TKIPEngine, TKIPKey, TKIPRole, MICCountermeasures
except ImportError:
    TKIPEngine = None
    TKIPKey = None
    TKIPRole = None
    MICCountermeasures = None

try:
    from .ccmp import CCMPEngine, CCMPKey, ccmp_encapsulate, ccmp_decapsulate
except ImportError:
    CCMPEngine = None
    CCMPKey = None
    ccmp_encapsulate = None
    ccmp_decapsulate = None

try:
    from .wpa2 import (
        WPA2Handshake, HandshakeRole, HandshakeState, CipherSuite,
        EAPOLKeyFrame, DerivedKeys, derive_pmk, derive_ptk,
        extract_key_hierarchy, compute_eapol_mic, verify_eapol_mic,
    )
except ImportError:
    WPA2Handshake = None
    HandshakeRole = None
    HandshakeState = None
    CipherSuite = None
    EAPOLKeyFrame = None
    DerivedKeys = None
    derive_pmk = None
    derive_ptk = None
    extract_key_hierarchy = None
    compute_eapol_mic = None
    verify_eapol_mic = None

# Subpackage re-exports for convenience
try:
    from . import ble
except ImportError:
    ble = None

try:
    from . import sdr
except ImportError:
    sdr = None

try:
    from . import gps
except ImportError:
    gps = None

try:
    from . import wpa3
except ImportError:
    wpa3 = None

try:
    from .intel_enricher import IntelEnricher
except ImportError:
    IntelEnricher = None

try:
    from .target_queue import TargetQueue
except ImportError:
    TargetQueue = None
