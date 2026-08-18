"""
POSFramework Advanced Terminal UI v3.0.0
----------------------------------------
Comprehensive ncurses-based terminal interface for POSFramework.
Wires in ALL 90+ modules across 9 organized tabs with:
  - Advanced target selection with sortable AP/client tables
  - Context-sensitive attack menus based on selected target
  - Passive credential/secret harvesting with live tshark decryption + pyWhat
  - Every module accessible from the UI organized into logical categories
  - Real-time status for all running engines
  - AutoPwn autonomous mode with full state machine integration

Uses ONLY Python standard library (curses module) for the UI.
All external modules are imported with graceful try/except fallbacks.

Tabs: [1:Targets] [2:WiFi Attacks] [3:Credential Attacks] [4:MITM]
      [5:Network] [6:BLE/SDR] [7:Harvester] [8:Cracking] [9:Settings]

Keys: q=quit, Tab/1-9=tabs, arrows=nav, Enter=action, Space=toggle,
      s=sort, a=autopwn, f=filter, /=search, e=export, r=refresh
"""

import os
import sys
import time
import curses
import threading
import logging
import asyncio
import json
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---- Core imports (always available) ----
from .config import (
    DB_NAME, CHANNELS_24GHZ, CHANNELS_5GHZ, IS_WINDOWS, IS_LINUX,
    DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE, log,
)
from .database import POSDatabase

# ---- Scapy-dependent engines ----
SCAPY_AVAILABLE = True
try:
    from .recon import ReconEngine
except ImportError:
    SCAPY_AVAILABLE = False
    ReconEngine = None

try:
    from .orchestrator import AttackOrchestrator
except ImportError:
    AttackOrchestrator = None

try:
    from .deauth import DeauthEngine
except ImportError:
    DeauthEngine = None

try:
    from .beacons import KnownBeaconsEngine
except ImportError:
    KnownBeaconsEngine = None

try:
    from .karma import KARMAEngine
except ImportError:
    KARMAEngine = None

try:
    from .rogueap import RogueAPEngine
except ImportError:
    RogueAPEngine = None

try:
    from .ap_clone import APCloneEngine
except ImportError:
    APCloneEngine = None

try:
    from .krack import KRACKEngine
except ImportError:
    KRACKEngine = None

try:
    from .dos_wifi import WiFiDoSEngine
except ImportError:
    WiFiDoSEngine = None

try:
    from .client_isolation import ClientIsolationEngine
except ImportError:
    ClientIsolationEngine = None

try:
    from .network_disruption import NetworkDisruption
except ImportError:
    NetworkDisruption = None

try:
    from .handshake import HandshakeCapture
except ImportError:
    HandshakeCapture = None

try:
    from .pmkid import PMKIDCapture
except ImportError:
    PMKIDCapture = None

try:
    from .multi_ap_capture import MultiAPCapture
except ImportError:
    MultiAPCapture = None

# ---- MITM modules ----
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

# ---- Credential modules ----
try:
    from .cred_harvester import CredentialHarvester
except ImportError:
    CredentialHarvester = None

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
    from .browser_cred_extract import BrowserCredentialExtractor
except ImportError:
    BrowserCredentialExtractor = None

try:
    from .cred_sprayer import CredentialSprayer
except ImportError:
    CredentialSprayer = None

try:
    from .cred_enrichment import CredentialEnrichment
except ImportError:
    CredentialEnrichment = None

try:
    from .cred_correlation import CredentialCorrelationEngine
except ImportError:
    CredentialCorrelationEngine = None

try:
    from .client_profiler import ClientProfiler
except ImportError:
    ClientProfiler = None

# ---- Network modules ----
try:
    from .vlan_scanner import VLANScanner
except ImportError:
    VLANScanner = None

try:
    from .network_mapper import NetworkSegmentationMapper
except ImportError:
    NetworkSegmentationMapper = None

try:
    from .auto_pivot import AutoPivot
except ImportError:
    AutoPivot = None

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
    from .printer_creds import PrinterCredentialHarvester
except ImportError:
    PrinterCredentialHarvester = None

# ---- Analysis modules ----
try:
    from .signal_targeting import SignalTargeting
except ImportError:
    SignalTargeting = None

try:
    from .target_scorer import TargetScorer
except ImportError:
    TargetScorer = None

try:
    from .attack_selector import AttackSelector
except ImportError:
    AttackSelector = None

try:
    from .post_attack import PostAttackAnalyzer
except ImportError:
    PostAttackAnalyzer = None

# ---- Cracking modules ----
try:
    from .hashcat_integration import HashcatIntegration
except ImportError:
    HashcatIntegration = None

try:
    from .john_integration import JohnManager
except ImportError:
    JohnManager = None

# ---- Harvester/Decryption modules ----
try:
    from .pywhat_analyzer import PyWhatAnalyzer, PyWhatCallback
except ImportError:
    PyWhatAnalyzer = None
    PyWhatCallback = None

try:
    from .tshark_decrypt import LiveDecryptionSession, TsharkDecryptionEngine
except ImportError:
    LiveDecryptionSession = None
    TsharkDecryptionEngine = None

# ---- WPA3 modules ----
try:
    from .wpa3.wpa3_attack import WPA3Attack
except ImportError:
    WPA3Attack = None

try:
    from .wpa3.wpa3_detector import WPA3Detector
except ImportError:
    WPA3Detector = None

# ---- BLE modules ----
try:
    from .ble.scanner import BLEScanner
except ImportError:
    BLEScanner = None

try:
    from .ble.beacon_spoofer import BeaconSpoofer
except ImportError:
    BeaconSpoofer = None

try:
    from .ble.gatt_explorer import GATTExplorer
except ImportError:
    GATTExplorer = None

try:
    from .ble.hid_injector import HIDInjector
except ImportError:
    HIDInjector = None

# ---- SDR modules ----
try:
    from .sdr.sdr_manager import SDRManager
except ImportError:
    SDRManager = None

try:
    from .sdr.spectrum_analyzer import SpectrumAnalyzer
except ImportError:
    SpectrumAnalyzer = None

try:
    from .sdr.signal_decoder import SignalDecoder
except ImportError:
    SignalDecoder = None

# ---- GPS modules ----
try:
    from .gps.gpsd_client import GPSDClient
except ImportError:
    GPSDClient = None

try:
    from .gps.distance import Distance
except ImportError:
    Distance = None

# ---- Infrastructure modules ----
try:
    from .event_bus import EventBus, EventType
except ImportError:
    EventBus = None
    EventType = None

try:
    from .autopwn_engine import AutoPwnEngine, AutoPwnConfig, AutoPwnMode, AutoPwnState
except ImportError:
    AutoPwnEngine = None
    AutoPwnConfig = None
    AutoPwnMode = None
    AutoPwnState = None

try:
    from .session_manager import SessionManager
except ImportError:
    SessionManager = None

try:
    from .plugin_system import PluginManager
except ImportError:
    PluginManager = None

try:
    from .capability_manager import CapabilityManager
except ImportError:
    CapabilityManager = None

try:
    from .radio_manager import RadioManager
except ImportError:
    RadioManager = None

try:
    from .load_balancer import LoadBalancer
except ImportError:
    LoadBalancer = None

try:
    from .monitor_manager import EnhancedMonitorManager
except ImportError:
    EnhancedMonitorManager = None

try:
    from .chip_detector import ChipDetector
except ImportError:
    ChipDetector = None

try:
    from .config_loader import ConfigLoader
except ImportError:
    ConfigLoader = None

try:
    from .net_utils import parse_cidr, get_interface_ip
except ImportError:
    parse_cidr = None
    get_interface_ip = None

# ---- Intelligence & Analysis tool wrappers ----
try:
    from .tools.p0f import P0F
except ImportError:
    P0F = None

try:
    from .tools.kismet import KismetClient
except ImportError:
    KismetClient = None

try:
    from .tools.airgraph import AirgraphNG
except ImportError:
    AirgraphNG = None

try:
    from .tools.horst import Horst
except ImportError:
    Horst = None

# ---- Attack Persistence (auto-save/auto-load vectors live) ----
try:
    from .attack_persistence import AttackPersistence
except ImportError:
    AttackPersistence = None


# ---- Version ----
VERSION = "3.0.0"

# ---- Color Pair IDs ----
COLOR_NORMAL = 0
COLOR_HEADER = 1
COLOR_SUCCESS = 2
COLOR_ERROR = 3
COLOR_WARNING = 4
COLOR_STATUS = 5
COLOR_SELECTED = 6
COLOR_TAB_ACTIVE = 7
COLOR_TAB_INACTIVE = 8
COLOR_ACCENT = 9
COLOR_CYAN_BG = 10
COLOR_HIGHLIGHT = 11
COLOR_RUNNING = 12
COLOR_STOPPED = 13
COLOR_DIM = 14
COLOR_CRITICAL = 15
COLOR_DIVIDER = 16
COLOR_GRADIENT = 17

# ---- UI Theme Constants (Unicode Box Drawing & Indicators) ----
# Single-line box drawing
BOX_H = "\u2500"          # horizontal line
BOX_V = "\u2502"          # vertical line
BOX_TL = "\u250c"         # top-left corner
BOX_TR = "\u2510"         # top-right corner
BOX_BL = "\u2514"         # bottom-left corner
BOX_BR = "\u2518"         # bottom-right corner
BOX_T_DOWN = "\u252c"     # T-junction pointing down
BOX_T_UP = "\u2534"       # T-junction pointing up
BOX_T_RIGHT = "\u251c"    # T-junction pointing right
BOX_T_LEFT = "\u2524"     # T-junction pointing left
BOX_CROSS = "\u253c"      # cross junction

# Double-line box drawing (for popups)
DOUBLE_BOX_H = "\u2550"   # double horizontal
DOUBLE_BOX_V = "\u2551"   # double vertical
DOUBLE_BOX_TL = "\u2554"  # double top-left
DOUBLE_BOX_TR = "\u2557"  # double top-right
DOUBLE_BOX_BL = "\u255a"  # double bottom-left
DOUBLE_BOX_BR = "\u255d"  # double bottom-right

# Status indicators
BULLET = "\u2022"         # bullet point
ARROW_RIGHT = "\u25b6"    # right-pointing triangle
CHECK_MARK = "\u2714"     # check mark
CROSS_MARK = "\u2718"     # cross mark
CIRCLE_FILLED = "\u25cf"  # filled circle (running)
CIRCLE_EMPTY = "\u25cb"   # empty circle (idle)
CIRCLE_DOT = "\u25c9"     # circle with dot (pulsing)

# Spinner frames for animated indicators
SPINNER_FRAMES = ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f"]

# Progress bar blocks
PROGRESS_BLOCKS = [" ", "\u2591", "\u2592", "\u2593", "\u2588"]  # empty, light, medium, dark, full


def _init_colors():
    """Initialize curses color pairs with enhanced theme."""
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(COLOR_HEADER, curses.COLOR_CYAN, -1)
    curses.init_pair(COLOR_SUCCESS, curses.COLOR_GREEN, -1)
    curses.init_pair(COLOR_ERROR, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_WARNING, curses.COLOR_YELLOW, -1)
    curses.init_pair(COLOR_STATUS, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(COLOR_SELECTED, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(COLOR_TAB_ACTIVE, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(COLOR_TAB_INACTIVE, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(COLOR_ACCENT, curses.COLOR_MAGENTA, -1)
    curses.init_pair(COLOR_CYAN_BG, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(COLOR_HIGHLIGHT, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(COLOR_RUNNING, curses.COLOR_GREEN, -1)
    curses.init_pair(COLOR_STOPPED, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(COLOR_CRITICAL, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_DIVIDER, curses.COLOR_BLUE, -1)
    curses.init_pair(COLOR_GRADIENT, curses.COLOR_CYAN, -1)


# ---- Log Capture Handler ----

class CursesLogHandler(logging.Handler):
    """Captures log records for display in the CLI UI."""

    def __init__(self, max_lines=500):
        super().__init__()
        self.records: List[Tuple[int, str]] = []
        self.max_lines = max_lines
        self._lock = threading.Lock()

    def emit(self, record):
        with self._lock:
            msg = self.format(record)
            self.records.append((record.levelno, msg))
            if len(self.records) > self.max_lines:
                self.records = self.records[-self.max_lines:]

    def get_records(self):
        with self._lock:
            return list(self.records)

    def clear(self):
        with self._lock:
            self.records.clear()


# ---- Tab definitions ----

TABS = [
    "Targets", "WiFi Attacks", "Cred Attacks", "MITM",
    "Network", "BLE/SDR", "Harvester", "Cracking", "Settings"
]

# ---- Sort modes for targets tab ----
SORT_MODES = ["rssi", "security", "pos", "channel", "clients", "ssid"]


# ---- Engine status tracking ----

class EngineStatus:
    """Track status of a module engine (thread-safe)."""
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PREVIOUSLY_ACTIVE = "previously_active"

    def __init__(self, name: str, engine_class=None):
        self.name = name
        self.engine_class = engine_class
        self.engine = None
        self._status = self.IDLE
        self.error_msg = ""
        self.start_time: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @status.setter
    def status(self, value: str):
        with self._lock:
            self._status = value

    @property
    def available(self) -> bool:
        return self.engine_class is not None

    @property
    def is_running(self) -> bool:
        return self.status == self.RUNNING

    def start(self, *args, **kwargs):
        """Start the engine."""
        if not self.available:
            self.status = self.FAILED
            self.error_msg = "Module not available"
            return False
        try:
            if self.engine is None:
                self.engine = self.engine_class(*args, **kwargs)
            self.engine.start()
            self.status = self.RUNNING
            self.start_time = time.time()
            return True
        except Exception as e:
            self.status = self.FAILED
            self.error_msg = str(e)
            return False

    def stop(self):
        """Stop the engine."""
        if self.engine and self.status == self.RUNNING:
            try:
                self.engine.stop()
                self.status = self.IDLE
            except Exception as e:
                self.status = self.FAILED
                self.error_msg = str(e)
        else:
            self.status = self.IDLE
        self.engine = None

    def toggle(self, *args, **kwargs):
        """Toggle engine start/stop."""
        if self.is_running:
            self.stop()
        else:
            self.start(*args, **kwargs)


# ---- Logging handler for curses mode ----

class _CursesLogHandler(logging.Handler):
    """Logging handler that captures log records into the TerminalUI activity feed.

    When the curses GUI is active, stderr output corrupts the display.
    This handler intercepts all log records and routes them to the UI's
    internal activity feed deque, which is displayed within the curses panels.
    """

    def __init__(self, ui_instance):
        super().__init__()
        self._ui = ui_instance

    def emit(self, record):
        try:
            msg = self.format(record)
            # Route to the UI's activity feed
            level_map = {
                "CRITICAL": "critical",
                "ERROR": "error",
                "WARNING": "warning",
                "INFO": "info",
                "DEBUG": "debug",
            }
            category = level_map.get(record.levelname, "info")
            self._ui._log_activity(msg, category)
        except Exception:
            pass  # Never let logging errors crash the UI


# ---- Main Terminal UI Class ----

class TerminalUI:
    """Advanced ncurses terminal UI for POSFramework v3.0.

    Comprehensive 9-tab interface wiring in all 90+ modules with:
    - Advanced target selection with sortable AP/client tables
    - Context-sensitive attack menus
    - Passive credential/secret harvesting
    - AutoPwn autonomous mode
    """

    def __init__(self):
        self.db = POSDatabase()
        self.running = True
        self.active_tab = 0
        self.scroll_offset = 0
        self.menu_selected = 0
        self.stdscr = None

        # Thread safety lock for shared mutable state accessed from daemon threads
        self._state_lock = threading.Lock()

        # Log handler
        self.log_handler = CursesLogHandler()
        self.log_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
        )
        log.addHandler(self.log_handler)

        # Target selection
        self.selected_target_idx = 0
        self.selected_client_idx = 0
        self.selected_target: Optional[Dict] = None
        self.selected_client: Optional[Dict] = None
        self.target_view = "ap"  # "ap" or "client"
        self.sort_mode = 0  # index into SORT_MODES
        self.filter_text = ""
        self.show_popup = False
        self.popup_items: List[str] = []
        self.popup_selected = 0
        self.popup_title = ""

        # Core engines
        self.recon_engine = None
        self.recon_running = False
        self.autopwn_engine = None
        self.autopwn_running = False
        self.autopwn_state = "IDLE"
        self.event_bus = None

        # Client profiler
        self.client_profiler = None
        if ClientProfiler is not None:
            try:
                self.client_profiler = ClientProfiler(db=self.db)
            except Exception:
                pass

        # WiFi attack engines
        self.wifi_attacks = {
            "deauth": EngineStatus("Deauthentication", DeauthEngine),
            "beacons": EngineStatus("Beacon Flood", KnownBeaconsEngine),
            "karma": EngineStatus("KARMA AP", KARMAEngine),
            "rogueap": EngineStatus("Rogue AP", RogueAPEngine),
            "ap_clone": EngineStatus("Evil Twin/AP Clone", APCloneEngine),
            "krack": EngineStatus("KRACK Attack", KRACKEngine),
            "dos_cts": EngineStatus("DoS: CTS Flood", WiFiDoSEngine),
            "dos_beacon": EngineStatus("DoS: Beacon Exhaust", WiFiDoSEngine),
            "dos_qos": EngineStatus("DoS: QoS Null", WiFiDoSEngine),
            "dos_frag": EngineStatus("DoS: Fragment", WiFiDoSEngine),
            "client_iso": EngineStatus("Client Isolation", ClientIsolationEngine),
            "net_disrupt": EngineStatus("Network Disruption", NetworkDisruption),
            "wpa3_attack": EngineStatus("WPA3 Downgrade", WPA3Attack),
            "wpa3_detect": EngineStatus("WPA3 Detector", WPA3Detector),
            "handshake": EngineStatus("Handshake Capture", HandshakeCapture),
            "pmkid": EngineStatus("PMKID Capture", PMKIDCapture),
            "multi_cap": EngineStatus("Multi-AP Capture", MultiAPCapture),
        }

        # Credential attack engines
        self.cred_attacks = {
            "harvester": EngineStatus("HTTP/FTP/IMAP Harvester", CredentialHarvester),
            "https": EngineStatus("HTTPS Interceptor", HTTPSInterceptor),
            "session": EngineStatus("Session Hijacker", SessionHijacker),
            "ntlm": EngineStatus("NTLM Capture", NTLMCapture),
            "kerberos": EngineStatus("Kerberos Capture", KerberosCapture),
            "ldap": EngineStatus("LDAP Capture", LDAPCapture),
            "cloud": EngineStatus("Cloud Credential Detect", CloudCredentialDetector),
            "cert_auth": EngineStatus("Certificate Auth Detect", CertAuthDetector),
            "browser": EngineStatus("Browser Cred Extract", BrowserCredentialExtractor),
            "sprayer": EngineStatus("Credential Sprayer", CredentialSprayer),
            "enrichment": EngineStatus("Credential Enrichment", CredentialEnrichment),
            "correlation": EngineStatus("Credential Correlation", CredentialCorrelationEngine),
        }

        # MITM engines
        self.mitm_attacks = {
            "arp": EngineStatus("ARP Poison (MITM)", MITMEngine),
            "ssl_strip": EngineStatus("SSL Strip", SSLStripper),
            "dns_spoof": EngineStatus("DNS Spoof", DNSSpoofEngine),
        }

        # Network engines
        self.network_modules = {
            "vlan": EngineStatus("VLAN Scanner", VLANScanner),
            "mapper": EngineStatus("Network Mapper", NetworkSegmentationMapper),
            "pivot": EngineStatus("Auto-Pivot", AutoPivot),
            "printer_recon": EngineStatus("Printer Recon", PrinterRecon),
            "ipp": EngineStatus("IPP Scanner", IPPScanner),
            "print_intercept": EngineStatus("Print Interceptor", PrintJobInterceptor),
            "printer_creds": EngineStatus("Printer Credentials", PrinterCredentialHarvester),
        }

        # Intelligence & Analysis engines
        self.intel_modules = {
            "p0f": EngineStatus("P0F OS Fingerprint", P0F),
            "kismet": EngineStatus("Kismet WiFi Intel", KismetClient),
            "airgraph": EngineStatus("Airgraph-NG Visualizer", AirgraphNG),
            "horst": EngineStatus("Horst Link Scanner", Horst),
        }

        # BLE/SDR engines
        self.ble_sdr_modules = {
            "ble_scan": EngineStatus("BLE Scanner", BLEScanner),
            "ble_beacon": EngineStatus("Beacon Spoofer", BeaconSpoofer),
            "ble_gatt": EngineStatus("GATT Explorer", GATTExplorer),
            "ble_hid": EngineStatus("HID Injector", HIDInjector),
            "sdr_mgr": EngineStatus("SDR Manager", SDRManager),
            "spectrum": EngineStatus("Spectrum Analyzer", SpectrumAnalyzer),
            "decoder": EngineStatus("Signal Decoder", SignalDecoder),
            "gps": EngineStatus("GPS Client", GPSDClient),
        }

        # Harvester state
        self.harvester_session: Optional[Any] = None
        self.harvester_running = False
        self.pywhat_analyzer: Optional[Any] = None
        self.pywhat_callback: Optional[Any] = None
        self.harvester_psk = ""
        self.harvester_ssid = ""
        self.harvester_wep_key = ""
        self.harvester_findings: List[Dict] = []

        if PyWhatAnalyzer is not None:
            try:
                self.pywhat_analyzer = PyWhatAnalyzer()
            except Exception:
                pass

        # Cracking state
        self.hashcat_engine = None
        self.john_engine = None
        self.cracking_active = False
        self.cracking_progress = 0.0
        self.cracking_mode = "dictionary"  # dictionary, brute-force, rules
        self.wordlist_path = "/usr/share/wordlists/rockyou.txt"
        self.captured_handshakes: List[Dict] = []
        self.crack_target_bssid = ""
        self.crack_target_ssid = ""

        # Settings
        self.monitor_iface = DEFAULT_MONITOR_IFACE
        self.ap_iface = DEFAULT_AP_IFACE
        self.use_5ghz = False
        self.channels = CHANNELS_24GHZ
        self.verbose_mode = False
        self.signal_targeting_enabled = False
        self.rssi_limit = -80
        self.recon_duration = 30
        self.dos_mode = "cts_flood"

        # MITM config
        self.mitm_target_ip = ""
        self.mitm_gateway_ip = ""
        self.dns_spoof_domain = ""

        # Infrastructure
        self.config_loader = None
        self.plugin_manager = None
        self.capability_manager = None
        self.radio_manager = None
        self.load_balancer = None
        self.monitor_manager = None
        self.chip_detector = None
        self.session_manager = None

        # Track acquired adapter pools for release on engine stop
        self._active_pools: Dict[str, List] = {}

        # Initialize infrastructure
        self._init_infrastructure()

        # Attack persistence: live auto-save/auto-load of vectors and targets
        self.attack_persistence: Optional[Any] = None
        if AttackPersistence is not None:
            try:
                self.attack_persistence = AttackPersistence()
            except Exception:
                pass

        # Live-load persisted attack state on startup
        self._load_persisted_state()

        # UI state
        self.status_message = "Ready"
        self.last_refresh = 0
        self.input_mode = False
        self.input_buffer = ""
        self.input_field = ""
        self.input_callback = None

        # Intercepted traffic for MITM tab
        self.intercepted_traffic: List[Dict] = []

        # Notification system
        self.notifications: List[Dict] = []
        self._last_cred_count = 0

        # Activity feed
        self.activity_feed: deque = deque(maxlen=50)

        # Help overlay
        self.show_help = False

        # Confirmation dialog state
        self._confirm_active = False
        self._confirm_message = ""
        self._confirm_callback = None

    def _init_infrastructure(self):
        """Initialize infrastructure modules."""
        if ConfigLoader is not None:
            try:
                self.config_loader = ConfigLoader()
            except Exception:
                pass
        if PluginManager is not None:
            try:
                self.plugin_manager = PluginManager()
            except Exception:
                pass
        if CapabilityManager is not None:
            try:
                self.capability_manager = CapabilityManager()
            except Exception:
                pass
        if RadioManager is not None:
            try:
                self.radio_manager = RadioManager()
            except Exception:
                pass
        if LoadBalancer is not None and self.radio_manager is not None:
            try:
                self.load_balancer = LoadBalancer(self.radio_manager)
                # Initialize the load balancer (async) from synchronous context
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self.load_balancer.initialize())
                loop.close()
            except Exception:
                pass
        if EnhancedMonitorManager is not None:
            try:
                self.monitor_manager = EnhancedMonitorManager()
            except Exception:
                pass
        if ChipDetector is not None:
            try:
                self.chip_detector = ChipDetector()
            except Exception:
                pass
        if SessionManager is not None:
            try:
                self.session_manager = SessionManager()
            except Exception:
                pass

    # ================================================================
    # ATTACK STATE PERSISTENCE (live save/load)
    # ================================================================

    def _load_persisted_state(self) -> None:
        """Load persisted attack state and populate UI fields (live load).

        Called at startup to immediately restore targets, attack vectors,
        and settings from the last session.
        """
        if not self.attack_persistence:
            return
        try:
            state = self.attack_persistence.load()
            if not state:
                return

            # Restore selected target
            if state.get("selected_target"):
                self.selected_target = state["selected_target"]

            # Restore selected client
            if state.get("selected_client"):
                self.selected_client = state["selected_client"]

            # Restore settings
            settings = state.get("settings", {})
            if settings.get("monitor_iface"):
                self.monitor_iface = settings["monitor_iface"]
            if settings.get("ap_iface"):
                self.ap_iface = settings["ap_iface"]
            if "use_5ghz" in settings:
                self.use_5ghz = bool(settings["use_5ghz"])
                self.channels = (
                    (CHANNELS_24GHZ + CHANNELS_5GHZ)
                    if self.use_5ghz
                    else CHANNELS_24GHZ
                )
            if "rssi_limit" in settings:
                try:
                    self.rssi_limit = int(settings["rssi_limit"])
                except (ValueError, TypeError):
                    pass
            if "recon_duration" in settings:
                try:
                    self.recon_duration = int(settings["recon_duration"])
                except (ValueError, TypeError):
                    pass
            if settings.get("mitm_target_ip"):
                self.mitm_target_ip = settings["mitm_target_ip"]
            if settings.get("mitm_gateway_ip"):
                self.mitm_gateway_ip = settings["mitm_gateway_ip"]
            if settings.get("dns_spoof_domain"):
                self.dns_spoof_domain = settings["dns_spoof_domain"]
            if settings.get("wordlist_path"):
                self.wordlist_path = settings["wordlist_path"]
            if settings.get("cracking_mode"):
                self.cracking_mode = settings["cracking_mode"]

            # Restore enabled_attacks: mark engines that were running
            enabled_attacks = state.get("enabled_attacks", {})
            if enabled_attacks:
                self._restore_enabled_attacks(enabled_attacks)

            log.info("Attack state loaded live from persisted file")
        except Exception as e:
            log.warning("Failed to load persisted attack state: %s", e)

    def _restore_enabled_attacks(self, enabled_attacks: Dict[str, bool]) -> None:
        """Restore which attacks were enabled from persisted state.

        Maps saved enabled_attacks keys back to engine groups and sets
        the is_running flag for engines that were active in the previous session.
        This does NOT actually start processes - it marks them so the UI reflects
        their previous state for the user to re-launch.

        Args:
            enabled_attacks: Dict mapping 'group_key' -> bool.
        """
        # Map prefix to engine group
        group_map = {
            "wifi_": self.wifi_attacks,
            "cred_": self.cred_attacks,
            "mitm_": self.mitm_attacks,
            "network_": self.network_modules,
            "intel_": self.intel_modules,
            "ble_sdr_": self.ble_sdr_modules,
        }

        for full_key, was_running in enabled_attacks.items():
            if not was_running:
                continue
            # Determine which group and engine key
            for prefix, engines in group_map.items():
                if full_key.startswith(prefix):
                    engine_key = full_key[len(prefix):]
                    engine = engines.get(engine_key)
                    if engine is not None:
                        # Mark as previously active so UI shows saved state
                        # (actual process restart requires user action)
                        engine.status = EngineStatus.PREVIOUSLY_ACTIVE
                    break

    def _save_attack_state(self) -> None:
        """Save current attack state to disk immediately (live save).

        Called after every target selection, attack toggle, or settings change
        to persist vectors live.
        """
        if not self.attack_persistence:
            return
        try:
            # Collect enabled attacks across all engine groups
            enabled_attacks: Dict[str, bool] = {}
            for key, eng in self.wifi_attacks.items():
                enabled_attacks[f"wifi_{key}"] = eng.is_running
            for key, eng in self.cred_attacks.items():
                enabled_attacks[f"cred_{key}"] = eng.is_running
            for key, eng in self.mitm_attacks.items():
                enabled_attacks[f"mitm_{key}"] = eng.is_running
            for key, eng in self.network_modules.items():
                enabled_attacks[f"network_{key}"] = eng.is_running
            for key, eng in self.intel_modules.items():
                enabled_attacks[f"intel_{key}"] = eng.is_running
            for key, eng in self.ble_sdr_modules.items():
                enabled_attacks[f"ble_sdr_{key}"] = eng.is_running

            # Build settings snapshot
            settings = {
                "monitor_iface": self.monitor_iface,
                "ap_iface": self.ap_iface,
                "use_5ghz": self.use_5ghz,
                "channels": list(self.channels) if self.channels else [],
                "rssi_limit": self.rssi_limit,
                "recon_duration": self.recon_duration,
                "mitm_target_ip": self.mitm_target_ip,
                "mitm_gateway_ip": self.mitm_gateway_ip,
                "dns_spoof_domain": self.dns_spoof_domain,
                "wordlist_path": self.wordlist_path,
                "cracking_mode": self.cracking_mode,
            }

            state = self.attack_persistence.build_state(
                selected_target=self.selected_target,
                selected_client=self.selected_client,
                enabled_attacks=enabled_attacks,
                attack_params={},
                settings=settings,
            )
            self.attack_persistence.save(state)
        except Exception as e:
            log.warning("Failed to save attack state: %s", e)

    # ================================================================
    # PUBLIC API
    # ================================================================

    def run(self):
        """Main entry point - wraps curses."""
        if IS_WINDOWS:
            print("Error: Curses-based terminal UI is not supported on Windows.")
            print("Use 'python -m posframework recon' or other CLI modes directly.")
            return
        try:
            # Redirect logging away from stderr while curses is active.
            # Log messages written to stderr corrupt the curses display.
            # We capture them in a deque and display inside the UI instead.
            self._setup_gui_logging()
            curses.wrapper(self._main_loop)
        except curses.error as e:
            print(f"Terminal UI error: {e}")
            print("Ensure your terminal supports curses (not a pipe or redirect).")
        finally:
            self._restore_logging()

    def _setup_gui_logging(self):
        """Redirect framework logging to an internal buffer for curses display.

        Removes all existing handlers from the POSFramework logger and replaces
        them with a handler that writes to self._log_buffer (a deque shown in
        the activity feed). Saves original handlers for restoration on exit.
        """
        self._original_handlers = log.handlers[:]
        self._original_level = log.level

        # Remove stderr handlers to prevent curses corruption
        for handler in log.handlers[:]:
            log.removeHandler(handler)

        # Add a custom handler that captures to our deque
        self._log_handler = _CursesLogHandler(self)
        self._log_handler.setLevel(logging.DEBUG)
        self._log_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
        )
        log.addHandler(self._log_handler)

        # Also redirect the root logger to avoid stray library output
        root = logging.getLogger()
        self._original_root_handlers = root.handlers[:]
        for handler in root.handlers[:]:
            if hasattr(handler, 'stream') and hasattr(handler.stream, 'fileno'):
                try:
                    if handler.stream.fileno() in (1, 2):  # stdout/stderr
                        root.removeHandler(handler)
                except (ValueError, OSError):
                    pass

    def _restore_logging(self):
        """Restore original logging handlers after curses exits."""
        # Restore POSFramework logger
        if hasattr(self, '_log_handler'):
            log.removeHandler(self._log_handler)
        if hasattr(self, '_original_handlers'):
            for handler in self._original_handlers:
                log.addHandler(handler)

        # Restore root logger
        if hasattr(self, '_original_root_handlers'):
            root = logging.getLogger()
            for handler in self._original_root_handlers:
                if handler not in root.handlers:
                    root.addHandler(handler)

    # ================================================================
    # MAIN LOOP
    # ================================================================

    def _main_loop(self, stdscr):
        """Main curses event loop."""
        self.stdscr = stdscr
        _init_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(500)

        while self.running:
            try:
                self._draw(stdscr)
                key = stdscr.getch()
                if key != -1:
                    self._handle_input(key)
            except curses.error:
                pass
            except KeyboardInterrupt:
                self.running = False

        self._cleanup()

    # ================================================================
    # SAFE DRAWING HELPERS
    # ================================================================

    def _safe_addstr(self, win, y, x, text, attr=0):
        """Safely add a string, catching curses errors for edge cases."""
        try:
            h, w = win.getmaxyx()
            if y < 0 or y >= h or x < 0:
                return
            max_len = w - x - 1
            if max_len <= 0:
                return
            win.addstr(y, x, str(text).replace('\x00', '')[:max_len], attr)
        except curses.error:
            pass

    def _safe_hline(self, win, y, x, ch, n, attr=0):
        """Safely draw a horizontal line."""
        try:
            h, w = win.getmaxyx()
            if y < 0 or y >= h or x < 0:
                return
            max_n = min(n, w - x - 1)
            if max_n <= 0:
                return
            win.hline(y, x, ch, max_n, attr)
        except curses.error:
            pass

    def _draw_box(self, win, y, x, height, width, title=""):
        """Draw a bordered box with optional title using Unicode box-drawing."""
        try:
            h, w = win.getmaxyx()
            if y + height > h or x + width > w:
                height = min(height, h - y)
                width = min(width, w - x)
            if height < 2 or width < 2:
                return
            # Top border
            self._safe_addstr(win, y, x, BOX_TL + BOX_H * (width - 2) + BOX_TR)
            # Sides
            for i in range(1, height - 1):
                self._safe_addstr(win, y + i, x, BOX_V)
                self._safe_addstr(win, y + i, x + width - 1, BOX_V)
            # Bottom border
            self._safe_addstr(win, y + height - 1, x, BOX_BL + BOX_H * (width - 2) + BOX_BR)
            # Title
            if title:
                self._safe_addstr(win, y, x + 2, f" {title} ", curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_section_header(self, stdscr, y, x, w, title, color_pair=COLOR_HEADER):
        """Draw a section title with horizontal line extending to fill the width."""
        try:
            title_str = f" {title} "
            self._safe_addstr(stdscr, y, x, BOX_T_RIGHT + BOX_H, curses.color_pair(color_pair))
            self._safe_addstr(stdscr, y, x + 2, title_str, curses.color_pair(color_pair) | curses.A_BOLD)
            line_start = x + 2 + len(title_str)
            remaining = w - line_start - 1
            if remaining > 0:
                self._safe_addstr(stdscr, y, line_start, BOX_H * remaining, curses.color_pair(color_pair))
        except curses.error:
            pass

    def _draw_progress_bar(self, stdscr, y, x, w, progress, label='', color_pair=COLOR_SUCCESS):
        """Render a Unicode block-character progress bar with percentage and optional label."""
        try:
            # Clamp progress to 0-1
            progress = max(0.0, min(1.0, progress))
            # Reserve space for label and percentage
            pct_str = f" {int(progress * 100)}%"
            label_str = f"{label} " if label else ""
            bar_width = w - len(label_str) - len(pct_str) - 2  # 2 for brackets
            if bar_width < 3:
                return

            # Draw label
            if label_str:
                self._safe_addstr(stdscr, y, x, label_str, curses.color_pair(color_pair))

            # Build the bar using block characters
            filled = int(bar_width * progress)
            remainder = (bar_width * progress) - filled
            bar_str = PROGRESS_BLOCKS[4] * filled  # full blocks

            # Partial block for fractional part
            if remainder > 0.75:
                bar_str += PROGRESS_BLOCKS[3]
            elif remainder > 0.5:
                bar_str += PROGRESS_BLOCKS[2]
            elif remainder > 0.25:
                bar_str += PROGRESS_BLOCKS[1]
            elif filled < bar_width:
                bar_str += PROGRESS_BLOCKS[0]

            # Fill remaining with empty
            bar_str += PROGRESS_BLOCKS[0] * (bar_width - len(bar_str))
            bar_str = bar_str[:bar_width]

            bar_x = x + len(label_str)
            self._safe_addstr(stdscr, y, bar_x, "[", curses.color_pair(color_pair))
            self._safe_addstr(stdscr, y, bar_x + 1, bar_str, curses.color_pair(color_pair) | curses.A_BOLD)
            self._safe_addstr(stdscr, y, bar_x + 1 + bar_width, "]", curses.color_pair(color_pair))
            self._safe_addstr(stdscr, y, bar_x + 2 + bar_width, pct_str, curses.color_pair(color_pair))
        except curses.error:
            pass

    # ================================================================
    # NOTIFICATION SYSTEM
    # ================================================================

    def _add_notification(self, message: str, level: str = "info"):
        """Add a notification to the notification queue.

        Args:
            message: Notification text.
            level: One of 'info', 'warning', 'critical'.
        """
        notification = {
            "message": message,
            "level": level,
            "timestamp": time.time(),
            "seen": False,
        }
        self.notifications.append(notification)
        # Keep max 20 notifications
        if len(self.notifications) > 20:
            self.notifications = self.notifications[-20:]

    def _draw_notifications(self, stdscr, h, w):
        """Draw the most recent unseen notification as a badge in the header area."""
        unseen = [n for n in self.notifications if not n["seen"]]
        if not unseen:
            return

        # Show notification count badge on the right side of row 0
        badge_str = f" {CIRCLE_FILLED} {len(unseen)} "
        badge_x = w - len(badge_str) - 12  # Before the time display
        if badge_x < 30:
            return

        # Color based on highest severity
        has_critical = any(n["level"] == "critical" for n in unseen)
        has_warning = any(n["level"] == "warning" for n in unseen)
        if has_critical:
            attr = curses.color_pair(COLOR_CRITICAL) | curses.A_BOLD
            if int(time.time()) % 2 == 0:
                attr |= curses.A_BLINK
        elif has_warning:
            attr = curses.color_pair(COLOR_WARNING) | curses.A_BOLD
        else:
            attr = curses.color_pair(COLOR_SUCCESS) | curses.A_BOLD

        self._safe_addstr(stdscr, 0, badge_x, badge_str, attr)

        # Show the latest notification text below tabs
        latest = unseen[-1]
        # Auto-mark as seen after 5 seconds
        if time.time() - latest["timestamp"] > 5:
            latest["seen"] = True
            return

        icon = {
            "info": CIRCLE_FILLED,
            "warning": ARROW_RIGHT,
            "critical": CROSS_MARK,
        }.get(latest["level"], BULLET)

        notif_str = f" {icon} {latest['message']}"
        notif_attr = attr
        # Draw on the separator line (row 2) if space allows
        if len(notif_str) < w - 4:
            self._safe_addstr(stdscr, 2, w - len(notif_str) - 2, notif_str[:w-4], notif_attr)

    # ================================================================
    # ACTIVITY FEED
    # ================================================================

    def _log_activity(self, message: str, category: str = "general"):
        """Log an activity to the activity feed.

        Args:
            message: Activity description.
            category: Category tag (engine, recon, export, target, etc.).
        """
        entry = {
            "message": message,
            "category": category,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        self.activity_feed.append(entry)

    # ================================================================
    # HELP OVERLAY
    # ================================================================

    def _draw_help_overlay(self, stdscr, h, w):
        """Draw a centered help overlay showing all keyboard shortcuts."""
        # Calculate overlay dimensions (80% of screen)
        overlay_h = max(20, int(h * 0.8))
        overlay_w = max(50, int(w * 0.8))
        start_y = max(1, (h - overlay_h) // 2)
        start_x = max(1, (w - overlay_w) // 2)

        # Clamp to screen bounds
        overlay_h = min(overlay_h, h - start_y - 1)
        overlay_w = min(overlay_w, w - start_x - 1)

        if overlay_h < 10 or overlay_w < 30:
            return

        # Draw shadow
        for sy in range(start_y + 1, start_y + overlay_h + 1):
            if sy < h:
                self._safe_addstr(stdscr, sy, start_x + overlay_w, " ", curses.A_DIM)
        if start_y + overlay_h < h:
            self._safe_addstr(stdscr, start_y + overlay_h, start_x + 1,
                              " " * min(overlay_w, w - start_x - 2), curses.A_DIM)

        # Draw double-line border
        self._safe_addstr(stdscr, start_y, start_x,
                          DOUBLE_BOX_TL + DOUBLE_BOX_H * (overlay_w - 2) + DOUBLE_BOX_TR,
                          curses.color_pair(COLOR_HEADER))
        for i in range(1, overlay_h - 1):
            self._safe_addstr(stdscr, start_y + i, start_x, DOUBLE_BOX_V, curses.color_pair(COLOR_HEADER))
            self._safe_addstr(stdscr, start_y + i, start_x + 1, " " * (overlay_w - 2))
            self._safe_addstr(stdscr, start_y + i, start_x + overlay_w - 1, DOUBLE_BOX_V, curses.color_pair(COLOR_HEADER))
        self._safe_addstr(stdscr, start_y + overlay_h - 1, start_x,
                          DOUBLE_BOX_BL + DOUBLE_BOX_H * (overlay_w - 2) + DOUBLE_BOX_BR,
                          curses.color_pair(COLOR_HEADER))

        # Title
        title = " Keyboard Shortcuts "
        title_x = start_x + (overlay_w - len(title)) // 2
        self._safe_addstr(stdscr, start_y, title_x, title,
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)

        # Content
        cx = start_x + 3
        cy = start_y + 2
        max_line_w = overlay_w - 6

        sections = [
            ("Navigation", [
                ("Tab / Shift+Tab", "Next / Previous tab"),
                ("1-9", "Jump to tab by number"),
                ("Up / Down", "Navigate items"),
                ("PgUp / PgDn", "Scroll by page"),
                ("Space", "Toggle view (Targets) / Toggle setting"),
            ]),
            ("Actions", [
                ("Enter", "Execute action / Toggle engine"),
                ("s", "Cycle sort mode (Targets)"),
                ("r", "Start recon (Targets) / Refresh"),
                ("x", "Stop recon"),
                ("a", "AutoPwn toggle / Stop recon & attack"),
                ("e", "Export current data"),
                ("f or /", "Filter / Search"),
            ]),
            ("Display", [
                ("?", "Toggle this help overlay"),
                ("q / Q", "Quit application"),
            ]),
            ("Tabs Overview", [
                ("1: Targets", "AP/Client discovery and selection"),
                ("2: WiFi Attacks", "Deauth, beacon, KARMA, WPA3"),
                ("3: Cred Attacks", "Credential harvesting modules"),
                ("4: MITM", "ARP poison, SSL strip, DNS spoof"),
                ("5: Network", "VLAN, mapper, pivot, printers"),
                ("6: BLE/SDR", "Bluetooth & software-defined radio"),
                ("7: Harvester", "Live tshark decrypt + pyWhat"),
                ("8: Cracking", "Hashcat & John integration"),
                ("9: Settings", "Configuration & module status"),
            ]),
        ]

        for section_title, shortcuts in sections:
            if cy >= start_y + overlay_h - 2:
                break
            # Section header
            self._safe_addstr(stdscr, cy, cx, section_title,
                              curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
            cy += 1
            for key, desc in shortcuts:
                if cy >= start_y + overlay_h - 2:
                    break
                line = f"  {key:<20s} {desc}"
                self._safe_addstr(stdscr, cy, cx, line[:max_line_w],
                                  curses.color_pair(COLOR_NORMAL))
                cy += 1
            cy += 1  # Gap between sections

        # Footer hint
        footer = " Press ? or Esc to close "
        footer_x = start_x + (overlay_w - len(footer)) // 2
        if start_y + overlay_h - 1 < h:
            self._safe_addstr(stdscr, start_y + overlay_h - 1, footer_x, footer,
                              curses.color_pair(COLOR_DIM))

    # ================================================================
    # CONFIRMATION DIALOG
    # ================================================================

    def _show_confirm(self, message: str, on_confirm):
        """Show a confirmation dialog for destructive actions.

        Args:
            message: The confirmation prompt text.
            on_confirm: Callback to execute if user confirms (Y).
        """
        self._confirm_active = True
        self._confirm_message = message
        self._confirm_callback = on_confirm

    def _draw_confirm_dialog(self, stdscr, h, w):
        """Render the confirmation dialog popup."""
        if not self._confirm_active:
            return

        msg = self._confirm_message
        popup_w = min(max(len(msg) + 8, 30), w - 4)
        popup_h = 5
        start_y = max(2, (h - popup_h) // 2)
        start_x = max(2, (w - popup_w) // 2)

        # Shadow
        for sy in range(start_y + 1, start_y + popup_h + 1):
            if sy < h:
                self._safe_addstr(stdscr, sy, start_x + popup_w, " ", curses.A_DIM)
        if start_y + popup_h < h:
            self._safe_addstr(stdscr, start_y + popup_h, start_x + 1,
                              " " * min(popup_w, w - start_x - 2), curses.A_DIM)

        # Double-line border
        self._safe_addstr(stdscr, start_y, start_x,
                          DOUBLE_BOX_TL + DOUBLE_BOX_H * (popup_w - 2) + DOUBLE_BOX_TR,
                          curses.color_pair(COLOR_WARNING))
        for i in range(1, popup_h - 1):
            self._safe_addstr(stdscr, start_y + i, start_x, DOUBLE_BOX_V, curses.color_pair(COLOR_WARNING))
            self._safe_addstr(stdscr, start_y + i, start_x + 1, " " * (popup_w - 2))
            self._safe_addstr(stdscr, start_y + i, start_x + popup_w - 1, DOUBLE_BOX_V, curses.color_pair(COLOR_WARNING))
        self._safe_addstr(stdscr, start_y + popup_h - 1, start_x,
                          DOUBLE_BOX_BL + DOUBLE_BOX_H * (popup_w - 2) + DOUBLE_BOX_BR,
                          curses.color_pair(COLOR_WARNING))

        # Title
        title = " Confirm "
        title_x = start_x + (popup_w - len(title)) // 2
        self._safe_addstr(stdscr, start_y, title_x, title,
                          curses.color_pair(COLOR_WARNING) | curses.A_BOLD)

        # Message
        self._safe_addstr(stdscr, start_y + 1, start_x + 2, msg[:popup_w - 4],
                          curses.color_pair(COLOR_NORMAL) | curses.A_BOLD)

        # Options
        options_str = "[Y] Yes    [N] No"
        opt_x = start_x + (popup_w - len(options_str)) // 2
        self._safe_addstr(stdscr, start_y + 3, opt_x, options_str,
                          curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)

    # ================================================================
    # MAIN DRAW
    # ================================================================

    def _draw(self, stdscr):
        """Main draw routine."""
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        if h < 10 or w < 40:
            self._safe_addstr(stdscr, 0, 0, "Terminal too small. Resize to at least 40x10.")
            stdscr.refresh()
            return

        # Draw header
        self._draw_header(stdscr, w)
        # Draw tabs
        self._draw_tabs(stdscr, w)
        # Draw content area (row 3 to h-3)
        self._draw_content(stdscr, h, w)
        # Draw status bar
        self._draw_status_bar(stdscr, h, w)
        # Draw help bar
        self._draw_help_bar(stdscr, h, w)
        # Draw notifications badge/toast
        self._draw_notifications(stdscr, h, w)
        # Draw popup if active
        if self.show_popup:
            self._draw_popup(stdscr, h, w)
        # Draw input mode if active
        if self.input_mode:
            self._draw_input(stdscr, h, w)
        # Draw confirmation dialog if active
        if self._confirm_active:
            self._draw_confirm_dialog(stdscr, h, w)
        # Draw help overlay on top of everything
        if self.show_help:
            self._draw_help_overlay(stdscr, h, w)

        # Check for credential count changes (trigger notifications)
        self._check_credential_notifications()

        stdscr.refresh()

    def _check_credential_notifications(self):
        """Check for credential count changes and trigger notifications."""
        try:
            current_creds = self._get_credentials_count()
            if current_creds > self._last_cred_count and self._last_cred_count > 0:
                new_count = current_creds - self._last_cred_count
                self._add_notification(
                    f"New credentials captured! (+{new_count})", "critical"
                )
                self._log_activity(
                    f"Discovered {new_count} new credential(s)", "credential"
                )
            self._last_cred_count = current_creds
        except Exception:
            pass

    def _draw_header(self, stdscr, w):
        """Draw the header banner with version, subtitle, and time."""
        # Full-width background
        self._safe_addstr(stdscr, 0, 0, " " * w, curses.color_pair(COLOR_STATUS))
        # Title (bold cyan)
        title = f" POSFramework v{VERSION}"
        self._safe_addstr(stdscr, 0, 0, title, curses.color_pair(COLOR_STATUS) | curses.A_BOLD)
        # Subtitle (dim)
        subtitle = " Advanced WiFi Security Suite"
        sub_x = len(title)
        if sub_x + len(subtitle) < w - 10:
            self._safe_addstr(stdscr, 0, sub_x, subtitle, curses.color_pair(COLOR_STATUS))
        # Time on the right
        now = datetime.now().strftime("%H:%M:%S")
        time_str = f" {now} "
        time_x = max(0, w - len(time_str) - 1)
        self._safe_addstr(stdscr, 0, time_x, time_str, curses.color_pair(COLOR_STATUS) | curses.A_BOLD)

    def _draw_tabs(self, stdscr, w):
        """Draw the tab bar with modern Unicode indicators."""
        x = 0
        for i, tab in enumerate(TABS):
            if i == self.active_tab:
                label = f" [{i+1}:{tab}] "
                attr = curses.color_pair(COLOR_TAB_ACTIVE) | curses.A_BOLD
            else:
                label = f"  {i+1}:{tab}  "
                attr = curses.color_pair(COLOR_TAB_INACTIVE)
            self._safe_addstr(stdscr, 1, x, label, attr)
            x += len(label)
        # Fill remainder
        if x < w:
            self._safe_addstr(stdscr, 1, x, " " * (w - x - 1), curses.color_pair(COLOR_TAB_INACTIVE))
        # Visual separator between tabs and content
        separator = BOX_H * (w - 1)
        self._safe_addstr(stdscr, 2, 0, separator, curses.color_pair(COLOR_DIVIDER))

    def _draw_content(self, stdscr, h, w):
        """Draw content based on active tab, with activity log at bottom."""
        # Content area: row 3 to h-3
        # Reserve bottom 6 rows of content area for activity log
        log_panel_height = min(6, max(3, (h - 6) // 4))
        content_h = h - log_panel_height  # tabs get full height minus log panel

        tab = TABS[self.active_tab]
        if tab == "Targets":
            self._draw_targets_tab(stdscr, content_h, w)
        elif tab == "WiFi Attacks":
            self._draw_wifi_attacks_tab(stdscr, content_h, w)
        elif tab == "Cred Attacks":
            self._draw_cred_attacks_tab(stdscr, content_h, w)
        elif tab == "MITM":
            self._draw_mitm_tab(stdscr, content_h, w)
        elif tab == "Network":
            self._draw_network_tab(stdscr, content_h, w)
        elif tab == "BLE/SDR":
            self._draw_ble_sdr_tab(stdscr, content_h, w)
        elif tab == "Harvester":
            self._draw_harvester_tab(stdscr, content_h, w)
        elif tab == "Cracking":
            self._draw_cracking_tab(stdscr, content_h, w)
        elif tab == "Settings":
            self._draw_settings_tab(stdscr, content_h, w)

        # Draw activity log panel at bottom of content area
        self._draw_activity_log(stdscr, h, w, content_h)

    def _draw_activity_log(self, stdscr, h, w, start_y):
        """Draw the activity log panel showing recent log messages.

        Renders the last N entries from self.activity_feed in a bordered
        panel at the bottom of the content area, above the status bar.
        """
        panel_top = start_y
        panel_bottom = h - 3  # Leave room for status + help bars
        available_rows = panel_bottom - panel_top - 1  # -1 for header

        if available_rows < 2:
            return

        # Panel header with separator
        header = f"{BOX_H * 2} Activity Log {BOX_H * (w - 17)}"
        self._safe_addstr(stdscr, panel_top, 0, header[:w-1], curses.color_pair(COLOR_DIVIDER))

        # Get recent activity entries
        entries = list(self.activity_feed)
        visible_entries = entries[-(available_rows):]

        # Color mapping for categories
        cat_colors = {
            "critical": COLOR_CRITICAL,
            "error": COLOR_WARNING,
            "warning": COLOR_WARNING,
            "info": COLOR_NORMAL,
            "debug": COLOR_DIM,
            "engine": COLOR_RUNNING,
            "recon": COLOR_ACCENT,
            "credential": COLOR_CRITICAL,
            "general": COLOR_NORMAL,
        }

        for i, entry in enumerate(visible_entries):
            y = panel_top + 1 + i
            if y >= panel_bottom:
                break

            ts = entry.get("timestamp", "")
            msg = entry.get("message", "")
            cat = entry.get("category", "general")
            color = cat_colors.get(cat, COLOR_NORMAL)

            # Format: [HH:MM:SS] message
            line = f" {ts} {msg}"
            self._safe_addstr(stdscr, y, 0, line[:w-1], curses.color_pair(color))

    def _draw_status_bar(self, stdscr, h, w):
        """Draw the status bar with color-coded segments and pulsing indicator."""
        y = h - 2
        self._safe_addstr(stdscr, y, 0, " " * w, curses.color_pair(COLOR_STATUS))

        # Running engines count
        running_count = sum(1 for e in self.wifi_attacks.values() if e.is_running)
        running_count += sum(1 for e in self.cred_attacks.values() if e.is_running)
        running_count += sum(1 for e in self.mitm_attacks.values() if e.is_running)
        running_count += sum(1 for e in self.network_modules.values() if e.is_running)
        running_count += sum(1 for e in self.ble_sdr_modules.values() if e.is_running)
        if self.recon_running:
            running_count += 1
        if self.harvester_running:
            running_count += 1

        # AP/Client counts
        aps = self._get_access_points()
        clients = self._get_clients()
        creds = self._get_credentials_count()

        # Pulsing dot indicator for active engines
        pulse_char = CIRCLE_FILLED if (int(time.time()) % 2 == 0 and running_count > 0) else CIRCLE_EMPTY

        x_pos = 1
        # Pulsing indicator
        if running_count > 0:
            self._safe_addstr(stdscr, y, x_pos, f"{pulse_char}", curses.color_pair(COLOR_RUNNING))
            x_pos += 2

        # Engines (green)
        eng_str = f"Engines: {running_count}"
        self._safe_addstr(stdscr, y, x_pos, eng_str, curses.color_pair(COLOR_STATUS) | curses.A_BOLD)
        x_pos += len(eng_str)

        # Separator
        self._safe_addstr(stdscr, y, x_pos, " \u2502 ", curses.color_pair(COLOR_STATUS))
        x_pos += 3

        # APs (cyan)
        ap_str = f"APs: {len(aps)}"
        self._safe_addstr(stdscr, y, x_pos, ap_str, curses.color_pair(COLOR_STATUS))
        x_pos += len(ap_str)

        self._safe_addstr(stdscr, y, x_pos, " \u2502 ", curses.color_pair(COLOR_STATUS))
        x_pos += 3

        # Clients
        cli_str = f"Clients: {len(clients)}"
        self._safe_addstr(stdscr, y, x_pos, cli_str, curses.color_pair(COLOR_STATUS))
        x_pos += len(cli_str)

        self._safe_addstr(stdscr, y, x_pos, " \u2502 ", curses.color_pair(COLOR_STATUS))
        x_pos += 3

        # Creds (yellow)
        cred_str = f"Creds: {creds}"
        self._safe_addstr(stdscr, y, x_pos, cred_str, curses.color_pair(COLOR_STATUS) | curses.A_BOLD)
        x_pos += len(cred_str)

        if self.recon_running:
            self._safe_addstr(stdscr, y, x_pos, " \u2502 ", curses.color_pair(COLOR_STATUS))
            x_pos += 3
            self._safe_addstr(stdscr, y, x_pos, f"{CIRCLE_FILLED} RECON", curses.color_pair(COLOR_STATUS) | curses.A_BOLD)
            x_pos += 7

        if self.autopwn_running:
            self._safe_addstr(stdscr, y, x_pos, " \u2502 ", curses.color_pair(COLOR_STATUS))
            x_pos += 3
            self._safe_addstr(stdscr, y, x_pos, f"{CIRCLE_FILLED} AUTOPWN:{self.autopwn_state}", curses.color_pair(COLOR_STATUS) | curses.A_BOLD)
            x_pos += 10 + len(str(self.autopwn_state))

        if self.selected_target:
            ssid = self.selected_target.get("ssid", "?")[:16]
            bssid = self.selected_target.get("bssid", "?")[:17]
            self._safe_addstr(stdscr, y, x_pos, " \u2502 ", curses.color_pair(COLOR_STATUS))
            x_pos += 3
            target_str = f"{ARROW_RIGHT} {ssid} ({bssid})"
            self._safe_addstr(stdscr, y, x_pos, target_str, curses.color_pair(COLOR_STATUS))
            x_pos += len(target_str)

        # Time on the right
        now = datetime.now().strftime("%H:%M:%S")
        time_x = max(x_pos + 2, w - len(now) - 2)
        self._safe_addstr(stdscr, y, time_x, now, curses.color_pair(COLOR_STATUS))

    def _draw_help_bar(self, stdscr, h, w):
        """Draw context-sensitive help bar with bracketed key indicators."""
        y = h - 1
        tab = TABS[self.active_tab]
        if tab == "Targets":
            keys = [("Q", "Quit"), ("Tab", "Switch"), ("s", "Sort"), ("Enter", "Attack"), ("Space", "Toggle"), ("\u2191\u2193", "Nav"), ("a", "AutoPwn"), ("r", "Refresh"), ("?", "Help")]
        elif tab == "Harvester":
            keys = [("Q", "Quit"), ("Tab", "Switch"), ("Enter", "Start/Stop"), ("Space", "Config"), ("e", "Export"), ("r", "Refresh"), ("?", "Help")]
        elif tab == "Cracking":
            keys = [("Q", "Quit"), ("Tab", "Switch"), ("Enter", "Start/Stop"), ("Space", "Mode"), ("\u2191\u2193", "Nav"), ("?", "Help")]
        else:
            keys = [("Q", "Quit"), ("Tab", "Switch"), ("Enter", "Action"), ("Space", "Toggle"), ("\u2191\u2193", "Nav"), ("a", "AutoPwn"), ("e", "Export"), ("?", "Help")]

        x_pos = 1
        for key, desc in keys:
            if x_pos >= w - 10:
                break
            # Key in brackets with highlight color
            key_str = f"[{key}]"
            self._safe_addstr(stdscr, y, x_pos, key_str, curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            x_pos += len(key_str)
            # Description
            desc_str = f" {desc} "
            self._safe_addstr(stdscr, y, x_pos, desc_str, curses.color_pair(COLOR_DIM))
            x_pos += len(desc_str)

    # ================================================================
    # TARGETS TAB
    # ================================================================

    def _draw_targets_tab(self, stdscr, h, w):
        """Draw the Targets tab with sortable AP and client tables."""
        start_y = 3

        # Dashboard summary panel
        aps = self._get_access_points()
        clients = self._get_clients()
        creds = self._get_credentials_count()
        running_count = sum(1 for e in self.wifi_attacks.values() if e.is_running)
        running_count += sum(1 for e in self.cred_attacks.values() if e.is_running)
        running_count += sum(1 for e in self.mitm_attacks.values() if e.is_running)
        running_count += sum(1 for e in self.network_modules.values() if e.is_running)
        running_count += sum(1 for e in self.ble_sdr_modules.values() if e.is_running)

        recon_label = f"{CIRCLE_FILLED} Active" if self.recon_running else f"{CIRCLE_EMPTY} Idle"
        autopwn_label = f"{CIRCLE_FILLED} {self.autopwn_state}" if self.autopwn_running else f"{CIRCLE_EMPTY} Off"

        dash_line = (
            f" APs: {len(aps)} {BOX_V} Clients: {len(clients)} {BOX_V} "
            f"Creds: {creds} {BOX_V} Engines: {running_count} {BOX_V} "
            f"Recon: {recon_label} {BOX_V} AutoPwn: {autopwn_label}"
        )
        self._safe_addstr(stdscr, start_y, 1, dash_line[:w-2],
                          curses.color_pair(COLOR_GRADIENT) | curses.A_BOLD)
        start_y += 1

        # Header using section header
        sort_name = SORT_MODES[self.sort_mode]
        view_label = "Access Points" if self.target_view == "ap" else "Clients"
        header = f"[{view_label}] Sort: {sort_name} | Space: Toggle AP/Client View | s: Cycle Sort"
        if self.recon_running:
            header += f" | {CIRCLE_FILLED} Recon Active"
        else:
            header += " | r: Start Recon"
        self._draw_section_header(stdscr, start_y, 1, w - 2, header, COLOR_HEADER)

        if self.target_view == "ap":
            self._draw_ap_table(stdscr, start_y + 2, h, w)
        else:
            self._draw_client_table(stdscr, start_y + 2, h, w)

    def _draw_ap_table(self, stdscr, start_y, h, w):
        """Draw AP table with columns and alternating row shading."""
        # Column headers
        cols = " {:17s} {:20s} {:3s} {:8s} {:5s} {:12s} {:3s} {:4s}".format(
            "BSSID", "SSID", "Ch", "Security", "RSSI", "Vendor", "POS", "Cli"
        )
        self._safe_addstr(stdscr, start_y, 1, cols[:w-2], curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
        self._safe_addstr(stdscr, start_y + 1, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        aps = self._get_access_points()
        max_rows = h - start_y - 5
        visible_aps = aps[self.scroll_offset:self.scroll_offset + max_rows]

        for i, ap in enumerate(visible_aps):
            y = start_y + 2 + i
            if y >= h - 3:
                break
            actual_idx = self.scroll_offset + i
            bssid = ap.get("bssid", "??:??:??:??:??:??")[:17]
            ssid = ap.get("ssid", "<hidden>")[:20]
            ch = str(ap.get("channel", "?"))[:3]
            sec = (ap.get("security") or "?")[:8]
            rssi = str(ap.get("rssi", "?"))[:5]
            vendor = (ap.get("vendor") or "")[:12]
            pos = "YES" if ap.get("is_pos", False) else ""
            cli_count = str(ap.get("client_count", 0))[:4]

            # Use arrow for selected item
            prefix = f" {ARROW_RIGHT}" if actual_idx == self.selected_target_idx else "  "
            line = "{} {:17s} {:20s} {:3s} {:8s} {:5s} {:12s} {:3s} {:4s}".format(
                prefix, bssid, ssid, ch, sec, rssi, vendor, pos, cli_count
            )

            if actual_idx == self.selected_target_idx:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
                self.selected_target = ap
            elif ap.get("is_pos", False):
                attr = curses.color_pair(COLOR_WARNING)
            elif i % 2 == 0:
                attr = curses.color_pair(COLOR_NORMAL) | curses.A_DIM
            else:
                attr = curses.color_pair(COLOR_NORMAL)

            self._safe_addstr(stdscr, y, 1, line[:w-2], attr)

    def _draw_client_table(self, stdscr, start_y, h, w):
        """Draw client table with columns."""
        cols = " {:17s} {:12s} {:17s} {:5s} {:10s} {:10s}".format(
            "MAC", "Vendor", "Associated AP", "RSSI", "OS", "DevType"
        )
        self._safe_addstr(stdscr, start_y, 1, cols[:w-2], curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
        self._safe_addstr(stdscr, start_y + 1, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        clients = self._get_clients()
        max_rows = h - start_y - 5
        visible_clients = clients[self.scroll_offset:self.scroll_offset + max_rows]

        for i, client in enumerate(visible_clients):
            y = start_y + 2 + i
            if y >= h - 3:
                break
            actual_idx = self.scroll_offset + i
            mac = client.get("mac", "??:??:??:??:??:??")[:17]
            vendor = client.get("vendor", "")[:12]
            assoc_ap = client.get("associated_ap", "")[:17]
            rssi = str(client.get("rssi", "?"))[:5]
            os_fp = client.get("os", "")[:10]
            dev_type = client.get("device_type", "")[:10]

            line = " {:17s} {:12s} {:17s} {:5s} {:10s} {:10s}".format(
                mac, vendor, assoc_ap, rssi, os_fp, dev_type
            )

            if actual_idx == self.selected_client_idx:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
                self.selected_client = client
            else:
                attr = curses.color_pair(COLOR_NORMAL)

            self._safe_addstr(stdscr, y, 1, line[:w-2], attr)

    # ================================================================
    # WIFI ATTACKS TAB
    # ================================================================

    def _format_engine_uptime(self, engine) -> str:
        """Format engine uptime as Xm Xs if running."""
        if engine.is_running and engine.start_time:
            elapsed = time.time() - engine.start_time
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            return f" {minutes}m {seconds}s"
        return ""

    def _draw_wifi_attacks_tab(self, stdscr, h, w):
        """Draw WiFi Attacks tab with all attack modules."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "WiFi Attack Modules (Enter: Toggle Start/Stop)", COLOR_HEADER)

        if self.selected_target:
            target_info = f" {ARROW_RIGHT} Target: {self.selected_target.get('ssid', '?')} ({self.selected_target.get('bssid', '?')})"
            self._safe_addstr(stdscr, start_y + 1, 1, target_info, curses.color_pair(COLOR_WARNING))

        self._safe_addstr(stdscr, start_y + 2, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        y = start_y + 3
        items = list(self.wifi_attacks.items())
        max_rows = h - y - 3
        visible_items = items[self.scroll_offset:self.scroll_offset + max_rows]

        for i, (key, engine) in enumerate(visible_items):
            actual_idx = self.scroll_offset + i
            row_y = y + i
            if row_y >= h - 3:
                break

            # Status indicator with Unicode circles
            uptime_str = self._format_engine_uptime(engine)
            if engine.is_running:
                status = f"{CIRCLE_FILLED} RUNNING{uptime_str}"
                status_color = curses.color_pair(COLOR_RUNNING)
            elif engine.status == EngineStatus.FAILED:
                status = f"{CROSS_MARK} FAILED"
                status_color = curses.color_pair(COLOR_ERROR)
            elif engine.status == EngineStatus.SUCCESS:
                status = f"{CHECK_MARK} DONE"
                status_color = curses.color_pair(COLOR_SUCCESS)
            elif engine.status == EngineStatus.PREVIOUSLY_ACTIVE:
                status = f"{CIRCLE_DOT} SAVED"
                status_color = curses.color_pair(COLOR_WARNING)
            else:
                status = f"{CIRCLE_EMPTY} IDLE"
                status_color = curses.color_pair(COLOR_NORMAL)

            avail = BULLET if engine.available else CROSS_MARK
            line = f" {avail} {engine.name:<28s} {status}"

            if actual_idx == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            else:
                attr = status_color

            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

    # ================================================================
    # CREDENTIAL ATTACKS TAB
    # ================================================================

    def _draw_cred_attacks_tab(self, stdscr, h, w):
        """Draw Credential Attacks tab."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "Credential Attack Modules (Enter: Toggle Start/Stop)", COLOR_HEADER)

        if self.selected_target:
            target_info = f" {ARROW_RIGHT} Target: {self.selected_target.get('ssid', '?')} ({self.selected_target.get('bssid', '?')})"
            self._safe_addstr(stdscr, start_y + 1, 1, target_info, curses.color_pair(COLOR_WARNING))

        self._safe_addstr(stdscr, start_y + 2, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        y = start_y + 3
        items = list(self.cred_attacks.items())
        max_rows = h - y - 3
        visible_items = items[self.scroll_offset:self.scroll_offset + max_rows]

        for i, (key, engine) in enumerate(visible_items):
            actual_idx = self.scroll_offset + i
            row_y = y + i
            if row_y >= h - 3:
                break

            uptime_str = self._format_engine_uptime(engine)
            if engine.is_running:
                status = f"{CIRCLE_FILLED} RUNNING{uptime_str}"
                status_color = curses.color_pair(COLOR_RUNNING)
            elif engine.status == EngineStatus.FAILED:
                status = f"{CROSS_MARK} FAILED"
                status_color = curses.color_pair(COLOR_ERROR)
            elif engine.status == EngineStatus.PREVIOUSLY_ACTIVE:
                status = f"{CIRCLE_DOT} SAVED"
                status_color = curses.color_pair(COLOR_WARNING)
            else:
                status = f"{CIRCLE_EMPTY} IDLE"
                status_color = curses.color_pair(COLOR_NORMAL)

            avail = BULLET if engine.available else CROSS_MARK
            line = f" {avail} {engine.name:<28s} {status}"

            if actual_idx == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            else:
                attr = status_color

            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

    # ================================================================
    # MITM TAB
    # ================================================================

    def _draw_mitm_tab(self, stdscr, h, w):
        """Draw MITM tab with attack modules and intercepted traffic."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "Man-in-the-Middle Attacks", COLOR_HEADER)

        # Config display
        cfg_y = start_y + 1
        target_info = ""
        if self.selected_target:
            target_info = f" [{ARROW_RIGHT} {self.selected_target.get('ssid', '?')} ({self.selected_target.get('bssid', '?')})]"
        self._safe_addstr(stdscr, cfg_y, 1,
                          f" Target IP: {self.mitm_target_ip or '<not set>'} | Gateway: {self.mitm_gateway_ip or '<not set>'} | DNS Domain: {self.dns_spoof_domain or '<any>'}{target_info}",
                          curses.color_pair(COLOR_WARNING))
        self._safe_addstr(stdscr, cfg_y + 1, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        # Attack modules
        y = cfg_y + 2
        items = list(self.mitm_attacks.items())
        for i, (key, engine) in enumerate(items):
            row_y = y + i
            if row_y >= h - 3:
                break

            uptime_str = self._format_engine_uptime(engine)
            if engine.is_running:
                status = f"{CIRCLE_FILLED} RUNNING{uptime_str}"
                status_color = curses.color_pair(COLOR_RUNNING)
            elif engine.status == EngineStatus.PREVIOUSLY_ACTIVE:
                status = f"{CIRCLE_DOT} SAVED"
                status_color = curses.color_pair(COLOR_WARNING)
            else:
                status = f"{CIRCLE_EMPTY} IDLE"
                status_color = curses.color_pair(COLOR_NORMAL)

            avail = BULLET if engine.available else CROSS_MARK
            line = f" {avail} {engine.name:<28s} {status}"

            if i == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            else:
                attr = status_color

            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

        # Intercepted traffic table
        traffic_y = y + len(items) + 1
        self._draw_section_header(stdscr, traffic_y, 1, w - 2, "Intercepted Traffic", COLOR_ACCENT)

        cols = " {:15s} {:15s} {:8s} {:30s}".format("Source", "Dest", "Proto", "Data")
        self._safe_addstr(stdscr, traffic_y + 1, 1, cols[:w-2], curses.color_pair(COLOR_ACCENT))

        max_traffic = h - traffic_y - 6
        for i, traffic in enumerate(self.intercepted_traffic[-max_traffic:]):
            ty = traffic_y + 2 + i
            if ty >= h - 3:
                break
            src = traffic.get("src", "?")[:15]
            dst = traffic.get("dst", "?")[:15]
            proto = traffic.get("proto", "?")[:8]
            data = traffic.get("data", "")[:30]
            line = " {:15s} {:15s} {:8s} {:30s}".format(src, dst, proto, data)
            self._safe_addstr(stdscr, ty, 1, line[:w-2], curses.color_pair(COLOR_NORMAL))

    # ================================================================
    # NETWORK TAB
    # ================================================================

    def _draw_network_tab(self, stdscr, h, w):
        """Draw Network tab."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "Network Reconnaissance & Exploitation", COLOR_HEADER)
        self._safe_addstr(stdscr, start_y + 1, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        y = start_y + 2
        items = list(self.network_modules.items())
        max_rows = h - y - 3
        visible_items = items[self.scroll_offset:self.scroll_offset + max_rows]

        for i, (key, engine) in enumerate(visible_items):
            actual_idx = self.scroll_offset + i
            row_y = y + i
            if row_y >= h - 3:
                break

            uptime_str = self._format_engine_uptime(engine)
            if engine.is_running:
                status = f"{CIRCLE_FILLED} RUNNING{uptime_str}"
                status_color = curses.color_pair(COLOR_RUNNING)
            elif engine.status == EngineStatus.FAILED:
                status = f"{CROSS_MARK} FAILED"
                status_color = curses.color_pair(COLOR_ERROR)
            elif engine.status == EngineStatus.PREVIOUSLY_ACTIVE:
                status = f"{CIRCLE_DOT} SAVED"
                status_color = curses.color_pair(COLOR_WARNING)
            else:
                status = f"{CIRCLE_EMPTY} IDLE"
                status_color = curses.color_pair(COLOR_NORMAL)

            avail = BULLET if engine.available else CROSS_MARK
            line = f" {avail} {engine.name:<28s} {status}"

            if actual_idx == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            else:
                attr = status_color

            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

    # ================================================================
    # BLE/SDR TAB
    # ================================================================

    def _draw_ble_sdr_tab(self, stdscr, h, w):
        """Draw BLE/SDR tab with all BLE, SDR, and GPS modules."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "BLE / SDR / GPS Modules", COLOR_HEADER)
        self._safe_addstr(stdscr, start_y + 1, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        y = start_y + 2
        items = list(self.ble_sdr_modules.items())
        max_rows = h - y - 3
        visible_items = items[self.scroll_offset:self.scroll_offset + max_rows]

        for i, (key, engine) in enumerate(visible_items):
            actual_idx = self.scroll_offset + i
            row_y = y + i
            if row_y >= h - 3:
                break

            uptime_str = self._format_engine_uptime(engine)
            if engine.is_running:
                status = f"{CIRCLE_FILLED} RUNNING{uptime_str}"
                status_color = curses.color_pair(COLOR_RUNNING)
            elif engine.status == EngineStatus.FAILED:
                status = f"{CROSS_MARK} FAILED"
                status_color = curses.color_pair(COLOR_ERROR)
            elif engine.status == EngineStatus.PREVIOUSLY_ACTIVE:
                status = f"{CIRCLE_DOT} SAVED"
                status_color = curses.color_pair(COLOR_WARNING)
            else:
                status = f"{CIRCLE_EMPTY} IDLE"
                status_color = curses.color_pair(COLOR_NORMAL)

            avail = BULLET if engine.available else CROSS_MARK
            line = f" {avail} {engine.name:<28s} {status}"

            if actual_idx == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            else:
                attr = status_color

            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

    # ================================================================
    # HARVESTER TAB
    # ================================================================

    def _draw_harvester_tab(self, stdscr, h, w):
        """Draw Harvester tab - live tshark decryption + pyWhat analysis."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "Passive Credential & Secret Harvester (tshark + pyWhat)", COLOR_HEADER)

        # Controls row
        ctrl_y = start_y + 1
        running_label = f"{CIRCLE_FILLED} RUNNING" if self.harvester_running else f"{CIRCLE_EMPTY} STOPPED"
        running_color = curses.color_pair(COLOR_RUNNING) if self.harvester_running else curses.color_pair(COLOR_STOPPED)
        self._safe_addstr(stdscr, ctrl_y, 1, f" Status: ", curses.color_pair(COLOR_NORMAL))
        self._safe_addstr(stdscr, ctrl_y, 10, running_label, running_color)

        pywhat_status = "active" if self.pywhat_analyzer else "unavailable"
        self._safe_addstr(stdscr, ctrl_y, 22, f" | pyWhat: {pywhat_status} | PSK: {self.harvester_psk or '<none>'} | SSID: {self.harvester_ssid or '<none>'}",
                          curses.color_pair(COLOR_WARNING))

        self._safe_addstr(stdscr, ctrl_y + 1, 1, BOX_H * (w - 2), curses.color_pair(COLOR_DIVIDER))

        # Split view: top half = decrypted feed, bottom half = pyWhat findings
        content_h = h - ctrl_y - 5
        feed_h = content_h // 2
        findings_h = content_h - feed_h

        # Decrypted traffic feed
        feed_y = ctrl_y + 2
        self._safe_addstr(stdscr, feed_y, 1, " Live Decrypted Traffic Feed:",
                          curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)

        feed_data = self._get_decryption_feed()
        cols = " {:8s} {:8s} {:40s}".format("Time", "Proto", "Data")
        self._safe_addstr(stdscr, feed_y + 1, 1, cols[:w-2], curses.color_pair(COLOR_ACCENT))

        max_feed = min(feed_h - 3, len(feed_data))
        for i in range(max_feed):
            entry = feed_data[-(max_feed - i)]
            fy = feed_y + 2 + i
            if fy >= feed_y + feed_h:
                break
            ts = entry.get("time", "")[:8]
            proto = entry.get("proto", "")[:8]
            data = entry.get("data", "")[:40]
            line = " {:8s} {:8s} {:40s}".format(ts, proto, data)
            self._safe_addstr(stdscr, fy, 1, line[:w-2], curses.color_pair(COLOR_NORMAL))

        # pyWhat findings table
        findings_y = feed_y + feed_h
        self._safe_addstr(stdscr, findings_y, 1, " pyWhat Findings (Secrets, Keys, Credentials):",
                          curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)

        findings_cols = " {:8s} {:15s} {:30s} {:6s} {:8s}".format(
            "Time", "Type", "Value", "Conf", "Source"
        )
        self._safe_addstr(stdscr, findings_y + 1, 1, findings_cols[:w-2], curses.color_pair(COLOR_ACCENT))

        findings = self._get_harvester_findings()
        max_findings = min(findings_h - 3, len(findings))
        for i in range(max_findings):
            finding = findings[-(max_findings - i)]
            fy = findings_y + 2 + i
            if fy >= h - 3:
                break
            ts = finding.get("timestamp", "")[:8]
            ftype = finding.get("name", finding.get("type", ""))[:15]
            value = finding.get("value", "")[:30]
            conf = str(finding.get("confidence", ""))[:6]
            source = finding.get("source", finding.get("category", ""))[:8]
            line = " {:8s} {:15s} {:30s} {:6s} {:8s}".format(ts, ftype, value, conf, source)

            # Color based on confidence
            if finding.get("confidence", 0) >= 0.8:
                attr = curses.color_pair(COLOR_ERROR) | curses.A_BOLD
            elif finding.get("confidence", 0) >= 0.5:
                attr = curses.color_pair(COLOR_WARNING)
            else:
                attr = curses.color_pair(COLOR_NORMAL)

            self._safe_addstr(stdscr, fy, 1, line[:w-2], attr)

        # Attack surfaces summary at bottom if space
        if findings_y + max_findings + 3 < h - 3 and self.pywhat_analyzer:
            surf_y = findings_y + max_findings + 3
            self._safe_addstr(stdscr, surf_y, 1, " Attack Surfaces:",
                              curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
            surfaces = self._get_attack_surfaces()
            sx = 1
            for category, items in list(surfaces.items())[:6]:
                label = f" {category}:{len(items)}"
                self._safe_addstr(stdscr, surf_y + 1, sx, label,
                                  curses.color_pair(COLOR_WARNING))
                sx += len(label) + 1

    # ================================================================
    # CRACKING TAB
    # ================================================================

    def _draw_cracking_tab(self, stdscr, h, w):
        """Draw Cracking tab with hashcat/john integration."""
        start_y = 3
        self._draw_section_header(stdscr, start_y, 1, w - 2, "Password Cracking (Hashcat / John the Ripper)", COLOR_HEADER)

        # Status
        y = start_y + 2
        crack_status = f"{CIRCLE_FILLED} CRACKING" if self.cracking_active else f"{CIRCLE_EMPTY} IDLE"
        crack_color = curses.color_pair(COLOR_RUNNING) if self.cracking_active else curses.color_pair(COLOR_NORMAL)
        self._safe_addstr(stdscr, y, 1, f" Status: {crack_status}  Mode: {self.cracking_mode}  Wordlist: {self.wordlist_path}", crack_color)

        # Show target info if set
        if self.crack_target_bssid or self.crack_target_ssid:
            y += 1
            target_line = f" Target: {self.crack_target_ssid or '<hidden>'} ({self.crack_target_bssid})"
            self._safe_addstr(stdscr, y, 1, target_line[:w-2], curses.color_pair(COLOR_WARNING))

        # Progress bar using _draw_progress_bar helper
        y += 1
        if self.cracking_active:
            bar_w = min(50, w - 4)
            eta_str = ""
            if self.cracking_progress > 0:
                # Estimate ETA based on progress rate
                eta_str = " ETA: calculating..."
                if self.cracking_progress > 0.01:
                    # Simple linear ETA
                    eta_str = f" ETA: ~{int((1.0 - self.cracking_progress) / self.cracking_progress * 60)}s"
            self._draw_progress_bar(stdscr, y, 2, bar_w, self.cracking_progress, "Cracking:", COLOR_SUCCESS)
            if eta_str and y + 1 < h - 3:
                self._safe_addstr(stdscr, y, 2 + bar_w + 2, eta_str[:w - bar_w - 6],
                                  curses.color_pair(COLOR_DIM))

        # Menu items
        y += 2
        menu_items = [
            ("Start Hashcat", HashcatIntegration is not None),
            ("Start John", JohnManager is not None),
            ("Stop Cracking", self.cracking_active),
            (f"Mode: {self.cracking_mode}", True),
            ("Select Wordlist", True),
        ]

        for i, (label, available) in enumerate(menu_items):
            row_y = y + i
            if row_y >= h - 3:
                break
            avail = "*" if available else "x"
            line = f" {avail} {label}"
            if i == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            else:
                attr = curses.color_pair(COLOR_NORMAL) if available else curses.color_pair(COLOR_ERROR)
            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

        # Captured handshakes list
        hs_y = y + len(menu_items) + 1
        self._safe_addstr(stdscr, hs_y, 1, " Captured Handshakes:",
                          curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
        handshakes = self._get_handshakes()
        for i, hs in enumerate(handshakes[:h - hs_y - 4]):
            row_y = hs_y + 1 + i
            if row_y >= h - 3:
                break
            ssid = hs.get("ssid", "?")
            bssid = hs.get("bssid", "?")
            hs_type = hs.get("type", "4-way")
            cracked = "[CRACKED]" if hs.get("cracked") else ""
            line = f"   {ssid:<20s} {bssid:<17s} {hs_type:<8s} {cracked}"
            attr = curses.color_pair(COLOR_SUCCESS) if hs.get("cracked") else curses.color_pair(COLOR_NORMAL)
            self._safe_addstr(stdscr, row_y, 1, line[:w-2], attr)

    # ================================================================
    # SETTINGS TAB
    # ================================================================

    def _draw_settings_tab(self, stdscr, h, w):
        """Draw Settings tab with all configuration options."""
        start_y = 3
        title = " Settings & Configuration"
        self._safe_addstr(stdscr, start_y, 1, title, curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        self._safe_hline(stdscr, start_y + 1, 1, curses.ACS_HLINE, w - 2)

        y = start_y + 2
        settings_items = [
            (f"Monitor Interface: {self.monitor_iface}", "iface"),
            (f"AP Interface: {self.ap_iface}", "ap_iface"),
            (f"5GHz Channels: {'ON' if self.use_5ghz else 'OFF'}", "5ghz"),
            (f"RSSI Limit: {self.rssi_limit} dBm", "rssi"),
            (f"Recon Duration: {self.recon_duration}s", "recon_dur"),
            (f"DoS Mode: {self.dos_mode}", "dos_mode"),
            (f"Signal Targeting: {'ON' if self.signal_targeting_enabled else 'OFF'}", "sig_target"),
            (f"Verbose Mode: {'ON' if self.verbose_mode else 'OFF'}", "verbose"),
            ("---", "sep"),
            (f"Chip Detector: {'available' if self.chip_detector else 'N/A'}", "chip"),
            (f"Monitor Manager: {'available' if self.monitor_manager else 'N/A'}", "mon_mgr"),
            (f"Radio Manager: {'available' if self.radio_manager else 'N/A'}", "radio"),
            (f"Plugin Manager: {'available' if self.plugin_manager else 'N/A'}", "plugins"),
            (f"Capability Manager: {'available' if self.capability_manager else 'N/A'}", "caps"),
            (f"Config Loader: {'available' if self.config_loader else 'N/A'}", "config"),
            (f"Session Manager: {'available' if self.session_manager else 'N/A'}", "session"),
            ("---", "sep2"),
            (f"Platform: {sys.platform}", "info"),
            (f"Python: {sys.version.split()[0]}", "info2"),
            (f"Scapy: {'YES' if SCAPY_AVAILABLE else 'NO'}", "info3"),
            (f"pyWhat: {'YES' if PyWhatAnalyzer else 'NO'}", "info4"),
            (f"BLE (bleak): {'YES' if BLEScanner else 'NO'}", "info5"),
            (f"SDR (pyrtlsdr): {'YES' if SDRManager else 'NO'}", "info6"),
            (f"tshark: {'YES' if TsharkDecryptionEngine else 'NO'}", "info7"),
        ]

        max_rows = h - y - 3
        visible = settings_items[self.scroll_offset:self.scroll_offset + max_rows]

        for i, (label, key) in enumerate(visible):
            actual_idx = self.scroll_offset + i
            row_y = y + i
            if row_y >= h - 3:
                break

            if label == "---":
                self._safe_hline(stdscr, row_y, 1, curses.ACS_HLINE, w - 2)
                continue

            if actual_idx == self.menu_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
            elif key.startswith("info"):
                attr = curses.color_pair(COLOR_ACCENT)
            else:
                attr = curses.color_pair(COLOR_NORMAL)

            self._safe_addstr(stdscr, row_y, 1, f" {label}", attr)

    # ================================================================
    # POPUP / CONTEXT MENU
    # ================================================================

    def _draw_popup(self, stdscr, h, w):
        """Draw a context-sensitive popup/submenu with double-line border."""
        popup_w = min(50, w - 4)
        popup_h = min(len(self.popup_items) + 4, h - 4)
        start_y = max(2, (h - popup_h) // 2)
        start_x = max(2, (w - popup_w) // 2)

        # Draw shadow effect (dim characters offset by 1)
        for sy in range(start_y + 1, start_y + popup_h + 1):
            if sy < h:
                self._safe_addstr(stdscr, sy, start_x + popup_w, " ", curses.color_pair(COLOR_NORMAL) | curses.A_DIM)
        if start_y + popup_h < h:
            self._safe_addstr(stdscr, start_y + popup_h, start_x + 1,
                              " " * min(popup_w, w - start_x - 2), curses.color_pair(COLOR_NORMAL) | curses.A_DIM)

        # Draw double-line box
        try:
            win_h, win_w = stdscr.getmaxyx()
            if start_y + popup_h <= win_h and start_x + popup_w <= win_w:
                # Top border (double line)
                self._safe_addstr(stdscr, start_y, start_x,
                                  DOUBLE_BOX_TL + DOUBLE_BOX_H * (popup_w - 2) + DOUBLE_BOX_TR,
                                  curses.color_pair(COLOR_ACCENT))
                # Sides (double line)
                for i in range(1, popup_h - 1):
                    self._safe_addstr(stdscr, start_y + i, start_x, DOUBLE_BOX_V, curses.color_pair(COLOR_ACCENT))
                    # Clear interior
                    self._safe_addstr(stdscr, start_y + i, start_x + 1, " " * (popup_w - 2))
                    self._safe_addstr(stdscr, start_y + i, start_x + popup_w - 1, DOUBLE_BOX_V, curses.color_pair(COLOR_ACCENT))
                # Bottom border (double line)
                self._safe_addstr(stdscr, start_y + popup_h - 1, start_x,
                                  DOUBLE_BOX_BL + DOUBLE_BOX_H * (popup_w - 2) + DOUBLE_BOX_BR,
                                  curses.color_pair(COLOR_ACCENT))
                # Title
                if self.popup_title:
                    self._safe_addstr(stdscr, start_y, start_x + 2, f" {self.popup_title} ",
                                      curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        # Draw items
        for i, item in enumerate(self.popup_items):
            if i >= popup_h - 3:
                break
            iy = start_y + 1 + i
            if i == self.popup_selected:
                attr = curses.color_pair(COLOR_SELECTED) | curses.A_BOLD
                prefix = f"{ARROW_RIGHT} "
            else:
                attr = curses.color_pair(COLOR_NORMAL)
                prefix = "  "
            self._safe_addstr(stdscr, iy, start_x + 2, (prefix + item)[:popup_w - 4], attr)

    def _draw_input(self, stdscr, h, w):
        """Draw input field overlay."""
        input_w = min(60, w - 4)
        start_y = h // 2
        start_x = max(2, (w - input_w) // 2)

        self._draw_box(stdscr, start_y - 1, start_x, 4, input_w, self.input_field)
        self._safe_addstr(stdscr, start_y + 1, start_x + 2,
                          self.input_buffer + "_", curses.color_pair(COLOR_HEADER))

    # ================================================================
    # INPUT HANDLING
    # ================================================================

    def _handle_input(self, key):
        """Process keyboard input."""
        # Input mode handling
        if self.input_mode:
            self._handle_input_mode(key)
            return

        # Confirmation dialog handling
        if self._confirm_active:
            if key == ord('y') or key == ord('Y'):
                self._confirm_active = False
                if self._confirm_callback:
                    self._confirm_callback()
                self._confirm_callback = None
            elif key == ord('n') or key == ord('N') or key == 27:
                self._confirm_active = False
                self._confirm_callback = None
                self.status_message = "Cancelled"
            return

        # Help overlay handling
        if self.show_help:
            if key == ord('?') or key == 27:  # ? or ESC
                self.show_help = False
            return

        # Popup handling
        if self.show_popup:
            self._handle_popup_input(key)
            return

        # Global keys
        if key == ord('q') or key == ord('Q'):
            self.running = False
        elif key == ord('?'):
            self.show_help = True
        elif key == ord('\t'):
            prev_tab = self.active_tab
            self.active_tab = (self.active_tab + 1) % len(TABS)
            self.scroll_offset = 0
            self.menu_selected = 0
            self._on_tab_switch(prev_tab, self.active_tab)
        elif key == curses.KEY_BTAB:
            prev_tab = self.active_tab
            self.active_tab = (self.active_tab - 1) % len(TABS)
            self.scroll_offset = 0
            self.menu_selected = 0
            self._on_tab_switch(prev_tab, self.active_tab)
        elif key >= ord('1') and key <= ord('9'):
            idx = key - ord('1')
            if idx < len(TABS):
                prev_tab = self.active_tab
                self.active_tab = idx
                self.scroll_offset = 0
                self.menu_selected = 0
                self._on_tab_switch(prev_tab, self.active_tab)
        elif key == curses.KEY_UP:
            if TABS[self.active_tab] == "Targets":
                # Direct target navigation
                if self.selected_target_idx > 0:
                    self.selected_target_idx -= 1
                    # Scroll up if needed
                    if self.selected_target_idx < self.scroll_offset:
                        self.scroll_offset = self.selected_target_idx
                self._sync_target_selection()
            else:
                if self.menu_selected > 0:
                    self.menu_selected -= 1
                elif self.scroll_offset > 0:
                    self.scroll_offset -= 1
        elif key == curses.KEY_DOWN:
            if TABS[self.active_tab] == "Targets":
                # Direct target navigation
                max_items = self._get_max_menu_items()
                if self.selected_target_idx < max_items - 1:
                    self.selected_target_idx += 1
                    # Get visible rows (approximate: terminal height - header - footer)
                    try:
                        h, w = self.stdscr.getmaxyx()
                        visible_rows = h - 10
                    except Exception:
                        visible_rows = 20
                    # Scroll down if selection goes below visible area
                    if self.selected_target_idx >= self.scroll_offset + visible_rows:
                        self.scroll_offset = self.selected_target_idx - visible_rows + 1
                self._sync_target_selection()
            else:
                max_items = self._get_max_menu_items()
                if self.menu_selected < max_items - 1:
                    self.menu_selected += 1
                else:
                    self.scroll_offset += 1
        elif key == curses.KEY_PPAGE:
            self.scroll_offset = max(0, self.scroll_offset - 10)
        elif key == curses.KEY_NPAGE:
            self.scroll_offset += 10
        elif key == ord('\n') or key == 10 or key == curses.KEY_ENTER:
            self._handle_action()
        elif key == ord(' '):
            self._handle_toggle()
        elif key == ord('s') or key == ord('S'):
            self._handle_sort()
        elif key == ord('a') or key == ord('A'):
            # In Targets tab during recon: stop recon and attack selected target
            if TABS[self.active_tab] == "Targets" and self.recon_running:
                self._stop_recon_and_attack()
            else:
                self._handle_autopwn()
        elif key == ord('e') or key == ord('E'):
            self._handle_export()
        elif key == ord('r') or key == ord('R'):
            # In Targets tab: start recon. Elsewhere: refresh.
            if TABS[self.active_tab] == "Targets" and not self.recon_running:
                self._start_recon()
            else:
                self._handle_refresh()
        elif key == ord('x') or key == ord('X'):
            # Stop recon without attacking
            if self.recon_running:
                self._stop_recon()
        elif key == ord('f') or key == ord('/'):
            self._start_input("Filter", "filter", self._apply_filter)

    def _handle_input_mode(self, key):
        """Handle key input while in text input mode."""
        if key == 27:  # ESC
            self.input_mode = False
            self.input_buffer = ""
        elif key == ord('\n') or key == 10:
            self.input_mode = False
            if self.input_callback:
                self.input_callback(self.input_buffer)
            self.input_buffer = ""
        elif key == curses.KEY_BACKSPACE or key == 127 or key == 8:
            self.input_buffer = self.input_buffer[:-1]
        elif 32 <= key <= 126:
            self.input_buffer += chr(key)

    def _handle_popup_input(self, key):
        """Handle input when popup is showing."""
        if key == 27 or key == ord('q'):  # ESC or q
            self.show_popup = False
        elif key == curses.KEY_UP:
            if self.popup_selected > 0:
                self.popup_selected -= 1
        elif key == curses.KEY_DOWN:
            if self.popup_selected < len(self.popup_items) - 1:
                self.popup_selected += 1
        elif key == ord('\n') or key == 10:
            self._execute_popup_action()
            self.show_popup = False

    def _start_input(self, label, field, callback):
        """Start text input mode."""
        self.input_mode = True
        self.input_field = label
        self.input_buffer = ""
        self.input_callback = callback

    # ================================================================
    # TARGET SELECTION & AUTO-FILL
    # ================================================================

    def _sync_target_selection(self):
        """Sync selected_target from selected_target_idx.

        Called when UP/DOWN keys are pressed while on the Targets tab so that
        the highlighted row in the AP/client table stays in sync with the
        logical selection index and auto-fill reads the correct target.
        """
        if self.target_view == "ap":
            aps = self._get_access_points()
            if aps and 0 <= self.selected_target_idx < len(aps):
                self.selected_target = aps[self.selected_target_idx]
        else:
            clients = self._get_clients()
            if clients and 0 <= self.selected_client_idx < len(clients):
                self.selected_client = clients[self.selected_client_idx]

    def _on_tab_switch(self, prev_tab_idx: int, new_tab_idx: int):
        """Handle logic when the user switches tabs.

        If leaving the Targets tab with a selected target, auto-fill all
        attack module parameters so the user does not have to manually
        enter BSSID/SSID/channel/IP information on each attack tab.
        """
        prev_tab = TABS[prev_tab_idx]
        if prev_tab == "Targets" and self.selected_target:
            self._autofill_from_target()

    def _autofill_from_target(self):
        """Populate attack parameters across all tabs from the currently selected target.

        Reads self.selected_target (an AP dict) and fills in:
          - WiFi Attacks: target BSSID, SSID, channel are already used via
            _build_engine_kwargs which reads self.selected_target directly.
          - MITM: derives gateway IP from target BSSID (assumes .1 on common
            subnet) and sets mitm_target_ip/mitm_gateway_ip if not already set.
          - Credential Attacks: target info available via self.selected_target.
          - Cracking: target BSSID/SSID stored for hashcat/john reference.

        This method only fills values that are currently empty so it does not
        overwrite user-provided configuration.
        """
        if not self.selected_target:
            return

        target_bssid = self.selected_target.get("bssid", "")
        target_ssid = self.selected_target.get("ssid", "")
        target_channel = self.selected_target.get("channel", "")

        # --- MITM auto-fill ---
        # Derive a plausible gateway IP from the target network.
        # If the target has associated client IPs or gateway info in the DB,
        # use that. Otherwise, use a common default gateway pattern.
        if not self.mitm_gateway_ip and target_bssid:
            gateway = self._derive_gateway_ip(target_bssid)
            if gateway:
                self.mitm_gateway_ip = gateway

        # If we derived a gateway, suggest a target IP range hint
        if not self.mitm_target_ip and self.mitm_gateway_ip:
            # Use the gateway network with .0/24 hint as target
            parts = self.mitm_gateway_ip.rsplit(".", 1)
            if len(parts) == 2:
                self.mitm_target_ip = parts[0] + ".0/24"

        # --- Cracking auto-fill ---
        # Store the target BSSID/SSID so hashcat/john commands reference
        # the correct capture file.
        if not hasattr(self, "crack_target_bssid") or not self.crack_target_bssid:
            self.crack_target_bssid = target_bssid
        if not hasattr(self, "crack_target_ssid") or not self.crack_target_ssid:
            self.crack_target_ssid = target_ssid

        # Update status message to confirm auto-fill
        self.status_message = f"Target set: {target_ssid or '<hidden>'} ({target_bssid}) Ch:{target_channel}"

    def _derive_gateway_ip(self, bssid: str) -> str:
        """Attempt to derive the gateway IP for a target AP.

        Strategy:
          1. Check database for DHCP leases that reference this BSSID's network.
          2. If not found, assume a common 192.168.x.1 pattern.

        Returns empty string if unable to determine.
        """
        # Try to get gateway from database DHCP info
        if self.db:
            try:
                conn = self.db.conn if hasattr(self.db, "conn") else None
                if conn:
                    cursor = conn.execute(
                        "SELECT gateway_ip FROM dhcp_leases WHERE bssid = ? LIMIT 1",
                        (bssid,)
                    )
                    row = cursor.fetchone()
                    if row and row[0]:
                        return row[0]
            except Exception:
                pass

        # Fallback: common gateway assumption
        # Many consumer routers use 192.168.1.1 or 192.168.0.1
        return "192.168.1.1"

    # ================================================================
    # ACTION HANDLERS
    # ================================================================

    def _handle_action(self):
        """Handle enter key press on current selection."""
        tab = TABS[self.active_tab]
        if tab == "Targets":
            self._handle_targets_action()
        elif tab == "WiFi Attacks":
            self._handle_wifi_attack_action()
        elif tab == "Cred Attacks":
            self._handle_cred_attack_action()
        elif tab == "MITM":
            self._handle_mitm_action()
        elif tab == "Network":
            self._handle_network_action()
        elif tab == "BLE/SDR":
            self._handle_ble_sdr_action()
        elif tab == "Harvester":
            self._handle_harvester_action()
        elif tab == "Cracking":
            self._handle_cracking_action()
        elif tab == "Settings":
            self._handle_settings_action()

    def _handle_toggle(self):
        """Handle space key."""
        tab = TABS[self.active_tab]
        if tab == "Targets":
            # Toggle between AP and client view
            self.target_view = "client" if self.target_view == "ap" else "ap"
            self.scroll_offset = 0
            self.menu_selected = 0
        elif tab == "Settings":
            self._toggle_setting()

    def _handle_sort(self):
        """Cycle sort mode (Targets tab)."""
        if TABS[self.active_tab] == "Targets":
            self.sort_mode = (self.sort_mode + 1) % len(SORT_MODES)

    def _handle_autopwn(self):
        """Toggle AutoPwn mode."""
        if self.autopwn_running:
            self._stop_autopwn()
        else:
            self._start_autopwn()

    def _handle_export(self):
        """Export data based on current tab."""
        tab = TABS[self.active_tab]
        try:
            if tab == "Targets":
                self._export_targets()
            elif tab == "Harvester":
                self._export_findings()
            elif tab == "Cracking":
                self._export_handshakes()
            else:
                self._export_targets()
            self.status_message = "Export complete"
            self._log_activity(f"Exported data from {tab} tab", "export")
        except Exception as e:
            self.status_message = f"Export failed: {e}"

    def _handle_refresh(self):
        """Force refresh data."""
        self.last_refresh = 0
        self.status_message = "Refreshed"

    # ================================================================
    # TARGETS TAB ACTIONS
    # ================================================================

    def _handle_targets_action(self):
        """Handle Enter on Targets tab - show context-sensitive attack popup."""
        # Sync target index with current navigation position
        self._sync_target_selection()
        if self.target_view == "ap":
            aps = self._get_access_points()
            if aps and self.selected_target_idx < len(aps):
                self.selected_target = aps[self.selected_target_idx]
                self._save_attack_state()
                self._show_ap_attack_popup()
        else:
            clients = self._get_clients()
            if clients and self.selected_client_idx < len(clients):
                self.selected_client = clients[self.selected_client_idx]
                self._save_attack_state()
                self._show_client_attack_popup()

    def _show_ap_attack_popup(self):
        """Show context-sensitive attack menu for selected AP."""
        if not self.selected_target:
            return
        ssid = self.selected_target.get("ssid", "?")
        security = self.selected_target.get("security", "").upper()

        self.popup_title = f"Attack: {ssid}"
        self.popup_items = [
            "Deauthentication",
            "Handshake Capture",
            "PMKID Capture",
            "Evil Twin / AP Clone",
            "Beacon Flood",
            "DoS Attack",
            "KARMA AP",
        ]

        # Add WPA3-specific if WPA3 detected
        if "WPA3" in security or "SAE" in security:
            self.popup_items.append("WPA3 Downgrade Attack")
            self.popup_items.append("SAE Flood")

        self.popup_items.append("Multi-AP Capture")
        self.popup_items.append("Cancel")

        self.show_popup = True
        self.popup_selected = 0

    def _show_client_attack_popup(self):
        """Show context-sensitive attack menu for selected client."""
        if not self.selected_client:
            return
        mac = self.selected_client.get("mac", "?")

        self.popup_title = f"Client: {mac}"
        self.popup_items = [
            "Deauth from AP",
            "Profile Client",
            "MITM (ARP Poison)",
            "Session Hijack",
            "Client Isolation",
            "Cancel",
        ]
        self.show_popup = True
        self.popup_selected = 0

    def _execute_popup_action(self):
        """Execute the selected popup action."""
        if not self.popup_items:
            return
        action = self.popup_items[self.popup_selected]

        if action == "Cancel":
            return

        # Map popup actions to engine toggles
        action_map = {
            "Deauthentication": ("wifi_attacks", "deauth"),
            "Handshake Capture": ("wifi_attacks", "handshake"),
            "PMKID Capture": ("wifi_attacks", "pmkid"),
            "Evil Twin / AP Clone": ("wifi_attacks", "ap_clone"),
            "Beacon Flood": ("wifi_attacks", "beacons"),
            "DoS Attack": ("wifi_attacks", "dos_cts"),
            "KARMA AP": ("wifi_attacks", "karma"),
            "WPA3 Downgrade Attack": ("wifi_attacks", "wpa3_attack"),
            "SAE Flood": ("wifi_attacks", "wpa3_attack"),
            "Multi-AP Capture": ("wifi_attacks", "multi_cap"),
            "Deauth from AP": ("wifi_attacks", "deauth"),
            "MITM (ARP Poison)": ("mitm_attacks", "arp"),
            "Session Hijack": ("cred_attacks", "session"),
            "Client Isolation": ("wifi_attacks", "client_iso"),
        }

        if action in action_map:
            group, key = action_map[action]
            engines = getattr(self, group, {})
            if key in engines:
                engine = engines[key]
                if not engine.is_running:
                    kwargs = self._build_engine_kwargs(key, group.replace("_attacks", "").replace("_modules", ""))
                    engine.toggle(**kwargs)
                    self.status_message = f"Started: {engine.name}"
                else:
                    self.status_message = f"Already running: {engine.name}"
        elif action == "Profile Client":
            if self.client_profiler and self.selected_client:
                mac = self.selected_client.get("mac", "")
                profile = self.client_profiler.get_profile(mac)
                if profile:
                    self.status_message = f"Profile: {profile.get('device_type', 'unknown')}"

    # ================================================================
    # ENGINE KWARGS BUILDER
    # ================================================================

    def _build_engine_kwargs(self, key: str, category: str) -> Dict[str, Any]:
        """Build constructor kwargs for an engine based on its type and selected target.

        Returns a dict of kwargs to pass to engine.toggle() / engine.start().
        Each engine requires different arguments (interface, target, db, etc.).
        """
        kwargs: Dict[str, Any] = {}

        # Common: interface
        iface = self.monitor_iface

        # If load balancer is available and initialized, acquire pool interfaces
        if self.load_balancer is not None:
            try:
                loop = asyncio.new_event_loop()
                pool = loop.run_until_complete(
                    self.load_balancer.acquire_pool(
                        task=self._get_task_type_for_category(category),
                        strategy="least_loaded",
                    )
                )
                loop.close()
                kwargs["interfaces"] = [iface.name for iface in pool] if pool else []
                # Store pool reference for release when engine stops
                if pool:
                    self._active_pools[key] = pool
            except Exception:
                kwargs["interfaces"] = []

        # Get target info
        target_bssid = ""
        target_client = ""
        target_ssid = ""
        if self.selected_target:
            target_bssid = self.selected_target.get("bssid", "")
            target_ssid = self.selected_target.get("ssid", "")
        if self.selected_client:
            target_client = self.selected_client.get("mac", "")

        if category == "wifi":
            # WiFi attack engines
            if key == "deauth":
                kwargs = {"interface": iface}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "beacons":
                kwargs = {"interface": iface}
            elif key == "karma":
                kwargs = {"interface": iface}
            elif key == "rogueap":
                kwargs = {"interface": iface}
            elif key == "ap_clone":
                kwargs = {"interface": iface, "db": self.db}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "krack":
                kwargs = {"interface": iface}
                if target_client:
                    kwargs["target_client"] = target_client
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key in ("dos_cts", "dos_beacon", "dos_qos", "dos_frag"):
                mode_map = {
                    "dos_cts": "cts_flood",
                    "dos_beacon": "beacon_exhaust",
                    "dos_qos": "qos_null",
                    "dos_frag": "fragment",
                }
                kwargs = {"interface": iface, "mode": mode_map.get(key, "cts_flood")}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "client_iso":
                kwargs = {"interface": iface}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "net_disrupt":
                kwargs = {"interface": iface}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key in ("wpa3_attack", "wpa3_detect"):
                kwargs = {"interface": iface}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "handshake":
                kwargs = {"interface": iface}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "pmkid":
                kwargs = {"interface": iface}
                if target_bssid:
                    kwargs["target_bssid"] = target_bssid
            elif key == "multi_cap":
                kwargs = {"interface": iface}
            else:
                kwargs = {"interface": iface}

        elif category == "cred":
            # Credential engines generally need interface
            kwargs = {"interface": iface}

        elif category == "mitm":
            # MITM engines need interface and target/gateway
            kwargs = {"interface": iface}
            if key == "arp":
                if self.mitm_target_ip:
                    kwargs["target_ip"] = self.mitm_target_ip
                if self.mitm_gateway_ip:
                    kwargs["gateway_ip"] = self.mitm_gateway_ip
            elif key == "dns_spoof":
                if self.dns_spoof_domain:
                    kwargs["domain"] = self.dns_spoof_domain

        elif category == "network":
            kwargs = {"interface": iface}

        elif category == "ble_sdr":
            kwargs = {"interface": iface}

        else:
            kwargs = {"interface": iface}

        return kwargs

    def _get_task_type_for_category(self, category: str):
        """Map a category string to a TaskType enum for load balancer pool acquisition."""
        try:
            from .radio_manager import TaskType
            category_map = {
                "wifi": TaskType.ATTACK,
                "cred": TaskType.ATTACK,
                "mitm": TaskType.ATTACK,
                "network": TaskType.SCAN,
                "ble_sdr": TaskType.SCAN,
                "intel": TaskType.SCAN,
            }
            return category_map.get(category, TaskType.SCAN)
        except (ImportError, AttributeError):
            # Fallback if TaskType is not available
            return None

    def _release_engine_pool(self, key: str) -> None:
        """Release adapter pool acquired for an engine back to the load balancer.

        Called when an engine is stopped to free up workload slots so
        the least_loaded strategy remains accurate.

        Args:
            key: The engine key used when the pool was acquired.
        """
        pool = self._active_pools.pop(key, None)
        if pool and self.load_balancer is not None:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self.load_balancer.release_pool(pool))
                loop.close()
            except Exception:
                pass

    # ================================================================
    # WIFI ATTACK ACTIONS
    # ================================================================

    def _handle_wifi_attack_action(self):
        """Toggle selected WiFi attack engine with proper constructor args."""
        items = list(self.wifi_attacks.items())
        idx = self.menu_selected
        if 0 <= idx < len(items):
            key, engine = items[idx]
            kwargs = self._build_engine_kwargs(key, "wifi")
            engine.toggle(**kwargs)
            if engine.is_running:
                self.status_message = f"Started: {engine.name}"
                self._log_activity(f"Started {engine.name}", "engine")
                self._add_notification(f"Engine started: {engine.name}", "info")
            else:
                self._release_engine_pool(key)
                self.status_message = f"Stopped: {engine.name}"
                self._log_activity(f"Stopped {engine.name}", "engine")
            self._save_attack_state()

    # ================================================================
    # CREDENTIAL ATTACK ACTIONS
    # ================================================================

    def _handle_cred_attack_action(self):
        """Toggle selected credential attack engine with proper constructor args."""
        items = list(self.cred_attacks.items())
        idx = self.menu_selected
        if 0 <= idx < len(items):
            key, engine = items[idx]
            kwargs = self._build_engine_kwargs(key, "cred")
            engine.toggle(**kwargs)
            if engine.is_running:
                self.status_message = f"Started: {engine.name}"
                self._log_activity(f"Started {engine.name}", "engine")
                self._add_notification(f"Engine started: {engine.name}", "info")
            else:
                self._release_engine_pool(key)
                self.status_message = f"Stopped: {engine.name}"
                self._log_activity(f"Stopped {engine.name}", "engine")
            self._save_attack_state()

    # ================================================================
    # MITM ACTIONS
    # ================================================================

    def _handle_mitm_action(self):
        """Handle MITM tab actions."""
        items = list(self.mitm_attacks.items())
        idx = self.menu_selected
        if 0 <= idx < len(items):
            key, engine = items[idx]
            kwargs = self._build_engine_kwargs(key, "mitm")
            engine.toggle(**kwargs)
            if engine.is_running:
                self.status_message = f"Started: {engine.name}"
                self._log_activity(f"Started {engine.name}", "engine")
                self._add_notification(f"Engine started: {engine.name}", "info")
            else:
                self._release_engine_pool(key)
                self.status_message = f"Stopped: {engine.name}"
                self._log_activity(f"Stopped {engine.name}", "engine")
            self._save_attack_state()

    # ================================================================
    # NETWORK ACTIONS
    # ================================================================

    def _handle_network_action(self):
        """Toggle selected network module."""
        items = list(self.network_modules.items())
        idx = self.menu_selected
        if 0 <= idx < len(items):
            key, engine = items[idx]
            kwargs = self._build_engine_kwargs(key, "network")
            engine.toggle(**kwargs)
            if engine.is_running:
                self.status_message = f"Started: {engine.name}"
            else:
                self._release_engine_pool(key)
                self.status_message = f"Stopped: {engine.name}"

    # ================================================================
    # BLE/SDR ACTIONS
    # ================================================================

    def _handle_ble_sdr_action(self):
        """Toggle selected BLE/SDR module."""
        items = list(self.ble_sdr_modules.items())
        idx = self.menu_selected
        if 0 <= idx < len(items):
            key, engine = items[idx]
            kwargs = self._build_engine_kwargs(key, "ble_sdr")
            engine.toggle(**kwargs)
            if engine.is_running:
                self.status_message = f"Started: {engine.name}"
            else:
                self._release_engine_pool(key)
                self.status_message = f"Stopped: {engine.name}"

    # ================================================================
    # HARVESTER ACTIONS
    # ================================================================

    def _handle_harvester_action(self):
        """Start/stop the harvester session."""
        if self.harvester_running:
            self._stop_harvester()
        else:
            self._start_harvester()

    def _start_harvester(self):
        """Start live decryption session with pyWhat callback."""
        if LiveDecryptionSession is None:
            self.status_message = "tshark not available"
            return

        try:
            # Create pyWhat callback if available
            if PyWhatCallback is not None and self.pywhat_analyzer is not None:
                self.pywhat_callback = PyWhatCallback(
                    analyzer=self.pywhat_analyzer
                )
                self.harvester_session = LiveDecryptionSession(
                    callback=self.pywhat_callback
                )
            else:
                self.harvester_session = LiveDecryptionSession()

            # Build start args
            kwargs = {}
            if self.harvester_psk and self.harvester_ssid:
                kwargs["psk"] = self.harvester_psk
                kwargs["ssid"] = self.harvester_ssid
            if self.harvester_wep_key:
                kwargs["wep_keys"] = [self.harvester_wep_key]
            kwargs["interface"] = self.monitor_iface

            self.harvester_session.start(**kwargs)
            self.harvester_running = True
            self.status_message = "Harvester started"
        except Exception as e:
            self.status_message = f"Harvester error: {e}"
            self.harvester_running = False

    def _stop_harvester(self):
        """Stop live decryption session."""
        if self.harvester_session:
            try:
                self.harvester_session.stop()
            except Exception:
                pass
        self.harvester_running = False
        self.status_message = "Harvester stopped"

    # ================================================================
    # CRACKING ACTIONS
    # ================================================================

    def _handle_cracking_action(self):
        """Handle cracking tab actions."""
        if self.menu_selected == 0:
            # Start Hashcat
            self._start_hashcat()
        elif self.menu_selected == 1:
            # Start John
            self._start_john()
        elif self.menu_selected == 2:
            # Stop cracking
            self._stop_cracking()
        elif self.menu_selected == 3:
            # Cycle mode
            modes = ["dictionary", "brute-force", "rules"]
            idx = modes.index(self.cracking_mode) if self.cracking_mode in modes else 0
            self.cracking_mode = modes[(idx + 1) % len(modes)]
        elif self.menu_selected == 4:
            # Wordlist input
            self._start_input("Wordlist Path", "wordlist", self._set_wordlist)

    def _start_hashcat(self):
        """Start hashcat cracking."""
        if HashcatIntegration is None:
            self.status_message = "Hashcat module not available"
            return
        try:
            self.hashcat_engine = HashcatIntegration()
            self.cracking_active = True
            self.status_message = "Hashcat started"
        except Exception as e:
            self.status_message = f"Hashcat error: {e}"

    def _start_john(self):
        """Start John the Ripper cracking."""
        if JohnManager is None:
            self.status_message = "John module not available"
            return
        try:
            self.john_engine = JohnManager()
            self.cracking_active = True
            self.status_message = "John started"
        except Exception as e:
            self.status_message = f"John error: {e}"

    def _stop_cracking(self):
        """Stop active cracking job."""
        self.cracking_active = False
        self.cracking_progress = 0.0
        if self.hashcat_engine:
            try:
                self.hashcat_engine.stop()
            except Exception:
                pass
            self.hashcat_engine = None
        if self.john_engine:
            try:
                self.john_engine.stop()
            except Exception:
                pass
            self.john_engine = None
        self.status_message = "Cracking stopped"

    def _set_wordlist(self, path):
        """Set wordlist path from input."""
        if path:
            self.wordlist_path = path
            self.status_message = f"Wordlist: {path}"

    # ================================================================
    # SETTINGS ACTIONS
    # ================================================================

    def _handle_settings_action(self):
        """Handle settings tab Enter actions."""
        if self.menu_selected == 0:
            self._start_input("Monitor Interface", "iface", self._set_monitor_iface)
        elif self.menu_selected == 1:
            self._start_input("AP Interface", "ap_iface", self._set_ap_iface)
        elif self.menu_selected == 3:
            self._start_input("RSSI Limit (dBm)", "rssi", self._set_rssi_limit)
        elif self.menu_selected == 4:
            self._start_input("Recon Duration (seconds)", "recon_dur", self._set_recon_duration)

    def _toggle_setting(self):
        """Toggle boolean settings."""
        if self.menu_selected == 2:
            self.use_5ghz = not self.use_5ghz
            self.channels = (CHANNELS_24GHZ + CHANNELS_5GHZ) if self.use_5ghz else CHANNELS_24GHZ
        elif self.menu_selected == 6:
            self.signal_targeting_enabled = not self.signal_targeting_enabled
        elif self.menu_selected == 7:
            self.verbose_mode = not self.verbose_mode
        self._save_attack_state()

    def _set_monitor_iface(self, value):
        """Set monitor interface."""
        if value:
            self.monitor_iface = value
            self._save_attack_state()

    def _set_ap_iface(self, value):
        """Set AP interface."""
        if value:
            self.ap_iface = value
            self._save_attack_state()

    def _set_rssi_limit(self, value):
        """Set RSSI limit."""
        try:
            self.rssi_limit = int(value)
            self._save_attack_state()
        except ValueError:
            pass

    def _set_recon_duration(self, value):
        """Set recon duration."""
        try:
            self.recon_duration = int(value)
            self._save_attack_state()
        except ValueError:
            pass

    # ================================================================
    # AUTOPWN
    # ================================================================

    def _start_autopwn(self):
        """Start AutoPwn autonomous mode."""
        if AutoPwnEngine is None:
            self.status_message = "AutoPwn module not available"
            return

        try:
            config = AutoPwnConfig() if AutoPwnConfig else None
            self.autopwn_engine = AutoPwnEngine(config=config)
            self.autopwn_running = True
            self.autopwn_state = "SCANNING"
            self._autopwn_loop = None

            # Run async engine in background thread
            def _run_autopwn():
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    self._autopwn_loop = loop
                    loop.run_until_complete(self.autopwn_engine.start())
                except Exception as e:
                    with self._state_lock:
                        self.autopwn_state = "FAILED"
                        self.status_message = f"AutoPwn error: {e}"
                finally:
                    with self._state_lock:
                        self.autopwn_running = False
                    try:
                        loop.close()
                    except Exception:
                        pass

            t = threading.Thread(target=_run_autopwn, daemon=True)
            t.start()
            self.status_message = "AutoPwn started"
            self._log_activity("AutoPwn mode activated", "engine")
            self._add_notification("AutoPwn mode engaged", "warning")
        except Exception as e:
            self.status_message = f"AutoPwn error: {e}"
            self.autopwn_running = False

    def _stop_autopwn(self):
        """Stop AutoPwn mode."""
        if self.autopwn_engine:
            try:
                loop = getattr(self, '_autopwn_loop', None)
                if loop and loop.is_running():
                    # Schedule stop on the engine's own event loop
                    loop.call_soon_threadsafe(
                        lambda: asyncio.ensure_future(self.autopwn_engine.stop())
                    )
                else:
                    # Fallback: create new loop only if background loop is gone
                    fallback_loop = asyncio.new_event_loop()
                    try:
                        fallback_loop.run_until_complete(self.autopwn_engine.stop())
                    finally:
                        fallback_loop.close()
            except Exception:
                pass
        self.autopwn_running = False
        self.autopwn_state = "IDLE"
        self._autopwn_loop = None
        self.status_message = "AutoPwn stopped"
        self._log_activity("AutoPwn mode deactivated", "engine")
        self._add_notification("AutoPwn stopped", "info")

    # ================================================================
    # DATA ACCESS METHODS
    # ================================================================

    def _get_access_points(self) -> List[Dict]:
        """Get access points from database sorted by current sort mode."""
        try:
            # Query ALL access points directly, computing is_pos from the two real columns
            aps = []
            try:
                cursor = self.db.conn.execute(
                    "SELECT bssid, ssid, channel, vendor, security, rssi, "
                    "(is_pos_vendor OR is_pos_ssid) as is_pos "
                    "FROM access_points ORDER BY rssi DESC LIMIT 100"
                )
                aps = cursor.fetchall()
            except Exception:
                # Fallback to get_pos_access_points if direct SQL fails
                if hasattr(self.db, 'get_pos_access_points'):
                    aps = self.db.get_pos_access_points() or []

            # Also get client counts via get_all_ap_clients()
            client_map = {}
            if hasattr(self.db, 'get_all_ap_clients'):
                try:
                    client_map = self.db.get_all_ap_clients() or {}
                except Exception:
                    pass

            if not aps:
                return []

            # Normalize to list of dicts
            ap_list = []
            for ap in aps:
                if isinstance(ap, dict):
                    ap_list.append(ap)
                elif isinstance(ap, (list, tuple)):
                    bssid = ap[0] if len(ap) > 0 else ""
                    ap_dict = {
                        "bssid": bssid,
                        "ssid": ap[1] if len(ap) > 1 else "",
                        "channel": ap[2] if len(ap) > 2 else 0,
                        "vendor": ap[3] if len(ap) > 3 else "",
                        "security": ap[4] if len(ap) > 4 else "",
                        "rssi": ap[5] if len(ap) > 5 else -100,
                        "is_pos": ap[6] if len(ap) > 6 else False,
                        "client_count": len(client_map.get(bssid, [])),
                    }
                    ap_list.append(ap_dict)
                elif hasattr(ap, '__dict__'):
                    ap_list.append(vars(ap))

            # Apply sorting
            sort_key = SORT_MODES[self.sort_mode]
            if sort_key == "rssi":
                ap_list.sort(key=lambda x: x.get("rssi", -100), reverse=True)
            elif sort_key == "security":
                ap_list.sort(key=lambda x: x.get("security", ""), reverse=False)
            elif sort_key == "pos":
                ap_list.sort(key=lambda x: x.get("is_pos", False), reverse=True)
            elif sort_key == "channel":
                ap_list.sort(key=lambda x: x.get("channel", 0))
            elif sort_key == "clients":
                ap_list.sort(key=lambda x: x.get("client_count", 0), reverse=True)
            elif sort_key == "ssid":
                ap_list.sort(key=lambda x: x.get("ssid", "").lower())

            # Apply filter
            if self.filter_text:
                ft = self.filter_text.lower()
                ap_list = [ap for ap in ap_list if
                           ft in ap.get("ssid", "").lower() or
                           ft in ap.get("bssid", "").lower() or
                           ft in ap.get("vendor", "").lower()]

            return ap_list
        except Exception:
            return []

    def _get_clients(self) -> List[Dict]:
        """Get clients with profile data."""
        try:
            # Use get_all_ap_clients() which returns {bssid: [client_macs]}
            # and get_clients_for_bssid(bssid) which returns [(mac, rssi), ...]
            client_list = []

            if hasattr(self.db, 'get_all_ap_clients'):
                ap_clients = self.db.get_all_ap_clients() or {}
                for bssid, macs in ap_clients.items():
                    if isinstance(macs, list):
                        for mac_entry in macs:
                            if isinstance(mac_entry, (list, tuple)):
                                mac = mac_entry[0] if len(mac_entry) > 0 else ""
                                rssi = mac_entry[1] if len(mac_entry) > 1 else -100
                            else:
                                mac = str(mac_entry)
                                rssi = -100
                            client_list.append({
                                "mac": mac,
                                "vendor": "",
                                "associated_ap": bssid,
                                "rssi": rssi,
                            })

            if not client_list:
                return []

            # Enrich with profiler data
            if self.client_profiler:
                for client in client_list:
                    mac = client.get("mac", "")
                    if mac:
                        try:
                            profile = self.client_profiler.get_profile(mac)
                            if profile:
                                client["os"] = profile.get("os", "")
                                client["device_type"] = profile.get("device_type", "")
                                client["vendor"] = profile.get("vendor", client["vendor"])
                        except Exception:
                            pass

            # Apply filter
            if self.filter_text:
                ft = self.filter_text.lower()
                client_list = [c for c in client_list if
                               ft in c.get("mac", "").lower() or
                               ft in c.get("vendor", "").lower() or
                               ft in c.get("associated_ap", "").lower()]

            return client_list
        except Exception:
            return []

    def _get_credentials_count(self) -> int:
        """Get total credentials discovered."""
        try:
            # Use direct SQL since POSDatabase has no get_credentials() method
            cursor = self.db.conn.execute(
                "SELECT COUNT(*) FROM credentials"
            )
            row = cursor.fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def _get_decryption_feed(self) -> List[Dict]:
        """Get live decrypted traffic from harvester session."""
        feed = []
        if self.harvester_session and self.harvester_running:
            try:
                summary = self.harvester_session.get_decrypted_summary()
                # DNS queries
                for dns in summary.get("dns_queries", []):
                    feed.append({
                        "time": dns.get("timestamp", "")[:8] if isinstance(dns, dict) else "",
                        "proto": "DNS",
                        "data": dns.get("query", str(dns)) if isinstance(dns, dict) else str(dns),
                    })
                # HTTP requests
                for http in summary.get("http_requests", []):
                    feed.append({
                        "time": http.get("timestamp", "")[:8] if isinstance(http, dict) else "",
                        "proto": "HTTP",
                        "data": http.get("url", http.get("host", str(http))) if isinstance(http, dict) else str(http),
                    })
                # DHCP leases
                for dhcp in summary.get("dhcp_leases", []):
                    feed.append({
                        "time": dhcp.get("timestamp", "")[:8] if isinstance(dhcp, dict) else "",
                        "proto": "DHCP",
                        "data": dhcp.get("ip", str(dhcp)) if isinstance(dhcp, dict) else str(dhcp),
                    })
                # EAPOL events
                for eapol in summary.get("eapol_events", []):
                    feed.append({
                        "time": eapol.get("timestamp", "")[:8] if isinstance(eapol, dict) else "",
                        "proto": "EAPOL",
                        "data": eapol.get("type", str(eapol)) if isinstance(eapol, dict) else str(eapol),
                    })
                # Credentials
                for cred in summary.get("credentials", []):
                    feed.append({
                        "time": cred.get("timestamp", "")[:8] if isinstance(cred, dict) else "",
                        "proto": "CRED",
                        "data": cred.get("username", str(cred)) if isinstance(cred, dict) else str(cred),
                    })
            except Exception:
                pass
        return feed

    def _get_harvester_findings(self) -> List[Dict]:
        """Get pyWhat findings from the analyzer."""
        if self.pywhat_analyzer:
            try:
                findings = self.pywhat_analyzer.findings
                if findings:
                    return findings
            except Exception:
                pass

        # Also check pywhat_callback
        if self.pywhat_callback:
            try:
                findings = self.pywhat_callback.analyzer.findings
                if findings:
                    return findings
            except Exception:
                pass

        return self.harvester_findings

    def _get_attack_surfaces(self) -> Dict[str, List]:
        """Get attack surfaces grouped by category from PyWhatAnalyzer."""
        if self.pywhat_analyzer:
            try:
                return self.pywhat_analyzer.get_attack_surfaces()
            except Exception:
                pass
        return {}

    def _get_handshakes(self) -> List[Dict]:
        """Get captured handshakes for cracking."""
        handshakes = []
        try:
            if hasattr(self.db, 'get_handshakes'):
                hs = self.db.get_handshakes()
                if hs:
                    for h in hs:
                        if isinstance(h, dict):
                            handshakes.append(h)
                        elif hasattr(h, '__dict__'):
                            handshakes.append(vars(h))
        except Exception:
            pass
        return handshakes or self.captured_handshakes

    def _get_sessions(self) -> List[Dict]:
        """Get session hijacker data."""
        sessions = []
        engine = self.cred_attacks.get("session")
        if engine and engine.engine:
            try:
                if hasattr(engine.engine, 'get_sessions'):
                    sessions = engine.engine.get_sessions()
            except Exception:
                pass
        return sessions

    # ================================================================
    # UTILITY / MAX ITEMS
    # ================================================================

    def _get_max_menu_items(self) -> int:
        """Get the maximum number of selectable items for the current tab."""
        tab = TABS[self.active_tab]
        if tab == "Targets":
            if self.target_view == "ap":
                return max(1, len(self._get_access_points()))
            else:
                return max(1, len(self._get_clients()))
        elif tab == "WiFi Attacks":
            return len(self.wifi_attacks)
        elif tab == "Cred Attacks":
            return len(self.cred_attacks)
        elif tab == "MITM":
            return len(self.mitm_attacks)
        elif tab == "Network":
            return len(self.network_modules)
        elif tab == "BLE/SDR":
            return len(self.ble_sdr_modules)
        elif tab == "Harvester":
            return 3
        elif tab == "Cracking":
            return 5
        elif tab == "Settings":
            return 24
        return 1

    def _apply_filter(self, text):
        """Apply text filter."""
        self.filter_text = text
        self.status_message = f"Filter: {text}" if text else "Filter cleared"

    # ================================================================
    # EXPORT METHODS
    # ================================================================

    def _export_targets(self):
        """Export discovered targets to JSON."""
        data = {
            "access_points": self._get_access_points(),
            "clients": self._get_clients(),
            "timestamp": datetime.now().isoformat(),
        }
        filepath = f"posframework_targets_{int(time.time())}.json"
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self.status_message = f"Exported to {filepath}"

    def _export_findings(self):
        """Export harvester findings to JSON."""
        data = {
            "findings": self._get_harvester_findings(),
            "attack_surfaces": self._get_attack_surfaces(),
            "decryption_feed": self._get_decryption_feed(),
            "timestamp": datetime.now().isoformat(),
        }
        filepath = f"posframework_findings_{int(time.time())}.json"
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self.status_message = f"Exported to {filepath}"

    def _export_handshakes(self):
        """Export handshakes to JSON."""
        data = {
            "handshakes": self._get_handshakes(),
            "timestamp": datetime.now().isoformat(),
        }
        filepath = f"posframework_handshakes_{int(time.time())}.json"
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self.status_message = f"Exported to {filepath}"

    # ================================================================
    # RECON CONTROL
    # ================================================================

    def _start_recon(self):
        """Start the recon engine with live intel enrichment."""
        if ReconEngine is None:
            self.status_message = "Recon not available (scapy missing)"
            return
        try:
            # Create intel enricher for background tool integration
            intel_enricher = None
            try:
                from .intel_enricher import IntelEnricher
                intel_enricher = IntelEnricher(
                    interface=self.monitor_iface, db=self.db
                )
            except (ImportError, Exception):
                pass

            if self.recon_engine is None:
                self.recon_engine = ReconEngine(
                    db=self.db,
                    interface=self.monitor_iface,
                    channels=self.channels,
                    intel_enricher=intel_enricher,
                )
            # Start recon in background thread
            recon_thread = threading.Thread(
                target=self.recon_engine.start, daemon=True, name="GUI-Recon"
            )
            recon_thread.start()
            self.recon_running = True
            self.status_message = "Recon started (press 'a' in Targets to attack)"
            self._log_activity("Recon engine started", "recon")
            self._add_notification("Reconnaissance started", "info")
        except Exception as e:
            self.status_message = f"Recon error: {e}"

    def _stop_recon(self):
        """Stop the recon engine."""
        if self.recon_engine and self.recon_running:
            try:
                self.recon_engine.stop()
            except Exception:
                pass
            self.recon_running = False
            self.status_message = "Recon stopped"
            self._log_activity("Recon engine stopped", "recon")

    def _stop_recon_and_attack(self):
        """Stop recon and immediately transition to attacking the selected target."""
        # Stop the recon engine
        self._stop_recon()

        # Get selected target
        target = self.selected_target
        if not target:
            aps = self._get_access_points()
            if aps:
                target = aps[0]  # Use strongest/first AP if none selected

        if not target:
            self.status_message = "No targets discovered yet"
            return

        bssid = target.get("bssid")
        ssid = target.get("ssid", "")
        channel = target.get("channel")

        self.status_message = f"Attacking: {ssid} ({bssid})"
        log.info(f"Stop-and-attack: targeting {ssid} ({bssid}) ch {channel}")

        # Launch attack via the orchestrator in a background thread
        try:
            from .orchestrator import AttackOrchestrator
            orchestrator = AttackOrchestrator(
                monitor_iface=self.monitor_iface,
                ap_iface=self.ap_iface,
                db=self.db,
                channels=self.channels,
                target_bssid=bssid,
                target_ssid=ssid,
                target_channel=channel,
                recon_duration=0,  # Skip recon - we already have data
            )

            def _run_attack():
                try:
                    orchestrator.start()
                except Exception as e:
                    log.error(f"Attack error: {e}")

            attack_thread = threading.Thread(
                target=_run_attack, daemon=True, name="StopAndAttack"
            )
            attack_thread.start()
            self.status_message = f"Attack launched against {ssid}"
        except Exception as e:
            self.status_message = f"Attack failed: {e}"

    # ================================================================
    # CLEANUP
    # ================================================================

    def _cleanup(self):
        """Stop all running engines on exit."""
        # Stop recon
        if self.recon_engine and self.recon_running:
            try:
                self.recon_engine.stop()
            except Exception:
                pass

        # Stop autopwn
        if self.autopwn_running:
            self._stop_autopwn()

        # Stop harvester
        if self.harvester_running:
            self._stop_harvester()

        # Stop all engine groups
        for group in [self.wifi_attacks, self.cred_attacks, self.mitm_attacks,
                      self.network_modules, self.ble_sdr_modules]:
            for key, engine in group.items():
                if engine.is_running:
                    try:
                        engine.stop()
                    except Exception:
                        pass

        # Stop cracking
        if self.cracking_active:
            self._stop_cracking()

        # Close database
        try:
            self.db.close()
        except Exception:
            pass


# ================================================================
# MODULE-LEVEL main() FUNCTION
# ================================================================

def main():
    """Entry point for the POSFramework Terminal UI."""
    ui = TerminalUI()
    ui.run()


if __name__ == "__main__":
    main()
