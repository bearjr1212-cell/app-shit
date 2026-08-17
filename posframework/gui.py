"""
POSFramework Tkinter GUI
─────────────────────────
Full-featured graphical interface for POSFramework with:
  - Dark professional theme
  - Tab-based navigation (Recon, Attack, MITM, Credentials, Printers, Settings)
  - Real-time Treeview tables
  - Start/Stop controls for all engines
  - Log panel with color-coded output
  - Status bar with live statistics
  - Threaded engine operations for responsive UI
  - Queue-based thread-safe communication
"""

import os
import re
import sys
import time
import json
import logging
import threading
import queue
import ipaddress
from datetime import datetime, timedelta

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False

from .config import (
    DB_NAME, CHANNELS_24GHZ, CHANNELS_5GHZ, IS_WINDOWS, IS_LINUX,
    DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE, log,
)
from .database import POSDatabase

# Attempt to import scapy-dependent engines
SCAPY_AVAILABLE = True
try:
    from .recon import ReconEngine
    from .orchestrator import AttackOrchestrator
    from .deauth import DeauthEngine
    from .beacons import KnownBeaconsEngine
    from .rogueap import RogueAPEngine
    from .karma import KARMAEngine
    from .mitm import MITMEngine
    from .ssl_strip import SSLStripper
    from .dns_spoof import DNSSpoofEngine
    from .cred_harvester import CredentialHarvester
    from .handshake import HandshakeCapture
    from .signal_targeting import SignalTargeting
    from .network_disruption import NetworkDisruption
    from .post_attack import PostAttackAnalyzer
    from .ap_clone import APCloneEngine
    from .krack import KRACKEngine
    from .dos_wifi import WiFiDoSEngine
    from .client_isolation import ClientIsolationEngine
    from .printer_recon import PrinterRecon
    from .ipp_scanner import IPPScanner
    from .print_interceptor import PrintJobInterceptor
    from .printer_creds import PrinterCredentialHarvester
except ImportError as e:
    SCAPY_AVAILABLE = False
    _SCAPY_IMPORT_ERROR = str(e)


# ─── Validation Helpers ──────────────────────────────────────────────────────

_MAC_RE = re.compile(
    r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$"
)


def _is_valid_mac(value):
    """Return True if *value* is a well-formed MAC address."""
    return bool(_MAC_RE.match(value))


def _is_valid_ip(value):
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ─── Color Theme ─────────────────────────────────────────────────────────────

COLORS = {
    "bg_dark": "#1e1e1e",
    "bg_medium": "#2d2d2d",
    "bg_light": "#3c3c3c",
    "fg_primary": "#e0e0e0",
    "fg_secondary": "#a0a0a0",
    "accent_blue": "#4fc3f7",
    "accent_green": "#66bb6a",
    "accent_red": "#ef5350",
    "accent_yellow": "#fdd835",
    "accent_cyan": "#26c6da",
    "accent_orange": "#ffa726",
    "accent_purple": "#ab47bc",
    "border": "#555555",
    "treeview_bg": "#252525",
    "treeview_fg": "#e0e0e0",
    "treeview_selected": "#1565c0",
    "button_bg": "#37474f",
    "button_fg": "#ffffff",
    "entry_bg": "#333333",
    "entry_fg": "#e0e0e0",
}


# ─── Custom Logging Handler ──────────────────────────────────────────────────

class TextWidgetHandler(logging.Handler):
    """Routes log records to a Tkinter Text widget via a thread-safe queue."""

    def __init__(self, text_queue):
        super().__init__()
        self.text_queue = text_queue

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            self.text_queue.put((msg, level))
        except Exception:
            self.handleError(record)


# ─── Main GUI Application ────────────────────────────────────────────────────

class POSFrameworkGUI:
    """Main application window for POSFramework GUI."""

    VERSION = "2.1.0"
    TITLE = "POSFramework v2.1.0 - WiFi Reconnaissance & Attack Suite"
    REFRESH_INTERVAL_MS = 2000
    STATUS_UPDATE_MS = 1000
    LOG_MAX_LINES = 10000

    def __init__(self, root):
        self.root = root
        self.root.title(self.TITLE)
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)
        self.root.configure(bg=COLORS["bg_dark"])

        # State variables
        self.start_time = datetime.now()
        self.db = None
        self.db_path = DB_NAME
        self.monitor_iface = DEFAULT_MONITOR_IFACE
        self.ap_iface = DEFAULT_AP_IFACE
        self.refresh_interval = self.REFRESH_INTERVAL_MS
        self.log_queue = queue.Queue()
        self.message_queue = queue.Queue()

        # Threading lock for engine state transitions
        self._state_lock = threading.Lock()

        # Engine references
        self.recon_engine = None
        self.orchestrator = None
        self.mitm_engine = None
        self.ssl_stripper = None
        self.dns_spoofer = None
        self.cred_harvester = None
        self.printer_recon = None
        self.ipp_scanner = None
        self.print_interceptor = None
        self.printer_cred_harvester = None

        # Running state flags
        self.recon_running = False
        self.attack_running = False
        self.mitm_running = False
        self.printer_recon_running = False

        # Active modules counter
        self.active_modules_count = 0

        # After IDs for cancellable timers
        self._refresh_after_id = None

        # Initialize database
        self._init_database()

        # Apply dark theme
        self._apply_dark_theme()

        # Build UI
        self._build_menu()
        self._build_main_layout()
        self._setup_logging_handler()

        # Start periodic updates
        self.root.after(100, self._process_log_queue)
        self.root.after(200, self._process_message_queue)
        self._schedule_refresh()
        self.root.after(self.STATUS_UPDATE_MS, self._update_status_bar)

        # Initial log messages
        log.info(f"POSFramework GUI v{self.VERSION} initialized")
        if not SCAPY_AVAILABLE:
            log.warning(f"Scapy not available: {_SCAPY_IMPORT_ERROR}")
            log.warning("Engine operations will be disabled until scapy is installed")
        log.info(f"Database: {self.db_path}")
        log.info(f"Monitor interface: {self.monitor_iface}")
        log.info(f"AP interface: {self.ap_iface}")

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _init_database(self):
        """Initialize database connection."""
        try:
            self.db = POSDatabase(self.db_path)
        except Exception as e:
            self.db = None
            log.error(f"Database initialization failed: {e}")

    def _apply_dark_theme(self):
        """Configure ttk styles for dark theme."""
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # General widget styles
        self.style.configure(".", background=COLORS["bg_dark"],
                             foreground=COLORS["fg_primary"],
                             fieldbackground=COLORS["entry_bg"])

        self.style.configure("TFrame", background=COLORS["bg_dark"])
        self.style.configure("TLabel", background=COLORS["bg_dark"],
                             foreground=COLORS["fg_primary"])
        self.style.configure("TLabelframe", background=COLORS["bg_dark"],
                             foreground=COLORS["accent_blue"])
        self.style.configure("TLabelframe.Label", background=COLORS["bg_dark"],
                             foreground=COLORS["accent_blue"])

        self.style.configure("TNotebook", background=COLORS["bg_dark"],
                             borderwidth=0)
        self.style.configure("TNotebook.Tab", background=COLORS["bg_medium"],
                             foreground=COLORS["fg_primary"],
                             padding=[12, 6])
        self.style.map("TNotebook.Tab",
                       background=[("selected", COLORS["bg_dark"])],
                       foreground=[("selected", COLORS["accent_blue"])])

        self.style.configure("TButton", background=COLORS["button_bg"],
                             foreground=COLORS["button_fg"],
                             padding=[8, 4])
        self.style.map("TButton",
                       background=[("active", COLORS["bg_light"]),
                                   ("disabled", COLORS["bg_medium"])])

        self.style.configure("Start.TButton", background="#2e7d32",
                             foreground="#ffffff")
        self.style.map("Start.TButton",
                       background=[("active", "#388e3c"), ("disabled", COLORS["bg_medium"])])

        self.style.configure("Stop.TButton", background="#c62828",
                             foreground="#ffffff")
        self.style.map("Stop.TButton",
                       background=[("active", "#d32f2f"), ("disabled", COLORS["bg_medium"])])

        self.style.configure("TEntry", fieldbackground=COLORS["entry_bg"],
                             foreground=COLORS["entry_fg"],
                             insertcolor=COLORS["fg_primary"])

        self.style.configure("TCombobox", fieldbackground=COLORS["entry_bg"],
                             foreground=COLORS["entry_fg"],
                             background=COLORS["button_bg"])

        self.style.configure("TCheckbutton", background=COLORS["bg_dark"],
                             foreground=COLORS["fg_primary"])
        self.style.map("TCheckbutton",
                       background=[("active", COLORS["bg_dark"])])

        self.style.configure("TScale", background=COLORS["bg_dark"],
                             troughcolor=COLORS["bg_medium"])

        self.style.configure("TSpinbox", fieldbackground=COLORS["entry_bg"],
                             foreground=COLORS["entry_fg"])

        # Treeview style
        self.style.configure("Treeview",
                             background=COLORS["treeview_bg"],
                             foreground=COLORS["treeview_fg"],
                             fieldbackground=COLORS["treeview_bg"],
                             borderwidth=0,
                             rowheight=24)
        self.style.configure("Treeview.Heading",
                             background=COLORS["bg_medium"],
                             foreground=COLORS["accent_blue"],
                             borderwidth=1)
        self.style.map("Treeview",
                       background=[("selected", COLORS["treeview_selected"])],
                       foreground=[("selected", "#ffffff")])

        # Scrollbar style
        self.style.configure("TScrollbar",
                             background=COLORS["bg_medium"],
                             troughcolor=COLORS["bg_dark"],
                             borderwidth=0)

        # Status bar style
        self.style.configure("Status.TLabel",
                             background=COLORS["bg_medium"],
                             foreground=COLORS["fg_primary"],
                             padding=[4, 2])
        self.style.configure("StatusGreen.TLabel",
                             background=COLORS["bg_medium"],
                             foreground=COLORS["accent_green"],
                             padding=[4, 2])
        self.style.configure("StatusRed.TLabel",
                             background=COLORS["bg_medium"],
                             foreground=COLORS["accent_red"],
                             padding=[4, 2])

    def _build_menu(self):
        """Build the application menu bar."""
        menubar = tk.Menu(self.root, bg=COLORS["bg_medium"],
                          fg=COLORS["fg_primary"],
                          activebackground=COLORS["bg_light"],
                          activeforeground=COLORS["fg_primary"])

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                            fg=COLORS["fg_primary"],
                            activebackground=COLORS["bg_light"])
        file_menu.add_command(label="Open Database...", command=self._open_database)
        file_menu.add_command(label="Export Credentials...", command=self._export_credentials)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                             fg=COLORS["fg_primary"],
                             activebackground=COLORS["bg_light"])
        tools_menu.add_command(label="Clear Database", command=self._clear_database)
        tools_menu.add_command(label="Refresh All", command=self._refresh_data)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                            fg=COLORS["fg_primary"],
                            activebackground=COLORS["bg_light"])
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_main_layout(self):
        """Build the main application layout."""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Notebook (tabs) - upper section
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Build each tab
        self._build_recon_tab()
        self._build_attack_tab()
        self._build_mitm_tab()
        self._build_credentials_tab()
        self._build_printers_tab()
        self._build_settings_tab()

        # Log panel - lower section
        self._build_log_panel(main_frame)

        # Status bar - bottom
        self._build_status_bar()

    # ─── Recon Tab ────────────────────────────────────────────────────────────

    def _build_recon_tab(self):
        """Build the Reconnaissance tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Recon  ")

        # Controls frame at top
        controls = ttk.LabelFrame(tab, text="Recon Controls", padding=10)
        controls.pack(fill=tk.X, padx=5, pady=5)

        # Row 1: Interface and channels
        row1 = ttk.Frame(controls)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.recon_iface_var = tk.StringVar(value=self.monitor_iface)
        iface_combo = ttk.Combobox(row1, textvariable=self.recon_iface_var,
                                   width=20, values=[DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE])
        iface_combo.pack(side=tk.LEFT, padx=(0, 20))

        ttk.Label(row1, text="Channels:").pack(side=tk.LEFT, padx=(0, 5))
        self.chan_24_var = tk.BooleanVar(value=True)
        self.chan_5_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="2.4 GHz", variable=self.chan_24_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row1, text="5 GHz", variable=self.chan_5_var).pack(side=tk.LEFT, padx=5)

        # Row 2: Verbose and signal targeting
        row2 = ttk.Frame(controls)
        row2.pack(fill=tk.X, pady=2)

        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Verbose Mode", variable=self.verbose_var).pack(side=tk.LEFT, padx=5)

        self.signal_targeting_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Signal Targeting", variable=self.signal_targeting_var).pack(side=tk.LEFT, padx=5)

        ttk.Label(row2, text="Timeout (s):").pack(side=tk.LEFT, padx=(20, 5))
        self.recon_timeout_var = tk.StringVar(value="")
        ttk.Entry(row2, textvariable=self.recon_timeout_var, width=8).pack(side=tk.LEFT)

        # Start/Stop buttons
        btn_frame = ttk.Frame(controls)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.recon_start_btn = ttk.Button(btn_frame, text="Start Recon",
                                          style="Start.TButton",
                                          command=self._start_recon)
        self.recon_start_btn.pack(side=tk.LEFT, padx=5)

        self.recon_stop_btn = ttk.Button(btn_frame, text="Stop Recon",
                                         style="Stop.TButton",
                                         command=self._stop_recon, state="disabled")
        self.recon_stop_btn.pack(side=tk.LEFT, padx=5)

        self.recon_status_label = ttk.Label(btn_frame, text="Status: Idle",
                                            foreground=COLORS["fg_secondary"])
        self.recon_status_label.pack(side=tk.LEFT, padx=20)

        # Tables area - split horizontally
        tables_frame = ttk.Frame(tab)
        tables_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # AP Table
        ap_frame = ttk.LabelFrame(tables_frame, text="Discovered Access Points", padding=5)
        ap_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP, pady=(0, 5))

        ap_columns = ("bssid", "ssid", "channel", "security", "rssi", "vendor", "pos")
        self.ap_tree = ttk.Treeview(ap_frame, columns=ap_columns, show="headings", height=8)
        for col in ap_columns:
            self.ap_tree.heading(col, text=col.upper())
            width = 150 if col in ("bssid", "ssid", "vendor") else 80
            self.ap_tree.column(col, width=width, anchor=tk.CENTER)

        ap_scroll_y = ttk.Scrollbar(ap_frame, orient=tk.VERTICAL, command=self.ap_tree.yview)
        ap_scroll_x = ttk.Scrollbar(ap_frame, orient=tk.HORIZONTAL, command=self.ap_tree.xview)
        self.ap_tree.configure(yscrollcommand=ap_scroll_y.set, xscrollcommand=ap_scroll_x.set)
        self.ap_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ap_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Client Table
        client_frame = ttk.LabelFrame(tables_frame, text="Discovered Clients", padding=5)
        client_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        client_columns = ("mac", "vendor", "associated_ap", "rssi", "pos")
        self.client_tree = ttk.Treeview(client_frame, columns=client_columns,
                                        show="headings", height=6)
        for col in client_columns:
            self.client_tree.heading(col, text=col.replace("_", " ").upper())
            width = 150 if col in ("mac", "associated_ap") else 100
            self.client_tree.column(col, width=width, anchor=tk.CENTER)

        client_scroll_y = ttk.Scrollbar(client_frame, orient=tk.VERTICAL,
                                        command=self.client_tree.yview)
        self.client_tree.configure(yscrollcommand=client_scroll_y.set)
        self.client_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        client_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

    # ─── Attack Tab ───────────────────────────────────────────────────────────

    def _build_attack_tab(self):
        """Build the Attack tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Attack  ")

        # Target frame
        target_frame = ttk.LabelFrame(tab, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)

        row1 = ttk.Frame(target_frame)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Target BSSID:").pack(side=tk.LEFT, padx=(0, 5))
        self.attack_target_var = tk.StringVar(value="")
        ttk.Entry(row1, textvariable=self.attack_target_var, width=25).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(row1, text="Auto (Strongest AP)", command=self._auto_target).pack(side=tk.LEFT, padx=5)

        ttk.Label(row1, text="RSSI Limit:").pack(side=tk.LEFT, padx=(20, 5))
        self.rssi_var = tk.IntVar(value=-80)
        rssi_scale = ttk.Scale(row1, from_=-100, to=-30, variable=self.rssi_var,
                               orient=tk.HORIZONTAL, length=150)
        rssi_scale.pack(side=tk.LEFT, padx=5)
        self.rssi_label = ttk.Label(row1, text="-80 dBm")
        self.rssi_label.pack(side=tk.LEFT)
        rssi_scale.configure(command=self._update_rssi_label)

        # Attack modules frame
        modules_frame = ttk.LabelFrame(tab, text="Attack Modules", padding=10)
        modules_frame.pack(fill=tk.X, padx=5, pady=5)

        # Module checkboxes in a grid
        self.attack_modules = {}
        module_names = [
            ("deauth", "Deauthentication"),
            ("beacons", "Known Beacons"),
            ("karma", "KARMA"),
            ("rogue_ap", "Rogue AP"),
            ("ap_clone", "AP Clone"),
            ("krack", "KRACK"),
            ("dos", "WiFi DoS"),
            ("client_isolation", "Client Isolation"),
            ("printer_attacks", "Printer Attacks"),
        ]

        mod_grid = ttk.Frame(modules_frame)
        mod_grid.pack(fill=tk.X)

        for i, (key, label) in enumerate(module_names):
            var = tk.BooleanVar(value=(key in ("deauth", "beacons", "karma")))
            self.attack_modules[key] = var
            row_idx = i // 3
            col_idx = i % 3
            ttk.Checkbutton(mod_grid, text=label, variable=var).grid(
                row=row_idx, column=col_idx, sticky=tk.W, padx=10, pady=2)

        # DoS mode selection
        dos_frame = ttk.Frame(modules_frame)
        dos_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(dos_frame, text="DoS Mode:").pack(side=tk.LEFT, padx=(0, 5))
        self.dos_mode_var = tk.StringVar(value="cts_flood")
        dos_combo = ttk.Combobox(dos_frame, textvariable=self.dos_mode_var, width=18,
                                 values=["cts_flood", "beacon_exhaust", "qos_null", "fragment"],
                                 state="readonly")
        dos_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(dos_frame, text="Recon Duration (s):").pack(side=tk.LEFT, padx=(20, 5))
        self.recon_duration_var = tk.IntVar(value=30)
        ttk.Spinbox(dos_frame, from_=10, to=300, textvariable=self.recon_duration_var,
                    width=5).pack(side=tk.LEFT)

        # Start/Stop buttons
        btn_frame = ttk.LabelFrame(tab, text="Attack Control", padding=10)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        self.attack_start_btn = ttk.Button(btn_frame, text="Start Attack",
                                           style="Start.TButton",
                                           command=self._start_attack)
        self.attack_start_btn.pack(side=tk.LEFT, padx=5)

        self.attack_stop_btn = ttk.Button(btn_frame, text="Stop Attack",
                                          style="Stop.TButton",
                                          command=self._stop_attack, state="disabled")
        self.attack_stop_btn.pack(side=tk.LEFT, padx=5)

        self.attack_status_label = ttk.Label(btn_frame, text="Status: Idle",
                                             foreground=COLORS["fg_secondary"])
        self.attack_status_label.pack(side=tk.LEFT, padx=20)

        # Attack status info
        status_frame = ttk.LabelFrame(tab, text="Attack Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.attack_info_text = tk.Text(status_frame, height=8,
                                        bg=COLORS["treeview_bg"],
                                        fg=COLORS["fg_primary"],
                                        font=("Consolas", 9),
                                        state="disabled", wrap=tk.WORD)
        self.attack_info_text.pack(fill=tk.BOTH, expand=True)

    # ─── MITM Tab ────────────────────────────────────────────────────────────

    def _build_mitm_tab(self):
        """Build the MITM (Man-in-the-Middle) tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  MITM  ")

        # Configuration frame
        config_frame = ttk.LabelFrame(tab, text="MITM Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)

        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Target IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.mitm_target_var = tk.StringVar(value="")
        ttk.Entry(row1, textvariable=self.mitm_target_var, width=18).pack(side=tk.LEFT, padx=(0, 20))

        ttk.Label(row1, text="Gateway IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.mitm_gateway_var = tk.StringVar(value="")
        ttk.Entry(row1, textvariable=self.mitm_gateway_var, width=18).pack(side=tk.LEFT)

        # MITM module checkboxes
        mod_frame = ttk.Frame(config_frame)
        mod_frame.pack(fill=tk.X, pady=(10, 0))

        self.mitm_modules = {}
        mitm_module_names = [
            ("arp_poison", "ARP Poison"),
            ("ssl_strip", "SSL Strip"),
            ("dns_spoof", "DNS Spoof"),
            ("cred_harvest", "Credential Harvest"),
        ]

        for key, label in mitm_module_names:
            var = tk.BooleanVar(value=True)
            self.mitm_modules[key] = var
            ttk.Checkbutton(mod_frame, text=label, variable=var).pack(side=tk.LEFT, padx=10)

        # DNS Spoof targets
        dns_frame = ttk.Frame(config_frame)
        dns_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(dns_frame, text="DNS Spoof Domains (one per line):").pack(anchor=tk.W)
        self.dns_domains_text = tk.Text(dns_frame, height=3, width=60,
                                        bg=COLORS["entry_bg"],
                                        fg=COLORS["entry_fg"],
                                        font=("Consolas", 9))
        self.dns_domains_text.pack(fill=tk.X, pady=2)
        self.dns_domains_text.insert("1.0", "*.google.com\n*.facebook.com\n*.bank.com")

        # Start/Stop buttons
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.mitm_start_btn = ttk.Button(btn_frame, text="Start MITM",
                                         style="Start.TButton",
                                         command=self._start_mitm)
        self.mitm_start_btn.pack(side=tk.LEFT, padx=5)

        self.mitm_stop_btn = ttk.Button(btn_frame, text="Stop MITM",
                                        style="Stop.TButton",
                                        command=self._stop_mitm, state="disabled")
        self.mitm_stop_btn.pack(side=tk.LEFT, padx=5)

        self.mitm_status_label = ttk.Label(btn_frame, text="Status: Idle",
                                           foreground=COLORS["fg_secondary"])
        self.mitm_status_label.pack(side=tk.LEFT, padx=20)

        self.mitm_packet_count_label = ttk.Label(btn_frame, text="Packets: 0",
                                                  foreground=COLORS["accent_cyan"])
        self.mitm_packet_count_label.pack(side=tk.RIGHT, padx=10)

        # Traffic table
        traffic_frame = ttk.LabelFrame(tab, text="Intercepted Traffic", padding=5)
        traffic_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        traffic_columns = ("source", "dest", "protocol", "data")
        self.traffic_tree = ttk.Treeview(traffic_frame, columns=traffic_columns,
                                         show="headings", height=12)
        for col in traffic_columns:
            self.traffic_tree.heading(col, text=col.upper())
            width = 200 if col == "data" else 150
            self.traffic_tree.column(col, width=width)

        traffic_scroll = ttk.Scrollbar(traffic_frame, orient=tk.VERTICAL,
                                       command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscrollcommand=traffic_scroll.set)
        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        traffic_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # ─── Credentials Tab ─────────────────────────────────────────────────────

    def _build_credentials_tab(self):
        """Build the Credentials tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Credentials  ")

        # Controls
        controls = ttk.Frame(tab)
        controls.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(controls, text="Refresh", command=self._refresh_credentials).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Export to JSON", command=self._export_credentials).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Clear All", command=self._clear_credentials).pack(side=tk.LEFT, padx=5)

        self.cred_count_label = ttk.Label(controls, text="Total: 0",
                                          foreground=COLORS["accent_orange"])
        self.cred_count_label.pack(side=tk.RIGHT, padx=10)

        # Credentials table
        cred_frame = ttk.LabelFrame(tab, text="Captured Credentials", padding=5)
        cred_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        cred_columns = ("timestamp", "source_ip", "username", "password", "url", "protocol")
        self.cred_tree = ttk.Treeview(cred_frame, columns=cred_columns,
                                      show="headings", height=18)
        for col in cred_columns:
            self.cred_tree.heading(col, text=col.replace("_", " ").upper())
            width = 180 if col in ("url", "timestamp") else 130
            self.cred_tree.column(col, width=width)

        cred_scroll_y = ttk.Scrollbar(cred_frame, orient=tk.VERTICAL,
                                      command=self.cred_tree.yview)
        cred_scroll_x = ttk.Scrollbar(cred_frame, orient=tk.HORIZONTAL,
                                      command=self.cred_tree.xview)
        self.cred_tree.configure(yscrollcommand=cred_scroll_y.set,
                                 xscrollcommand=cred_scroll_x.set)
        self.cred_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cred_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

    # ─── Printers Tab ────────────────────────────────────────────────────────

    def _build_printers_tab(self):
        """Build the Printers tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Printers  ")

        # Controls
        controls = ttk.LabelFrame(tab, text="Printer Recon Controls", padding=10)
        controls.pack(fill=tk.X, padx=5, pady=5)

        btn_frame = ttk.Frame(controls)
        btn_frame.pack(fill=tk.X)

        self.printer_start_btn = ttk.Button(btn_frame, text="Start Printer Recon",
                                            style="Start.TButton",
                                            command=self._start_printer_recon)
        self.printer_start_btn.pack(side=tk.LEFT, padx=5)

        self.printer_stop_btn = ttk.Button(btn_frame, text="Stop Printer Recon",
                                           style="Stop.TButton",
                                           command=self._stop_printer_recon, state="disabled")
        self.printer_stop_btn.pack(side=tk.LEFT, padx=5)

        self.printer_status_label = ttk.Label(btn_frame, text="Status: Idle",
                                              foreground=COLORS["fg_secondary"])
        self.printer_status_label.pack(side=tk.LEFT, padx=20)

        # Printers table
        printer_frame = ttk.LabelFrame(tab, text="Discovered Printers", padding=5)
        printer_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 2))

        printer_columns = ("ip", "model", "manufacturer", "hostname", "firmware",
                           "default_creds", "vulns")
        self.printer_tree = ttk.Treeview(printer_frame, columns=printer_columns,
                                         show="headings", height=5)
        for col in printer_columns:
            self.printer_tree.heading(col, text=col.replace("_", " ").upper())
            width = 130 if col in ("model", "manufacturer") else 100
            self.printer_tree.column(col, width=width)

        printer_scroll = ttk.Scrollbar(printer_frame, orient=tk.VERTICAL,
                                       command=self.printer_tree.yview)
        self.printer_tree.configure(yscrollcommand=printer_scroll.set)
        self.printer_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        printer_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Print Jobs table
        jobs_frame = ttk.LabelFrame(tab, text="Intercepted Print Jobs", padding=5)
        jobs_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

        job_columns = ("timestamp", "printer_ip", "source", "document", "type", "pages")
        self.jobs_tree = ttk.Treeview(jobs_frame, columns=job_columns,
                                      show="headings", height=5)
        for col in job_columns:
            self.jobs_tree.heading(col, text=col.replace("_", " ").upper())
            width = 150 if col in ("document", "timestamp") else 100
            self.jobs_tree.column(col, width=width)

        jobs_scroll = ttk.Scrollbar(jobs_frame, orient=tk.VERTICAL,
                                    command=self.jobs_tree.yview)
        self.jobs_tree.configure(yscrollcommand=jobs_scroll.set)
        self.jobs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        jobs_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Printer Credentials table
        pcred_frame = ttk.LabelFrame(tab, text="Printer Credentials", padding=5)
        pcred_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(2, 5))

        pcred_columns = ("timestamp", "printer_ip", "protocol", "username", "password")
        self.pcred_tree = ttk.Treeview(pcred_frame, columns=pcred_columns,
                                       show="headings", height=4)
        for col in pcred_columns:
            self.pcred_tree.heading(col, text=col.replace("_", " ").upper())
            self.pcred_tree.column(col, width=130)

        pcred_scroll = ttk.Scrollbar(pcred_frame, orient=tk.VERTICAL,
                                     command=self.pcred_tree.yview)
        self.pcred_tree.configure(yscrollcommand=pcred_scroll.set)
        self.pcred_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pcred_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # ─── Settings Tab ────────────────────────────────────────────────────────

    def _build_settings_tab(self):
        """Build the Settings tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Settings  ")

        # Interface settings
        iface_frame = ttk.LabelFrame(tab, text="Interface Configuration", padding=10)
        iface_frame.pack(fill=tk.X, padx=5, pady=5)

        row1 = ttk.Frame(iface_frame)
        row1.pack(fill=tk.X, pady=3)
        ttk.Label(row1, text="Monitor Interface:", width=18).pack(side=tk.LEFT)
        self.settings_monitor_var = tk.StringVar(value=self.monitor_iface)
        ttk.Entry(row1, textvariable=self.settings_monitor_var, width=25).pack(side=tk.LEFT, padx=5)

        row2 = ttk.Frame(iface_frame)
        row2.pack(fill=tk.X, pady=3)
        ttk.Label(row2, text="AP Interface:", width=18).pack(side=tk.LEFT)
        self.settings_ap_var = tk.StringVar(value=self.ap_iface)
        ttk.Entry(row2, textvariable=self.settings_ap_var, width=25).pack(side=tk.LEFT, padx=5)

        # Database settings
        db_frame = ttk.LabelFrame(tab, text="Database", padding=10)
        db_frame.pack(fill=tk.X, padx=5, pady=5)

        row3 = ttk.Frame(db_frame)
        row3.pack(fill=tk.X, pady=3)
        ttk.Label(row3, text="Database Path:", width=18).pack(side=tk.LEFT)
        self.settings_db_var = tk.StringVar(value=self.db_path)
        ttk.Entry(row3, textvariable=self.settings_db_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Browse...", command=self._browse_database).pack(side=tk.LEFT, padx=5)

        # Application settings
        app_frame = ttk.LabelFrame(tab, text="Application Settings", padding=10)
        app_frame.pack(fill=tk.X, padx=5, pady=5)

        row4 = ttk.Frame(app_frame)
        row4.pack(fill=tk.X, pady=3)
        ttk.Label(row4, text="Refresh Interval (ms):", width=18).pack(side=tk.LEFT)
        self.settings_refresh_var = tk.IntVar(value=self.refresh_interval)
        ttk.Spinbox(row4, from_=500, to=10000, increment=500,
                    textvariable=self.settings_refresh_var, width=8).pack(side=tk.LEFT, padx=5)

        row5 = ttk.Frame(app_frame)
        row5.pack(fill=tk.X, pady=3)
        ttk.Label(row5, text="Log Level:", width=18).pack(side=tk.LEFT)
        self.settings_loglevel_var = tk.StringVar(value="INFO")
        ttk.Combobox(row5, textvariable=self.settings_loglevel_var, width=12,
                     values=["DEBUG", "INFO", "WARNING", "ERROR"],
                     state="readonly").pack(side=tk.LEFT, padx=5)

        row6 = ttk.Frame(app_frame)
        row6.pack(fill=tk.X, pady=3)
        ttk.Label(row6, text="Theme:", width=18).pack(side=tk.LEFT)
        self.settings_theme_var = tk.StringVar(value="Dark")
        ttk.Combobox(row6, textvariable=self.settings_theme_var, width=12,
                     values=["Dark", "Light"], state="readonly").pack(side=tk.LEFT, padx=5)

        # Apply button
        apply_frame = ttk.Frame(app_frame)
        apply_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(apply_frame, text="Apply Settings", command=self._apply_settings).pack(side=tk.LEFT, padx=5)

        # About section
        about_frame = ttk.LabelFrame(tab, text="About", padding=10)
        about_frame.pack(fill=tk.X, padx=5, pady=5)

        about_text = (
            f"POSFramework v{self.VERSION}\n"
            "WiFi Reconnaissance & Attack Suite\n\n"
            "A comprehensive framework for POS system security testing.\n"
            "Includes passive recon, active attacks, MITM, credential\n"
            "harvesting, and printer exploitation modules.\n\n"
            "Platform: " + ("Windows" if IS_WINDOWS else "Linux") + "\n"
            f"Python: {sys.version.split()[0]}"
        )
        about_label = ttk.Label(about_frame, text=about_text, justify=tk.LEFT,
                                foreground=COLORS["fg_secondary"])
        about_label.pack(anchor=tk.W)

    # ─── Log Panel ───────────────────────────────────────────────────────────

    def _build_log_panel(self, parent):
        """Build the log output panel at the bottom."""
        log_frame = ttk.LabelFrame(parent, text="Log Output", padding=3)
        log_frame.pack(fill=tk.X, pady=(0, 5))

        # Toolbar for log panel
        log_toolbar = ttk.Frame(log_frame)
        log_toolbar.pack(fill=tk.X, pady=(0, 3))

        ttk.Button(log_toolbar, text="Clear Log", command=self._clear_log).pack(side=tk.LEFT, padx=2)
        ttk.Label(log_toolbar, text="Filter:").pack(side=tk.LEFT, padx=(10, 5))
        self.log_filter_var = tk.StringVar(value="ALL")
        ttk.Combobox(log_toolbar, textvariable=self.log_filter_var, width=10,
                     values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR"],
                     state="readonly").pack(side=tk.LEFT)

        # ScrolledText for log output
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=8, wrap=tk.WORD,
            bg=COLORS["bg_dark"], fg=COLORS["fg_primary"],
            font=("Consolas", 9), state="disabled",
            insertbackground=COLORS["fg_primary"],
            selectbackground=COLORS["treeview_selected"],
            borderwidth=1, relief=tk.SUNKEN
        )
        self.log_text.pack(fill=tk.X, expand=False)

        # Configure log level tags for color coding
        self.log_text.tag_configure("ERROR", foreground=COLORS["accent_red"])
        self.log_text.tag_configure("WARNING", foreground=COLORS["accent_yellow"])
        self.log_text.tag_configure("INFO", foreground=COLORS["accent_green"])
        self.log_text.tag_configure("DEBUG", foreground=COLORS["accent_cyan"])
        self.log_text.tag_configure("CRITICAL", foreground=COLORS["accent_red"],
                                    underline=True)

    # ─── Status Bar ──────────────────────────────────────────────────────────

    def _build_status_bar(self):
        """Build the status bar at the very bottom of the window."""
        status_frame = ttk.Frame(self.root, style="TFrame")
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=0, pady=0)

        # Separator line
        sep = ttk.Separator(status_frame, orient=tk.HORIZONTAL)
        sep.pack(fill=tk.X)

        bar = ttk.Frame(status_frame)
        bar.pack(fill=tk.X, padx=5, pady=2)

        self.status_connection = ttk.Label(bar, text="Disconnected",
                                           style="StatusRed.TLabel")
        self.status_connection.pack(side=tk.LEFT, padx=(0, 15))

        self.status_modules = ttk.Label(bar, text="Active: 0",
                                        style="Status.TLabel")
        self.status_modules.pack(side=tk.LEFT, padx=10)

        self.status_aps = ttk.Label(bar, text="APs: 0",
                                    style="Status.TLabel")
        self.status_aps.pack(side=tk.LEFT, padx=10)

        self.status_clients = ttk.Label(bar, text="Clients: 0",
                                        style="Status.TLabel")
        self.status_clients.pack(side=tk.LEFT, padx=10)

        self.status_creds = ttk.Label(bar, text="Creds: 0",
                                      style="Status.TLabel")
        self.status_creds.pack(side=tk.LEFT, padx=10)

        self.status_uptime = ttk.Label(bar, text="Uptime: 00:00:00",
                                       style="Status.TLabel")
        self.status_uptime.pack(side=tk.RIGHT, padx=10)

    # ─── Logging Setup ───────────────────────────────────────────────────────

    def _setup_logging_handler(self):
        """Set up custom logging handler that routes to the GUI text widget."""
        self.gui_handler = TextWidgetHandler(self.log_queue)
        self.gui_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        self.gui_handler.setFormatter(formatter)
        log.addHandler(self.gui_handler)

    def _process_log_queue(self):
        """Process pending log messages from the queue (runs in main thread)."""
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                # Check filter
                filter_level = self.log_filter_var.get()
                if filter_level != "ALL":
                    level_order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
                    if level_order.get(level, 0) < level_order.get(filter_level, 0):
                        continue

                self.log_text.configure(state="normal")
                self.log_text.insert(tk.END, msg + "\n", level)
                self._trim_log_widget()
                self.log_text.see(tk.END)
                self.log_text.configure(state="disabled")
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_log_queue)

    def _trim_log_widget(self):
        """Trim the log widget to LOG_MAX_LINES lines (ring-buffer behavior)."""
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > self.LOG_MAX_LINES:
            overflow = line_count - self.LOG_MAX_LINES
            self.log_text.delete("1.0", f"{overflow + 1}.0")

    # ─── Message Queue Consumer ──────────────────────────────────────────────

    def _process_message_queue(self):
        """Drain the message_queue and reconcile UI button/label states."""
        try:
            while True:
                msg_type, _payload = self.message_queue.get_nowait()
                self._handle_state_message(msg_type)
        except queue.Empty:
            pass
        finally:
            self.root.after(200, self._process_message_queue)

    def _handle_state_message(self, msg_type):
        """Reconcile button and label states based on engine messages."""
        if msg_type == "recon_started":
            self.recon_start_btn.configure(state="disabled")
            self.recon_stop_btn.configure(state="normal")
            self.recon_status_label.configure(
                text="Status: Running", foreground=COLORS["accent_green"])
        elif msg_type == "recon_stopped":
            self.recon_start_btn.configure(state="normal")
            self.recon_stop_btn.configure(state="disabled")
            self.recon_status_label.configure(
                text="Status: Stopped", foreground=COLORS["accent_red"])
        elif msg_type == "attack_started":
            self.attack_start_btn.configure(state="disabled")
            self.attack_stop_btn.configure(state="normal")
            self.attack_status_label.configure(
                text="Status: Running", foreground=COLORS["accent_green"])
        elif msg_type == "attack_stopped":
            self.attack_start_btn.configure(state="normal")
            self.attack_stop_btn.configure(state="disabled")
            self.attack_status_label.configure(
                text="Status: Stopped", foreground=COLORS["accent_red"])
        elif msg_type == "mitm_started":
            self.mitm_start_btn.configure(state="disabled")
            self.mitm_stop_btn.configure(state="normal")
            self.mitm_status_label.configure(
                text="Status: Running", foreground=COLORS["accent_green"])
        elif msg_type == "mitm_stopped":
            self.mitm_start_btn.configure(state="normal")
            self.mitm_stop_btn.configure(state="disabled")
            self.mitm_status_label.configure(
                text="Status: Stopped", foreground=COLORS["accent_red"])
        elif msg_type == "printer_recon_started":
            self.printer_start_btn.configure(state="disabled")
            self.printer_stop_btn.configure(state="normal")
            self.printer_status_label.configure(
                text="Status: Running", foreground=COLORS["accent_green"])
        elif msg_type == "printer_recon_stopped":
            self.printer_start_btn.configure(state="normal")
            self.printer_stop_btn.configure(state="disabled")
            self.printer_status_label.configure(
                text="Status: Stopped", foreground=COLORS["accent_red"])

    # ─── Data Refresh ────────────────────────────────────────────────────────

    def _schedule_refresh(self):
        """Schedule the next data refresh, cancelling any pending one."""
        if self._refresh_after_id is not None:
            self.root.after_cancel(self._refresh_after_id)
            self._refresh_after_id = None
        self._refresh_after_id = self.root.after(self.refresh_interval, self._refresh_data)

    def _refresh_data(self):
        """Periodically refresh data from the database."""
        self._refresh_after_id = None
        if self.db is not None:
            try:
                self._update_ap_table()
                self._update_client_table()
                self._update_credentials_table()
                self._update_printer_tables()
            except Exception as e:
                log.debug(f"Data refresh error: {e}")

        self._schedule_refresh()

    def _update_ap_table(self):
        """Update the AP Treeview from the database."""
        if self.db is None:
            return

        try:
            aps = self.db.get_pos_access_points()
        except Exception:
            return

        # Clear existing items
        for item in self.ap_tree.get_children():
            self.ap_tree.delete(item)

        # Insert new data
        if aps:
            for ap in aps:
                # (bssid, ssid, channel, vendor, security, rssi)
                if len(ap) >= 6:
                    bssid, ssid, channel, vendor, security, rssi = ap[:6]
                    pos_flag = "Yes"
                    self.ap_tree.insert("", tk.END, values=(
                        bssid, ssid or "Hidden", channel, security or "Open",
                        rssi, vendor or "Unknown", pos_flag
                    ))

    def _update_client_table(self):
        """Update the Client Treeview from the database."""
        if self.db is None:
            return

        try:
            ap_clients = self.db.get_all_ap_clients()
        except Exception:
            return

        # Clear existing items
        for item in self.client_tree.get_children():
            self.client_tree.delete(item)

        # Insert new data
        if ap_clients:
            for bssid, clients in ap_clients.items():
                for client_mac in clients:
                    self.client_tree.insert("", tk.END, values=(
                        client_mac, "Unknown", bssid, "N/A", "N/A"
                    ))

    def _update_credentials_table(self):
        """Update the credentials Treeview from the database."""
        if self.db is None:
            return

        # Clear existing items
        for item in self.cred_tree.get_children():
            self.cred_tree.delete(item)

        try:
            stats = self.db.get_stats()
            cred_count = stats.get("credentials", 0)
            self.cred_count_label.configure(text=f"Total: {cred_count}")
        except Exception:
            pass

    def _update_printer_tables(self):
        """Update the printer-related Treeviews from the database."""
        if self.db is None:
            return

        try:
            printers = self.db.get_printers()
        except Exception:
            printers = []

        # Clear and repopulate printers
        for item in self.printer_tree.get_children():
            self.printer_tree.delete(item)

        if printers:
            for p in printers:
                self.printer_tree.insert("", tk.END, values=(
                    p.get("ip", ""),
                    p.get("model", ""),
                    p.get("manufacturer", ""),
                    p.get("hostname", ""),
                    p.get("firmware", ""),
                    p.get("default_creds", "No"),
                    p.get("vulns", "0"),
                ))

        # Update print jobs
        try:
            jobs = self.db.get_print_jobs()
        except Exception:
            jobs = []

        for item in self.jobs_tree.get_children():
            self.jobs_tree.delete(item)

        if jobs:
            for j in jobs:
                self.jobs_tree.insert("", tk.END, values=(
                    j.get("timestamp", ""),
                    j.get("printer_ip", ""),
                    j.get("source", ""),
                    j.get("document", ""),
                    j.get("type", ""),
                    j.get("pages", ""),
                ))

    # ─── Status Bar Update ───────────────────────────────────────────────────

    def _update_status_bar(self):
        """Update the status bar with current statistics."""
        # Connection status
        if self.recon_running or self.attack_running or self.mitm_running:
            self.status_connection.configure(text="Connected", style="StatusGreen.TLabel")
        else:
            self.status_connection.configure(text="Disconnected", style="StatusRed.TLabel")

        # Active modules
        active = 0
        if self.recon_running:
            active += 1
        if self.attack_running:
            active += 1
        if self.mitm_running:
            active += 1
        if self.printer_recon_running:
            active += 1
        self.active_modules_count = active
        self.status_modules.configure(text=f"Active: {active}")

        # Stats from database
        if self.db is not None:
            try:
                stats = self.db.get_stats()
                self.status_aps.configure(text=f"APs: {stats.get('access_points', 0)}")
                self.status_clients.configure(text=f"Clients: {stats.get('clients', 0)}")
                self.status_creds.configure(text=f"Creds: {stats.get('credentials', 0)}")
            except Exception:
                pass

        # Uptime
        elapsed = datetime.now() - self.start_time
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        self.status_uptime.configure(text=f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")

        self.root.after(self.STATUS_UPDATE_MS, self._update_status_bar)

    # ─── Recon Operations ────────────────────────────────────────────────────

    def _start_recon(self):
        """Start reconnaissance in a background thread."""
        if not SCAPY_AVAILABLE:
            log.error("Cannot start recon: scapy is not available")
            return

        with self._state_lock:
            if self.recon_running:
                log.warning("Recon is already running")
                return
            self.recon_running = True

        iface = self.recon_iface_var.get()
        channels = []
        if self.chan_24_var.get():
            channels.extend(CHANNELS_24GHZ)
        if self.chan_5_var.get():
            channels.extend(CHANNELS_5GHZ)

        if not channels:
            channels = CHANNELS_24GHZ

        # Validate timeout
        timeout_str = self.recon_timeout_var.get().strip()
        timeout = None
        if timeout_str:
            if not timeout_str.isdigit() or int(timeout_str) == 0:
                log.error("Timeout must be a positive integer (seconds)")
                with self._state_lock:
                    self.recon_running = False
                return
            timeout = int(timeout_str)

        # Disable buttons immediately; message_queue consumer will reconcile
        self.recon_start_btn.configure(state="disabled")
        self.recon_stop_btn.configure(state="disabled")
        self.recon_status_label.configure(text="Status: Starting...",
                                          foreground=COLORS["accent_yellow"])

        def run_recon():
            try:
                self.recon_engine = ReconEngine(iface, self.db, channels=channels)
                if self.verbose_var.get():
                    self.recon_engine.enable_verbose()
                if self.signal_targeting_var.get():
                    self.recon_engine.set_signal_targeting(True)
                log.info(f"Starting recon on {iface} (channels: {len(channels)})")
                self.message_queue.put(("recon_started", None))
                self.recon_engine.start(timeout=timeout)
            except Exception as e:
                log.error(f"Recon error: {e}")
            finally:
                with self._state_lock:
                    self.recon_running = False
                self.message_queue.put(("recon_stopped", None))

        thread = threading.Thread(target=run_recon, daemon=True)
        thread.start()

    def _stop_recon(self):
        """Stop reconnaissance."""
        with self._state_lock:
            if not self.recon_running:
                return
            engine = self.recon_engine

        if engine is not None:
            log.info("Stopping recon...")

            # Disable both buttons while stopping
            self.recon_start_btn.configure(state="disabled")
            self.recon_stop_btn.configure(state="disabled")
            self.recon_status_label.configure(text="Status: Stopping...",
                                              foreground=COLORS["accent_yellow"])

            def stop_recon():
                try:
                    engine.stop()
                except Exception as e:
                    log.error(f"Error stopping recon: {e}")
                finally:
                    with self._state_lock:
                        self.recon_running = False
                        self.recon_engine = None
                    self.message_queue.put(("recon_stopped", None))

            thread = threading.Thread(target=stop_recon, daemon=True)
            thread.start()

    # ─── Attack Operations ───────────────────────────────────────────────────

    def _start_attack(self):
        """Start attack orchestration in a background thread."""
        if not SCAPY_AVAILABLE:
            log.error("Cannot start attack: scapy is not available")
            return

        with self._state_lock:
            if self.attack_running:
                log.warning("Attack is already running")
                return
            self.attack_running = True

        # Validate BSSID if provided
        target_bssid = self.attack_target_var.get().strip() or None
        if target_bssid and not _is_valid_mac(target_bssid):
            log.error(f"Invalid BSSID format: {target_bssid} (expected XX:XX:XX:XX:XX:XX)")
            with self._state_lock:
                self.attack_running = False
            return

        # Disable buttons immediately
        self.attack_start_btn.configure(state="disabled")
        self.attack_stop_btn.configure(state="disabled")
        self.attack_status_label.configure(text="Status: Starting...",
                                           foreground=COLORS["accent_yellow"])

        def run_attack():
            try:
                self.orchestrator = AttackOrchestrator(
                    monitor_iface=self.monitor_iface,
                    ap_iface=self.ap_iface,
                    db=self.db,
                    channels=self._get_selected_channels(),
                    target_bssid=target_bssid,
                    recon_duration=self.recon_duration_var.get(),
                    enable_beacons=self.attack_modules["beacons"].get(),
                    enable_karma=self.attack_modules["karma"].get(),
                    signal_rssi_limit=self.rssi_var.get(),
                    enable_ap_clone=self.attack_modules["ap_clone"].get(),
                    enable_krack=self.attack_modules["krack"].get(),
                    enable_dos=self.attack_modules["dos"].get(),
                    dos_mode=self.dos_mode_var.get(),
                    enable_client_isolation=self.attack_modules["client_isolation"].get(),
                    enable_printer_attacks=self.attack_modules["printer_attacks"].get(),
                )
                self.message_queue.put(("attack_started", None))
                log.info("Starting attack orchestration...")

                if self.orchestrator.start():
                    self._update_attack_info("Attack running...")
                    while self.orchestrator.running:
                        time.sleep(1)
                else:
                    log.error("Attack failed to start")
            except Exception as e:
                log.error(f"Attack error: {e}")
            finally:
                with self._state_lock:
                    self.attack_running = False
                self.message_queue.put(("attack_stopped", None))

        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()

    def _stop_attack(self):
        """Stop attack orchestration."""
        with self._state_lock:
            if not self.attack_running:
                return
            orch = self.orchestrator

        if orch is not None:
            log.info("Stopping attack...")

            self.attack_start_btn.configure(state="disabled")
            self.attack_stop_btn.configure(state="disabled")
            self.attack_status_label.configure(text="Status: Stopping...",
                                               foreground=COLORS["accent_yellow"])

            def stop_attack():
                try:
                    orch.stop()
                except Exception as e:
                    log.error(f"Error stopping attack: {e}")
                finally:
                    with self._state_lock:
                        self.attack_running = False
                        self.orchestrator = None
                    self.message_queue.put(("attack_stopped", None))

            thread = threading.Thread(target=stop_attack, daemon=True)
            thread.start()

    def _auto_target(self):
        """Auto-select the strongest AP from the database."""
        if self.db is None:
            log.warning("No database available")
            return

        try:
            strongest = self.db.get_strongest_ap()
            if strongest:
                bssid = strongest[0]
                ssid = strongest[1]
                self.attack_target_var.set(bssid)
                log.info(f"Auto-targeted: {bssid} ({ssid})")
            else:
                log.warning("No APs found in database. Run recon first.")
        except Exception as e:
            log.error(f"Auto-target error: {e}")

    def _update_rssi_label(self, value):
        """Update RSSI label when slider changes."""
        self.rssi_label.configure(text=f"{int(float(value))} dBm")

    def _update_attack_info(self, text):
        """Update the attack info text widget."""
        self.attack_info_text.configure(state="normal")
        self.attack_info_text.delete("1.0", tk.END)
        self.attack_info_text.insert("1.0", text)
        self.attack_info_text.configure(state="disabled")

    # ─── MITM Operations ─────────────────────────────────────────────────────

    def _start_mitm(self):
        """Start MITM attack in a background thread."""
        if not SCAPY_AVAILABLE:
            log.error("Cannot start MITM: scapy is not available")
            return

        with self._state_lock:
            if self.mitm_running:
                log.warning("MITM is already running")
                return
            self.mitm_running = True

        target_ip = self.mitm_target_var.get().strip()
        gateway_ip = self.mitm_gateway_var.get().strip()

        if not target_ip:
            log.error("Target IP is required for MITM")
            with self._state_lock:
                self.mitm_running = False
            return

        # Validate target IP
        if not _is_valid_ip(target_ip):
            log.error(f"Invalid target IP address: {target_ip}")
            with self._state_lock:
                self.mitm_running = False
            return

        # Validate gateway IP if provided
        if gateway_ip and not _is_valid_ip(gateway_ip):
            log.error(f"Invalid gateway IP address: {gateway_ip}")
            with self._state_lock:
                self.mitm_running = False
            return

        # Disable buttons immediately
        self.mitm_start_btn.configure(state="disabled")
        self.mitm_stop_btn.configure(state="disabled")
        self.mitm_status_label.configure(text="Status: Starting...",
                                         foreground=COLORS["accent_yellow"])

        def run_mitm():
            try:
                self.message_queue.put(("mitm_started", None))

                # Start ARP poisoning / MITM engine
                if self.mitm_modules["arp_poison"].get():
                    self.mitm_engine = MITMEngine(
                        self.monitor_iface,
                        target_ip=target_ip,
                        gateway_ip=gateway_ip or None
                    )
                    self.mitm_engine.start(target_ip=target_ip)
                    log.info(f"MITM/ARP poisoning started against {target_ip}")

                # Start SSL stripper
                if self.mitm_modules["ssl_strip"].get():
                    self.ssl_stripper = SSLStripper(
                        self.monitor_iface,
                        target_ip=target_ip,
                        gateway_ip=gateway_ip or None
                    )
                    self.ssl_stripper.start()
                    log.info("SSL stripping active")

                # Start DNS spoofer
                if self.mitm_modules["dns_spoof"].get():
                    self.dns_spoofer = DNSSpoofEngine(self.monitor_iface)
                    self.dns_spoofer.add_common_targets()
                    self.dns_spoofer.start()
                    log.info("DNS spoofing active")

                # Start credential harvester
                if self.mitm_modules["cred_harvest"].get():
                    self.cred_harvester = CredentialHarvester(
                        self.monitor_iface, output_db=self.db
                    )
                    self.cred_harvester.start()
                    log.info("Credential harvesting active")

                # Keep running until stopped
                while self.mitm_running:
                    time.sleep(1)

            except Exception as e:
                log.error(f"MITM error: {e}")
            finally:
                with self._state_lock:
                    self.mitm_running = False
                self.message_queue.put(("mitm_stopped", None))

        thread = threading.Thread(target=run_mitm, daemon=True)
        thread.start()

    def _stop_mitm(self):
        """Stop MITM attack."""
        with self._state_lock:
            if not self.mitm_running:
                return
            self.mitm_running = False
            mitm_eng = self.mitm_engine
            ssl_str = self.ssl_stripper
            dns_sp = self.dns_spoofer
            cred_h = self.cred_harvester

        log.info("Stopping MITM...")

        self.mitm_start_btn.configure(state="disabled")
        self.mitm_stop_btn.configure(state="disabled")
        self.mitm_status_label.configure(text="Status: Stopping...",
                                         foreground=COLORS["accent_yellow"])

        def stop_mitm():
            try:
                if mitm_eng:
                    mitm_eng.stop()
                if ssl_str:
                    ssl_str.stop()
                if dns_sp:
                    dns_sp.stop()
                if cred_h:
                    cred_h.stop()
            except Exception as e:
                log.error(f"Error stopping MITM: {e}")
            finally:
                with self._state_lock:
                    self.mitm_engine = None
                    self.ssl_stripper = None
                    self.dns_spoofer = None
                    self.cred_harvester = None
                self.message_queue.put(("mitm_stopped", None))

        thread = threading.Thread(target=stop_mitm, daemon=True)
        thread.start()

    # ─── Printer Operations ──────────────────────────────────────────────────

    def _start_printer_recon(self):
        """Start printer reconnaissance in a background thread."""
        if not SCAPY_AVAILABLE:
            log.error("Cannot start printer recon: scapy is not available")
            return

        with self._state_lock:
            if self.printer_recon_running:
                log.warning("Printer recon is already running")
                return
            self.printer_recon_running = True

        # Disable buttons immediately
        self.printer_start_btn.configure(state="disabled")
        self.printer_stop_btn.configure(state="disabled")
        self.printer_status_label.configure(text="Status: Starting...",
                                            foreground=COLORS["accent_yellow"])

        def run_printer_recon():
            try:
                self.printer_recon = PrinterRecon(self.monitor_iface, db=self.db)
                self.ipp_scanner = IPPScanner(self.monitor_iface)
                self.print_interceptor = PrintJobInterceptor(self.monitor_iface, db=self.db)
                self.printer_cred_harvester = PrinterCredentialHarvester(
                    self.monitor_iface, db=self.db
                )

                log.info("Starting printer reconnaissance...")
                self.printer_recon.start()
                self.ipp_scanner.start()
                self.print_interceptor.start()
                self.printer_cred_harvester.start()

                self.message_queue.put(("printer_recon_started", None))

                while self.printer_recon_running:
                    time.sleep(1)

            except Exception as e:
                log.error(f"Printer recon error: {e}")
            finally:
                with self._state_lock:
                    self.printer_recon_running = False
                self.message_queue.put(("printer_recon_stopped", None))

        thread = threading.Thread(target=run_printer_recon, daemon=True)
        thread.start()

    def _stop_printer_recon(self):
        """Stop printer reconnaissance."""
        with self._state_lock:
            if not self.printer_recon_running:
                return
            self.printer_recon_running = False
            pr = self.printer_recon
            ipp = self.ipp_scanner
            pi = self.print_interceptor
            pch = self.printer_cred_harvester

        log.info("Stopping printer recon...")

        self.printer_start_btn.configure(state="disabled")
        self.printer_stop_btn.configure(state="disabled")
        self.printer_status_label.configure(text="Status: Stopping...",
                                            foreground=COLORS["accent_yellow"])

        def stop_printer():
            try:
                if pr:
                    pr.stop()
                if ipp:
                    ipp.stop()
                if pi:
                    pi.stop()
                if pch:
                    pch.stop()
            except Exception as e:
                log.error(f"Error stopping printer recon: {e}")
            finally:
                with self._state_lock:
                    self.printer_recon = None
                    self.ipp_scanner = None
                    self.print_interceptor = None
                    self.printer_cred_harvester = None
                self.message_queue.put(("printer_recon_stopped", None))

        thread = threading.Thread(target=stop_printer, daemon=True)
        thread.start()

    # ─── Credential Operations ───────────────────────────────────────────────

    def _refresh_credentials(self):
        """Manually refresh the credentials table."""
        self._update_credentials_table()
        log.info("Credentials refreshed")

    def _export_credentials(self):
        """Export credentials to a JSON file."""
        filepath = filedialog.asksaveasfilename(
            title="Export Credentials",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filepath:
            try:
                # Collect data from Treeview
                creds = []
                for item_id in self.cred_tree.get_children():
                    values = self.cred_tree.item(item_id, "values")
                    if values:
                        creds.append({
                            "timestamp": values[0],
                            "source_ip": values[1],
                            "username": values[2],
                            "password": values[3],
                            "url": values[4],
                            "protocol": values[5] if len(values) > 5 else "",
                        })

                with open(filepath, "w") as f:
                    json.dump(creds, f, indent=2)

                log.info(f"Exported {len(creds)} credentials to {filepath}")
            except Exception as e:
                log.error(f"Export failed: {e}")
                messagebox.showerror("Export Error", f"Failed to export: {e}")

    def _clear_credentials(self):
        """Clear the credentials table display."""
        result = messagebox.askyesno("Clear Credentials",
                                     "Clear all credentials from the display?")
        if result:
            for item in self.cred_tree.get_children():
                self.cred_tree.delete(item)
            self.cred_count_label.configure(text="Total: 0")
            log.info("Credentials display cleared")

    # ─── Settings Operations ─────────────────────────────────────────────────

    def _apply_settings(self):
        """Apply settings from the Settings tab."""
        self.monitor_iface = self.settings_monitor_var.get()
        self.ap_iface = self.settings_ap_var.get()

        # Update database path if changed
        new_db_path = self.settings_db_var.get()
        if new_db_path != self.db_path:
            self.db_path = new_db_path
            if self.db:
                try:
                    self.db.close()
                except Exception:
                    pass
            self._init_database()
            log.info(f"Database changed to: {self.db_path}")

        # Update refresh interval - cancel old timer and reschedule
        new_interval = self.settings_refresh_var.get()
        if new_interval != self.refresh_interval:
            self.refresh_interval = new_interval
            self._schedule_refresh()
            log.info(f"Refresh interval set to {new_interval}ms")

        # Update log level
        level_name = self.settings_loglevel_var.get()
        level = getattr(logging, level_name, logging.INFO)
        log.setLevel(level)
        self.gui_handler.setLevel(level)
        log.info(f"Log level set to {level_name}")

        # Update interface in Recon tab
        self.recon_iface_var.set(self.monitor_iface)

        log.info("Settings applied successfully")

    def _browse_database(self):
        """Open file browser to select database path."""
        filepath = filedialog.askopenfilename(
            title="Select Database",
            filetypes=[("SQLite databases", "*.db"), ("All files", "*.*")]
        )
        if filepath:
            self.settings_db_var.set(filepath)

    # ─── Menu Actions ────────────────────────────────────────────────────────

    def _open_database(self):
        """Open a different database file."""
        filepath = filedialog.askopenfilename(
            title="Open Database",
            filetypes=[("SQLite databases", "*.db"), ("All files", "*.*")]
        )
        if filepath:
            self.settings_db_var.set(filepath)
            self._apply_settings()

    def _clear_database(self):
        """Clear all rows from the database tables."""
        result = messagebox.askyesno(
            "Clear Database",
            "This will permanently delete all collected data.\nAre you sure?"
        )
        if result:
            if self.db is None:
                log.error("No database connection available")
                return
            try:
                conn = self.db.conn
                cursor = conn.cursor()
                # Retrieve all user tables
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
                tables = [row[0] for row in cursor.fetchall()]
                for table in tables:
                    cursor.execute(f"DELETE FROM [{table}]")
                conn.commit()
                log.info(f"Database cleared: {len(tables)} table(s) emptied")
                # Refresh UI tables
                self._refresh_data()
            except Exception as e:
                log.error(f"Failed to clear database: {e}")

    def _show_about(self):
        """Show the about dialog."""
        messagebox.showinfo(
            "About POSFramework",
            f"POSFramework v{self.VERSION}\n\n"
            "WiFi Reconnaissance & Attack Suite\n\n"
            "A comprehensive framework for POS system\n"
            "security testing and network assessment.\n\n"
            "Modules: Recon, Attack, MITM, Credential\n"
            "Harvesting, Printer Exploitation\n\n"
            f"Platform: {'Windows' if IS_WINDOWS else 'Linux'}\n"
            f"Python: {sys.version.split()[0]}"
        )

    # ─── Utility Methods ─────────────────────────────────────────────────────

    def _get_selected_channels(self):
        """Get currently selected channel list."""
        channels = []
        if self.chan_24_var.get():
            channels.extend(CHANNELS_24GHZ)
        if self.chan_5_var.get():
            channels.extend(CHANNELS_5GHZ)
        return channels if channels else CHANNELS_24GHZ

    def _clear_log(self):
        """Clear the log text widget."""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def _on_close(self):
        """Handle window close event - stop all engines gracefully."""
        log.info("Shutting down POSFramework GUI...")

        # Stop all running engines
        if self.recon_running:
            self._stop_recon()
        if self.attack_running:
            self._stop_attack()
        if self.mitm_running:
            self._stop_mitm()
        if self.printer_recon_running:
            self._stop_printer_recon()

        # Remove custom logging handler
        try:
            log.removeHandler(self.gui_handler)
        except Exception:
            pass

        # Close database
        if self.db:
            try:
                self.db.close()
            except Exception:
                pass

        self.root.destroy()


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    """Launch the POSFramework GUI application."""
    if not TK_AVAILABLE:
        print("ERROR: tkinter is not available on this system.")
        print("Install it with:")
        if IS_LINUX:
            print("  sudo apt-get install python3-tk")
        elif IS_WINDOWS:
            print("  Reinstall Python with 'tcl/tk and IDLE' option checked")
        else:
            print("  Install tkinter for your platform")
        sys.exit(1)

    # Pre-flight safety check: detect headless environments and potential
    # segfaults BEFORE calling tk.Tk() which can crash at the C level.
    from .tk_preflight import preflight_check
    if not preflight_check(verbose=True):
        sys.exit(1)

    root = tk.Tk()

    # Set window icon (if available)
    try:
        if IS_WINDOWS:
            root.iconbitmap(default="")
    except Exception:
        pass

    app = POSFrameworkGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
