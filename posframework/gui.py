"""
POSFramework CLI Terminal UI
-----------------------------
Curses-based terminal interface for POSFramework with:
  - Main menu with options for each mode (Recon, Attack, MITM, Credentials, Printers, Settings)
  - Real-time updating display showing APs, clients, credentials as discovered
  - Status bar at the bottom with live stats
  - Color-coded output (green for success, red for errors, yellow for warnings)
  - Keyboard navigation (arrow keys, enter to select, q to quit)
  - Tabbed view within the terminal

Uses ONLY Python standard library (curses module). No external dependencies.
"""

import os
import sys
import time
import curses
import threading
import logging
from datetime import datetime

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


# ---- Version ----
VERSION = "2.2.0"

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


def _init_colors():
    """Initialize curses color pairs."""
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


# ---- Log Capture Handler ----

class CursesLogHandler(logging.Handler):
    """Captures log records for display in the CLI UI."""

    def __init__(self, max_lines=500):
        super().__init__()
        self.records = []
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

TABS = ["Recon", "Attack", "MITM", "Credentials", "Printers", "Settings"]


# ---- Main Terminal UI Class ----

class TerminalUI:
    """Curses-based terminal UI for POSFramework."""

    def __init__(self):
        self.db = POSDatabase()
        self.running = True
        self.active_tab = 0
        self.scroll_offset = 0
        self.log_handler = CursesLogHandler()
        self.log_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
        )
        log.addHandler(self.log_handler)

        # Engine state
        self.recon_engine = None
        self.recon_running = False
        self.attack_orchestrator = None
        self.attack_running = False
        self.mitm_engine = None
        self.mitm_running = False
        self.cred_harvester = None
        self.cred_running = False
        self.printer_scanner = None
        self.printer_running = False

        # Settings
        self.monitor_iface = DEFAULT_MONITOR_IFACE
        self.ap_iface = DEFAULT_AP_IFACE
        self.use_5ghz = False
        self.channels = CHANNELS_24GHZ
        self.verbose_mode = False
        self.signal_targeting = False

        # Attack configuration
        self.attack_target_bssid = ""
        self.rssi_limit = -80
        self.recon_duration = 30
        self.dos_mode = "cts_flood"
        self.attack_modules = {
            "deauth": True,
            "beacons": True,
            "karma": True,
            "rogue_ap": False,
            "ap_clone": False,
            "krack": False,
            "dos": False,
            "client_isolation": False,
            "printer_attacks": False,
        }

        # MITM configuration
        self.mitm_target_ip = ""
        self.mitm_gateway_ip = ""
        self.mitm_modules = {
            "arp_poison": True,
            "ssl_strip": True,
            "dns_spoof": True,
            "cred_harvest": True,
        }

        # UI state
        self.menu_selected = 0
        self.in_submenu = False
        self.status_message = "Ready"
        self.last_refresh = 0
        self.show_log_panel = True

    def run(self):
        """Main entry point - wraps curses."""
        if IS_WINDOWS:
            print("Error: Curses-based terminal UI is not supported on Windows.")
            print("Use 'python -m posframework recon' or other CLI modes directly.")
            return
        try:
            curses.wrapper(self._main_loop)
        except curses.error as e:
            print(f"Terminal UI error: {e}")
            print("Ensure your terminal supports curses (not a pipe or redirect).")

    def _main_loop(self, stdscr):
        """Main curses event loop."""
        self.stdscr = stdscr
        _init_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(500)  # Refresh every 500ms

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

    def _cleanup(self):
        """Stop all running engines."""
        if self.recon_engine and self.recon_running:
            try:
                self.recon_engine.stop()
            except Exception:
                pass
            self.recon_running = False
        if self.attack_orchestrator and self.attack_running:
            try:
                self.attack_orchestrator.stop()
            except Exception:
                pass
            self.attack_running = False
        if self.mitm_engine and self.mitm_running:
            try:
                self.mitm_engine.stop()
            except Exception:
                pass
            self.mitm_running = False
        try:
            self.db.close()
        except Exception:
            pass

    def _handle_input(self, key):
        """Process keyboard input."""
        if key == ord('q') or key == ord('Q'):
            self.running = False
        elif key == ord('\t') or key == curses.KEY_RIGHT:
            # Next tab
            self.active_tab = (self.active_tab + 1) % len(TABS)
            self.scroll_offset = 0
            self.menu_selected = 0
        elif key == curses.KEY_BTAB or key == curses.KEY_LEFT:
            # Previous tab
            self.active_tab = (self.active_tab - 1) % len(TABS)
            self.scroll_offset = 0
            self.menu_selected = 0
        elif key == curses.KEY_UP:
            if self.menu_selected > 0:
                self.menu_selected -= 1
        elif key == curses.KEY_DOWN:
            self.menu_selected += 1
            # Cap based on current tab's menu items
            max_items = self._get_max_menu_items()
            if self.menu_selected >= max_items:
                self.menu_selected = max_items - 1
        elif key == curses.KEY_PPAGE:
            # Page up for log scroll
            self.scroll_offset = max(0, self.scroll_offset - 10)
        elif key == curses.KEY_NPAGE:
            # Page down for log scroll
            self.scroll_offset += 10
        elif key == ord('\n') or key == curses.KEY_ENTER or key == 10:
            self._handle_action()
        elif key == ord(' '):
            # Space toggles checkboxes
            self._handle_toggle()
        elif key >= ord('1') and key <= ord('6'):
            # Quick tab switch with number keys
            self.active_tab = key - ord('1')
            self.scroll_offset = 0
            self.menu_selected = 0
        elif key == ord('l') or key == ord('L'):
            # Toggle log panel
            self.show_log_panel = not self.show_log_panel
        elif key == ord('c') or key == ord('C'):
            # Clear log
            self.log_handler.clear()

    def _get_max_menu_items(self):
        """Get the maximum number of selectable items for the current tab."""
        tab = TABS[self.active_tab]
        if tab == "Recon":
            return 5  # Start/Stop, Clear, Verbose, Signal Targeting, 5GHz
        elif tab == "Attack":
            return 12  # Start/Stop, Auto-target + 9 modules + DoS mode
        elif tab == "MITM":
            return 6  # Start/Stop + 4 modules + info
        elif tab == "Credentials":
            return 3  # Refresh, Export, Clear
        elif tab == "Printers":
            return 2  # Start/Stop scan
        elif tab == "Settings":
            return 5  # Interface, AP interface, 5GHz, Verbose, About
        return 1

    def _handle_action(self):
        """Handle enter key press on current selection."""
        tab = TABS[self.active_tab]
        if tab == "Recon":
            self._handle_recon_action()
        elif tab == "Attack":
            self._handle_attack_action()
        elif tab == "MITM":
            self._handle_mitm_action()
        elif tab == "Credentials":
            self._handle_cred_action()
        elif tab == "Printers":
            self._handle_printer_action()
        elif tab == "Settings":
            self._handle_settings_action()

    def _handle_toggle(self):
        """Handle space key for toggling checkboxes."""
        tab = TABS[self.active_tab]
        if tab == "Recon":
            if self.menu_selected == 2:
                self.verbose_mode = not self.verbose_mode
            elif self.menu_selected == 3:
                self.signal_targeting = not self.signal_targeting
            elif self.menu_selected == 4:
                self.use_5ghz = not self.use_5ghz
                self.channels = (CHANNELS_24GHZ + CHANNELS_5GHZ) if self.use_5ghz else CHANNELS_24GHZ
        elif tab == "Attack":
            # Indices 2-10 are module toggles
            module_keys = list(self.attack_modules.keys())
            idx = self.menu_selected - 2
            if 0 <= idx < len(module_keys):
                key = module_keys[idx]
                self.attack_modules[key] = not self.attack_modules[key]
        elif tab == "MITM":
            # Indices 2-5 are MITM module toggles
            module_keys = list(self.mitm_modules.keys())
            idx = self.menu_selected - 2
            if 0 <= idx < len(module_keys):
                key = module_keys[idx]
                self.mitm_modules[key] = not self.mitm_modules[key]

    def _handle_recon_action(self):
        """Handle recon tab actions."""
        if self.menu_selected == 0:
            # Start/Stop Recon
            if not self.recon_running:
                self._start_recon()
            else:
                self._stop_recon()
        elif self.menu_selected == 1:
            # Clear results
            self.scroll_offset = 0
            self.status_message = "Results cleared from view"
        elif self.menu_selected == 2:
            self.verbose_mode = not self.verbose_mode
            self.status_message = f"Verbose: {'ON' if self.verbose_mode else 'OFF'}"
        elif self.menu_selected == 3:
            self.signal_targeting = not self.signal_targeting
            self.status_message = f"Signal targeting: {'ON' if self.signal_targeting else 'OFF'}"
        elif self.menu_selected == 4:
            self.use_5ghz = not self.use_5ghz
            self.channels = (CHANNELS_24GHZ + CHANNELS_5GHZ) if self.use_5ghz else CHANNELS_24GHZ
            self.status_message = f"5GHz: {'ON' if self.use_5ghz else 'OFF'} ({len(self.channels)} channels)"

    def _handle_attack_action(self):
        """Handle attack tab actions."""
        if not SCAPY_AVAILABLE:
            self.status_message = "Scapy not available - cannot run attacks"
            return
        if self.menu_selected == 0:
            if not self.attack_running:
                self._start_attack()
            else:
                self._stop_attack()
        elif self.menu_selected == 1:
            # Auto-target strongest POS AP
            self._auto_target()
        else:
            # Toggle attack modules (indices 2-10)
            self._handle_toggle()

    def _handle_mitm_action(self):
        """Handle MITM tab actions."""
        if not SCAPY_AVAILABLE:
            self.status_message = "Scapy not available - cannot run MITM"
            return
        if self.menu_selected == 0:
            if not self.mitm_running:
                self._start_mitm()
            else:
                self._stop_mitm()
        elif self.menu_selected == 1:
            self.status_message = "Configure target/gateway in Settings tab"
        else:
            # Toggle MITM modules
            self._handle_toggle()

    def _handle_cred_action(self):
        """Handle credentials tab actions."""
        if self.menu_selected == 0:
            self.status_message = "Credentials refreshed"
        elif self.menu_selected == 1:
            self._export_credentials()
        elif self.menu_selected == 2:
            self.status_message = "Clear: use CLI 'analyze' mode for full DB operations"

    def _handle_printer_action(self):
        """Handle printer tab actions."""
        if not SCAPY_AVAILABLE:
            self.status_message = "Scapy not available - cannot scan printers"
            return
        if self.menu_selected == 0:
            if not self.printer_running:
                self._start_printer_recon()
            else:
                self._stop_printer_recon()
        elif self.menu_selected == 1:
            self.status_message = "Printer results shown below"

    def _handle_settings_action(self):
        """Handle settings tab actions."""
        if self.menu_selected == 0:
            # Toggle 5GHz
            self.use_5ghz = not self.use_5ghz
            self.channels = (CHANNELS_24GHZ + CHANNELS_5GHZ) if self.use_5ghz else CHANNELS_24GHZ
            self.status_message = f"5GHz scanning: {'enabled' if self.use_5ghz else 'disabled'}"
        elif self.menu_selected == 1:
            self.verbose_mode = not self.verbose_mode
            self.status_message = f"Verbose mode: {'ON' if self.verbose_mode else 'OFF'}"
        elif self.menu_selected == 2:
            self.signal_targeting = not self.signal_targeting
            self.status_message = f"Signal targeting: {'ON' if self.signal_targeting else 'OFF'}"

    # ---- Engine Control Methods ----

    def _start_recon(self):
        """Start recon engine in background thread."""
        if not SCAPY_AVAILABLE:
            self.status_message = "Scapy not available - cannot start recon"
            return
        try:
            self.recon_engine = ReconEngine(
                self.monitor_iface, self.db, channels=self.channels
            )
            if self.verbose_mode:
                self.recon_engine.enable_verbose()
            self.recon_running = True
            self.status_message = f"Recon started on {self.monitor_iface} ({len(self.channels)} channels)"
            threading.Thread(target=self._recon_thread, daemon=True).start()
        except Exception as e:
            self.status_message = f"Recon error: {e}"
            self.recon_running = False

    def _recon_thread(self):
        """Background thread for recon."""
        try:
            self.recon_engine.start()
        except Exception as e:
            self.status_message = f"Recon failed: {e}"
        finally:
            self.recon_running = False

    def _stop_recon(self):
        """Stop recon engine."""
        if self.recon_engine:
            try:
                self.recon_engine.stop()
            except Exception:
                pass
            self.recon_running = False
            self.status_message = "Recon stopped"

    def _auto_target(self):
        """Auto-select the strongest POS AP as attack target."""
        try:
            ap = self.db.get_strongest_pos_ap()
            if ap:
                self.attack_target_bssid = ap[0] if isinstance(ap, (list, tuple)) else ""
                self.status_message = f"Auto-target: {self.attack_target_bssid}"
            else:
                # Fall back to strongest AP
                ap = self.db.get_strongest_ap()
                if ap:
                    self.attack_target_bssid = ap[0] if isinstance(ap, (list, tuple)) else ""
                    self.status_message = f"Auto-target (non-POS): {self.attack_target_bssid}"
                else:
                    self.status_message = "No targets found - run recon first"
        except Exception as e:
            self.status_message = f"Auto-target error: {e}"

    def _start_attack(self):
        """Start attack orchestrator in background thread."""
        try:
            self.attack_orchestrator = AttackOrchestrator(
                monitor_iface=self.monitor_iface,
                ap_iface=self.ap_iface,
                channels=self.channels,
                target_bssid=self.attack_target_bssid or None,
                recon_duration=self.recon_duration,
                enable_beacons=self.attack_modules.get("beacons", True),
                enable_karma=self.attack_modules.get("karma", True),
                enable_isolation_check=True,
                signal_rssi_limit=self.rssi_limit,
                test_credentials=False,
                enable_ap_clone=self.attack_modules.get("ap_clone", False),
                enable_krack=self.attack_modules.get("krack", False),
                enable_dos=self.attack_modules.get("dos", False),
                dos_mode=self.dos_mode,
                enable_client_isolation=self.attack_modules.get("client_isolation", False),
                enable_printer_attacks=self.attack_modules.get("printer_attacks", False),
            )
            self.attack_running = True
            self.status_message = "Attack started..."
            threading.Thread(target=self._attack_thread, daemon=True).start()
        except Exception as e:
            self.status_message = f"Attack error: {e}"
            self.attack_running = False

    def _attack_thread(self):
        """Background thread for attack."""
        try:
            if self.attack_orchestrator.start():
                while self.attack_orchestrator.running and self.attack_running:
                    time.sleep(1)
        except Exception as e:
            self.status_message = f"Attack failed: {e}"
        finally:
            self.attack_running = False

    def _stop_attack(self):
        """Stop attack orchestrator."""
        if self.attack_orchestrator:
            try:
                self.attack_orchestrator.stop()
            except Exception:
                pass
            self.attack_running = False
            self.status_message = "Attack stopped"

    def _start_mitm(self):
        """Start MITM engine in background thread."""
        if not self.mitm_target_ip or not self.mitm_gateway_ip:
            self.status_message = "MITM requires target IP and gateway IP (set in Settings)"
            return
        try:
            self.mitm_engine = MITMEngine(
                interface=self.monitor_iface,
                target_ip=self.mitm_target_ip,
                gateway_ip=self.mitm_gateway_ip,
            )
            self.mitm_running = True
            self.status_message = f"MITM started: {self.mitm_target_ip} -> {self.mitm_gateway_ip}"
            threading.Thread(target=self._mitm_thread, daemon=True).start()
        except Exception as e:
            self.status_message = f"MITM error: {e}"
            self.mitm_running = False

    def _mitm_thread(self):
        """Background thread for MITM."""
        try:
            self.mitm_engine.start()
        except Exception as e:
            self.status_message = f"MITM failed: {e}"
        finally:
            self.mitm_running = False

    def _stop_mitm(self):
        """Stop MITM engine."""
        if self.mitm_engine:
            try:
                self.mitm_engine.stop()
            except Exception:
                pass
            self.mitm_running = False
            self.status_message = "MITM stopped"

    def _start_printer_recon(self):
        """Start printer reconnaissance."""
        try:
            self.printer_scanner = PrinterRecon(interface=self.monitor_iface)
            self.printer_running = True
            self.status_message = "Printer recon started..."
            threading.Thread(target=self._printer_thread, daemon=True).start()
        except Exception as e:
            self.status_message = f"Printer recon error: {e}"
            self.printer_running = False

    def _printer_thread(self):
        """Background thread for printer recon."""
        try:
            self.printer_scanner.scan()
        except Exception as e:
            self.status_message = f"Printer recon failed: {e}"
        finally:
            self.printer_running = False

    def _stop_printer_recon(self):
        """Stop printer recon."""
        if self.printer_scanner:
            try:
                self.printer_scanner.stop()
            except Exception:
                pass
            self.printer_running = False
            self.status_message = "Printer recon stopped"

    def _export_credentials(self):
        """Export credentials to JSON file."""
        try:
            from .post_attack import PostAttackAnalyzer
            analyzer = PostAttackAnalyzer(self.db)
            analyzer.export_credentials("exports/credentials.json")
            self.status_message = "Credentials exported to exports/credentials.json"
        except Exception as e:
            self.status_message = f"Export error: {e}"

    # ---- Drawing Methods ----

    def _draw(self, stdscr):
        """Draw the complete UI."""
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        if height < 10 or width < 40:
            try:
                stdscr.addstr(0, 0, "Terminal too small. Resize to at least 40x10.")
            except curses.error:
                pass
            stdscr.refresh()
            return

        # Draw header
        self._draw_header(stdscr, width)

        # Draw tab bar
        self._draw_tabs(stdscr, width)

        # Calculate layout
        content_start = 3
        status_height = 2
        log_height = min(10, max(4, (height - content_start - status_height) // 3)) if self.show_log_panel else 0
        content_end = height - status_height - log_height
        content_height = content_end - content_start

        # Draw main content area
        if content_height > 0:
            self._draw_content(stdscr, content_start, content_height, width)

        # Draw log panel
        if self.show_log_panel and log_height > 0:
            log_start = content_end
            log_end = height - status_height
            self._draw_log_panel(stdscr, log_start, log_end, width)

        # Draw status bar
        self._draw_status_bar(stdscr, height, width)

        stdscr.refresh()

    def _draw_header(self, stdscr, width):
        """Draw the title header."""
        title = f" POSFramework v{VERSION} - Terminal UI "
        try:
            stdscr.addstr(0, 0, " " * (width - 1), curses.color_pair(COLOR_STATUS))
            x = max(0, (width - len(title)) // 2)
            stdscr.addstr(0, x, title[:width - 1], curses.color_pair(COLOR_STATUS) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_tabs(self, stdscr, width):
        """Draw the tab bar."""
        x = 0
        for i, tab_name in enumerate(TABS):
            label = f" {i + 1}:{tab_name} "
            if i == self.active_tab:
                attr = curses.color_pair(COLOR_TAB_ACTIVE) | curses.A_BOLD
            else:
                attr = curses.color_pair(COLOR_TAB_INACTIVE)
            try:
                if x + len(label) < width:
                    stdscr.addstr(1, x, label, attr)
            except curses.error:
                pass
            x += len(label) + 1

        # Draw separator line
        try:
            sep = "-" * (width - 1)
            stdscr.addstr(2, 0, sep, curses.color_pair(COLOR_HEADER))
        except curses.error:
            pass

    def _draw_content(self, stdscr, start_y, height, width):
        """Draw the main content for the active tab."""
        tab = TABS[self.active_tab]
        if tab == "Recon":
            self._draw_recon_tab(stdscr, start_y, height, width)
        elif tab == "Attack":
            self._draw_attack_tab(stdscr, start_y, height, width)
        elif tab == "MITM":
            self._draw_mitm_tab(stdscr, start_y, height, width)
        elif tab == "Credentials":
            self._draw_cred_tab(stdscr, start_y, height, width)
        elif tab == "Printers":
            self._draw_printer_tab(stdscr, start_y, height, width)
        elif tab == "Settings":
            self._draw_settings_tab(stdscr, start_y, height, width)

    def _safe_addstr(self, stdscr, y, x, text, attr=curses.A_NORMAL):
        """Safely add a string to the screen, ignoring errors."""
        try:
            height, width = stdscr.getmaxyx()
            if y < height and x < width:
                stdscr.addstr(y, x, text[:width - x - 1], attr)
        except curses.error:
            pass

    def _draw_menu_item(self, stdscr, y, width, idx, text, is_checkbox=False, checked=False):
        """Draw a menu item with selection highlighting."""
        is_selected = (idx == self.menu_selected)
        if is_checkbox:
            prefix = "[X] " if checked else "[ ] "
        else:
            prefix = ""
        marker = "> " if is_selected else "  "
        full_text = marker + prefix + text

        attr = curses.color_pair(COLOR_SELECTED) if is_selected else curses.A_NORMAL
        self._safe_addstr(stdscr, y, 1, full_text, attr)

    def _draw_recon_tab(self, stdscr, start_y, height, width):
        """Draw the Recon tab content."""
        y = start_y

        # -- Controls Section --
        self._safe_addstr(stdscr, y, 1, "Recon Controls:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        # Menu items
        status_text = "Stop Recon" if self.recon_running else "Start Recon"
        self._draw_menu_item(stdscr, y, width, 0, f"[Enter] {status_text}")
        y += 1
        self._draw_menu_item(stdscr, y, width, 1, "[Enter] Clear Display")
        y += 1
        self._draw_menu_item(stdscr, y, width, 2,
                             f"Verbose Mode: {'ON' if self.verbose_mode else 'OFF'}",
                             is_checkbox=True, checked=self.verbose_mode)
        y += 1
        self._draw_menu_item(stdscr, y, width, 3,
                             f"Signal Targeting: {'ON' if self.signal_targeting else 'OFF'}",
                             is_checkbox=True, checked=self.signal_targeting)
        y += 1
        self._draw_menu_item(stdscr, y, width, 4,
                             f"5GHz Channels: {'ON' if self.use_5ghz else 'OFF'}",
                             is_checkbox=True, checked=self.use_5ghz)
        y += 1

        # Status indicator
        y += 1
        recon_status = "SCANNING" if self.recon_running else "IDLE"
        color = COLOR_SUCCESS if self.recon_running else COLOR_WARNING
        self._safe_addstr(stdscr, y, 1, f"Status: {recon_status}  |  "
                          f"Interface: {self.monitor_iface}  |  "
                          f"Channels: {len(self.channels)}",
                          curses.color_pair(color) | curses.A_BOLD)
        y += 2

        # -- AP Table --
        self._safe_addstr(stdscr, y, 1, "Discovered Access Points:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        header = f"{'BSSID':<18} {'SSID':<22} {'CH':<4} {'SEC':<8} {'RSSI':<6} {'VENDOR':<15} {'POS':<4}"
        self._safe_addstr(stdscr, y, 1, header[:width - 2],
                          curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
        y += 1

        # Fetch APs from database
        aps = self._get_access_points()
        for ap in aps:
            if y >= start_y + height - 6:
                break
            bssid = ap.get("bssid", "??:??:??:??:??:??")[:17]
            ssid = (ap.get("ssid") or "<hidden>")[:21]
            channel = str(ap.get("channel", "?"))[:3]
            security = (ap.get("security") or "Open")[:7]
            rssi = str(ap.get("rssi", "?"))[:5]
            vendor = (ap.get("vendor") or "Unknown")[:14]
            pos_flag = "YES" if ap.get("is_pos") else " - "
            line = f"{bssid:<18} {ssid:<22} {channel:<4} {security:<8} {rssi:<6} {vendor:<15} {pos_flag:<4}"

            color = COLOR_SUCCESS if ap.get("is_pos") else COLOR_NORMAL
            self._safe_addstr(stdscr, y, 1, line[:width - 2], curses.color_pair(color))
            y += 1

        if not aps:
            self._safe_addstr(stdscr, y, 1, "  No access points discovered yet. Start recon to scan.",
                              curses.color_pair(COLOR_WARNING))
            y += 1

        # -- Client Table --
        y += 1
        if y < start_y + height - 3:
            self._safe_addstr(stdscr, y, 1, "Discovered Clients:",
                              curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1

            client_header = f"{'MAC':<18} {'VENDOR':<15} {'ASSOCIATED AP':<18} {'RSSI':<6} {'POS':<4}"
            self._safe_addstr(stdscr, y, 1, client_header[:width - 2],
                              curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
            y += 1

            clients = self._get_clients()
            for client in clients:
                if y >= start_y + height - 1:
                    break
                mac = client.get("mac", "??:??:??:??:??:??")[:17]
                vendor = (client.get("vendor") or "Unknown")[:14]
                assoc = (client.get("associated_ap") or "None")[:17]
                rssi = str(client.get("rssi", "?"))[:5]
                pos_flag = "YES" if client.get("is_pos") else " - "
                line = f"{mac:<18} {vendor:<15} {assoc:<18} {rssi:<6} {pos_flag:<4}"
                color = COLOR_SUCCESS if client.get("is_pos") else COLOR_NORMAL
                self._safe_addstr(stdscr, y, 1, line[:width - 2], curses.color_pair(color))
                y += 1

            if not clients:
                self._safe_addstr(stdscr, y, 1, "  No clients discovered yet.",
                                  curses.color_pair(COLOR_WARNING))

    def _draw_attack_tab(self, stdscr, start_y, height, width):
        """Draw the Attack tab content."""
        y = start_y

        # -- Controls --
        self._safe_addstr(stdscr, y, 1, "Attack Configuration:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        # Start/Stop
        status_text = "Stop Attack" if self.attack_running else "Start Attack"
        self._draw_menu_item(stdscr, y, width, 0, f"[Enter] {status_text}")
        y += 1

        # Auto-target
        target_display = self.attack_target_bssid or "(auto-select strongest)"
        self._draw_menu_item(stdscr, y, width, 1, f"[Enter] Auto-Target  [{target_display}]")
        y += 1

        # Attack modules
        y += 1
        self._safe_addstr(stdscr, y, 1, "Attack Modules (Space to toggle):",
                          curses.color_pair(COLOR_ACCENT))
        y += 1

        module_labels = [
            ("deauth", "Deauthentication"),
            ("beacons", "Known Beacons"),
            ("karma", "KARMA"),
            ("rogue_ap", "Rogue AP"),
            ("ap_clone", "AP Clone (Evil Twin)"),
            ("krack", "KRACK"),
            ("dos", "WiFi DoS"),
            ("client_isolation", "Client Isolation"),
            ("printer_attacks", "Printer Attacks"),
        ]

        for i, (key, label) in enumerate(module_labels):
            if y >= start_y + height - 4:
                break
            checked = self.attack_modules.get(key, False)
            self._draw_menu_item(stdscr, y, width, i + 2, label,
                                 is_checkbox=True, checked=checked)
            y += 1

        # DoS mode and RSSI info
        y += 1
        if y < start_y + height - 2:
            self._safe_addstr(stdscr, y, 1,
                              f"DoS Mode: {self.dos_mode}  |  RSSI Limit: {self.rssi_limit} dBm  |  "
                              f"Recon Duration: {self.recon_duration}s",
                              curses.color_pair(COLOR_NORMAL))
            y += 1

        # Status
        y += 1
        if y < start_y + height - 1:
            atk_status = "ATTACKING" if self.attack_running else "IDLE"
            color = COLOR_ERROR if self.attack_running else COLOR_WARNING
            self._safe_addstr(stdscr, y, 1, f"Status: {atk_status}",
                              curses.color_pair(color) | curses.A_BOLD)

        if not SCAPY_AVAILABLE and y + 1 < start_y + height:
            y += 1
            self._safe_addstr(stdscr, y, 1,
                              "WARNING: Scapy not available - install scapy for attack features",
                              curses.color_pair(COLOR_ERROR))

    def _draw_mitm_tab(self, stdscr, start_y, height, width):
        """Draw the MITM tab content."""
        y = start_y

        self._safe_addstr(stdscr, y, 1, "MITM Attack Configuration:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        # Start/Stop
        status_text = "Stop MITM" if self.mitm_running else "Start MITM"
        self._draw_menu_item(stdscr, y, width, 0, f"[Enter] {status_text}")
        y += 1

        # Target info
        target_display = self.mitm_target_ip or "(not set)"
        gateway_display = self.mitm_gateway_ip or "(not set)"
        self._draw_menu_item(stdscr, y, width, 1,
                             f"Target: {target_display}  Gateway: {gateway_display}")
        y += 1

        # MITM modules
        y += 1
        self._safe_addstr(stdscr, y, 1, "MITM Modules (Space to toggle):",
                          curses.color_pair(COLOR_ACCENT))
        y += 1

        mitm_labels = [
            ("arp_poison", "ARP Poison"),
            ("ssl_strip", "SSL Strip"),
            ("dns_spoof", "DNS Spoof"),
            ("cred_harvest", "Credential Harvest"),
        ]

        for i, (key, label) in enumerate(mitm_labels):
            if y >= start_y + height - 4:
                break
            checked = self.mitm_modules.get(key, False)
            self._draw_menu_item(stdscr, y, width, i + 2, label,
                                 is_checkbox=True, checked=checked)
            y += 1

        # Status
        y += 2
        if y < start_y + height - 1:
            mitm_status = "ACTIVE" if self.mitm_running else "IDLE"
            color = COLOR_ERROR if self.mitm_running else COLOR_WARNING
            self._safe_addstr(stdscr, y, 1, f"Status: {mitm_status}",
                              curses.color_pair(color) | curses.A_BOLD)
            y += 1

        # Intercepted traffic placeholder
        y += 1
        if y < start_y + height - 2:
            self._safe_addstr(stdscr, y, 1, "Intercepted Traffic:",
                              curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1
            traffic_header = f"{'SOURCE':<16} {'DEST':<16} {'PROTO':<8} {'DATA':<30}"
            self._safe_addstr(stdscr, y, 1, traffic_header[:width - 2],
                              curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
            y += 1
            if not self.mitm_running:
                self._safe_addstr(stdscr, y, 1, "  Start MITM to capture traffic",
                                  curses.color_pair(COLOR_WARNING))

    def _draw_cred_tab(self, stdscr, start_y, height, width):
        """Draw the Credentials tab content."""
        y = start_y

        self._safe_addstr(stdscr, y, 1, "Captured Credentials:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        # Controls
        self._draw_menu_item(stdscr, y, width, 0, "[Enter] Refresh")
        y += 1
        self._draw_menu_item(stdscr, y, width, 1, "[Enter] Export to JSON")
        y += 1
        self._draw_menu_item(stdscr, y, width, 2, "[Enter] Clear All")
        y += 2

        # Credential count
        cred_count = self._get_credential_count()
        self._safe_addstr(stdscr, y, 1, f"Total Credentials: {cred_count}",
                          curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
        y += 2

        # Credentials table
        header = f"{'TIMESTAMP':<12} {'SOURCE IP':<16} {'USERNAME':<18} {'PASSWORD':<18} {'URL':<20} {'PROTO':<8}"
        self._safe_addstr(stdscr, y, 1, header[:width - 2],
                          curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
        y += 1

        creds = self._get_credentials()
        for cred in creds:
            if y >= start_y + height - 1:
                break
            timestamp = cred.get("timestamp", "?")[:11]
            source_ip = cred.get("source_ip", "?")[:15]
            user = cred.get("username", "?")[:17]
            password = cred.get("password", "****")[:17]
            url = cred.get("url", "?")[:19]
            protocol = cred.get("protocol", "?")[:7]
            line = f"{timestamp:<12} {source_ip:<16} {user:<18} {password:<18} {url:<20} {protocol:<8}"
            self._safe_addstr(stdscr, y, 1, line[:width - 2], curses.color_pair(COLOR_SUCCESS))
            y += 1

        if not creds:
            self._safe_addstr(stdscr, y, 1, "  No credentials captured yet. Run attack or MITM to harvest.",
                              curses.color_pair(COLOR_WARNING))

    def _draw_printer_tab(self, stdscr, start_y, height, width):
        """Draw the Printers tab content."""
        y = start_y

        self._safe_addstr(stdscr, y, 1, "Printer Reconnaissance:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        # Controls
        status_text = "Stop Printer Recon" if self.printer_running else "Start Printer Recon"
        self._draw_menu_item(stdscr, y, width, 0, f"[Enter] {status_text}")
        y += 1
        self._draw_menu_item(stdscr, y, width, 1, "[Enter] Refresh Results")
        y += 1

        # Status
        printer_status = "SCANNING" if self.printer_running else "IDLE"
        color = COLOR_SUCCESS if self.printer_running else COLOR_WARNING
        self._safe_addstr(stdscr, y, 1, f"Status: {printer_status}",
                          curses.color_pair(color) | curses.A_BOLD)
        y += 2

        # -- Discovered Printers Table --
        self._safe_addstr(stdscr, y, 1, "Discovered Printers:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        p_header = f"{'IP':<16} {'MODEL':<15} {'MANUFACTURER':<14} {'HOSTNAME':<14} {'FW':<10} {'DEF CREDS':<10} {'VULNS':<5}"
        self._safe_addstr(stdscr, y, 1, p_header[:width - 2],
                          curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
        y += 1

        printers = self._get_printers()
        for p in printers:
            if y >= start_y + height - 10:
                break
            ip = p.get("ip", "?")[:15]
            model = p.get("model", "?")[:14]
            mfg = p.get("manufacturer", "?")[:13]
            hostname = p.get("hostname", "?")[:13]
            fw = p.get("firmware", "?")[:9]
            def_creds = "YES" if p.get("default_creds") else "No"
            vulns = str(p.get("vulns", 0))[:4]
            line = f"{ip:<16} {model:<15} {mfg:<14} {hostname:<14} {fw:<10} {def_creds:<10} {vulns:<5}"
            color = COLOR_ERROR if p.get("default_creds") else COLOR_NORMAL
            self._safe_addstr(stdscr, y, 1, line[:width - 2], curses.color_pair(color))
            y += 1

        if not printers:
            self._safe_addstr(stdscr, y, 1, "  No printers discovered yet.",
                              curses.color_pair(COLOR_WARNING))
            y += 1

        # -- Print Jobs Table --
        y += 1
        if y < start_y + height - 5:
            self._safe_addstr(stdscr, y, 1, "Intercepted Print Jobs:",
                              curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1

            j_header = f"{'TIMESTAMP':<12} {'PRINTER IP':<16} {'SOURCE':<16} {'DOCUMENT':<20} {'TYPE':<8} {'PAGES':<5}"
            self._safe_addstr(stdscr, y, 1, j_header[:width - 2],
                              curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
            y += 1

            jobs = self._get_print_jobs()
            for j in jobs:
                if y >= start_y + height - 4:
                    break
                ts = j.get("timestamp", "?")[:11]
                pip = j.get("printer_ip", "?")[:15]
                src = j.get("source", "?")[:15]
                doc = j.get("document", "?")[:19]
                dtype = j.get("type", "?")[:7]
                pages = str(j.get("pages", "?"))[:4]
                line = f"{ts:<12} {pip:<16} {src:<16} {doc:<20} {dtype:<8} {pages:<5}"
                self._safe_addstr(stdscr, y, 1, line[:width - 2], curses.color_pair(COLOR_NORMAL))
                y += 1

            if not jobs:
                self._safe_addstr(stdscr, y, 1, "  No print jobs intercepted.",
                                  curses.color_pair(COLOR_WARNING))
                y += 1

        # -- Printer Credentials Table --
        y += 1
        if y < start_y + height - 3:
            self._safe_addstr(stdscr, y, 1, "Printer Credentials:",
                              curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1

            pc_header = f"{'PRINTER IP':<16} {'PROTOCOL':<10} {'USERNAME':<15} {'PASSWORD':<15}"
            self._safe_addstr(stdscr, y, 1, pc_header[:width - 2],
                              curses.color_pair(COLOR_HEADER) | curses.A_UNDERLINE)
            y += 1

            pcreds = self._get_printer_credentials()
            for pc in pcreds:
                if y >= start_y + height - 1:
                    break
                pip = pc.get("printer_ip", "?")[:15]
                proto = pc.get("protocol", "?")[:9]
                user = pc.get("username", "?")[:14]
                pw = pc.get("password", "****")[:14]
                line = f"{pip:<16} {proto:<10} {user:<15} {pw:<15}"
                self._safe_addstr(stdscr, y, 1, line[:width - 2], curses.color_pair(COLOR_SUCCESS))
                y += 1

    def _draw_settings_tab(self, stdscr, start_y, height, width):
        """Draw the Settings tab content."""
        y = start_y

        # Interface Configuration
        self._safe_addstr(stdscr, y, 1, "Interface Configuration:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1
        self._draw_menu_item(stdscr, y, width, 0,
                             f"5GHz Scanning: {'ON' if self.use_5ghz else 'OFF'}",
                             is_checkbox=True, checked=self.use_5ghz)
        y += 1
        self._draw_menu_item(stdscr, y, width, 1,
                             f"Verbose Mode: {'ON' if self.verbose_mode else 'OFF'}",
                             is_checkbox=True, checked=self.verbose_mode)
        y += 1
        self._draw_menu_item(stdscr, y, width, 2,
                             f"Signal Targeting: {'ON' if self.signal_targeting else 'OFF'}",
                             is_checkbox=True, checked=self.signal_targeting)
        y += 2

        # Display current settings (read-only info)
        self._safe_addstr(stdscr, y, 1, "Current Settings:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        settings_info = [
            f"  Monitor Interface:  {self.monitor_iface}",
            f"  AP Interface:       {self.ap_iface}",
            f"  Database:           {DB_NAME}",
            f"  Channels:           {len(self.channels)} ({', '.join(str(c) for c in self.channels[:5])}...)",
            f"  RSSI Limit:         {self.rssi_limit} dBm",
            f"  DoS Mode:           {self.dos_mode}",
            f"  Recon Duration:     {self.recon_duration}s",
        ]
        for info in settings_info:
            if y >= start_y + height - 8:
                break
            self._safe_addstr(stdscr, y, 1, info, curses.color_pair(COLOR_NORMAL))
            y += 1

        # MITM Configuration
        y += 1
        self._safe_addstr(stdscr, y, 1, "MITM Configuration:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1
        self._safe_addstr(stdscr, y, 1,
                          f"  Target IP:   {self.mitm_target_ip or '(not set)'}",
                          curses.color_pair(COLOR_NORMAL))
        y += 1
        self._safe_addstr(stdscr, y, 1,
                          f"  Gateway IP:  {self.mitm_gateway_ip or '(not set)'}",
                          curses.color_pair(COLOR_NORMAL))
        y += 2

        # System Info
        self._safe_addstr(stdscr, y, 1, "System Info:",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1

        platform_str = "Windows" if IS_WINDOWS else "Linux"
        self._safe_addstr(stdscr, y, 1, f"  Platform:  {platform_str}",
                          curses.color_pair(COLOR_NORMAL))
        y += 1
        self._safe_addstr(stdscr, y, 1, f"  Python:    {sys.version.split()[0]}",
                          curses.color_pair(COLOR_NORMAL))
        y += 1

        scapy_text = "Available" if SCAPY_AVAILABLE else "Not Available"
        scapy_color = COLOR_SUCCESS if SCAPY_AVAILABLE else COLOR_ERROR
        self._safe_addstr(stdscr, y, 1, "  Scapy:     ", curses.color_pair(COLOR_NORMAL))
        try:
            stdscr.addstr(scapy_text, curses.color_pair(scapy_color))
        except curses.error:
            pass
        y += 2

        # About
        if y < start_y + height - 3:
            self._safe_addstr(stdscr, y, 1, "About:",
                              curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1
            self._safe_addstr(stdscr, y, 1,
                              f"  POSFramework v{VERSION} - WiFi Reconnaissance & Attack Suite",
                              curses.color_pair(COLOR_ACCENT))
            y += 1
            self._safe_addstr(stdscr, y, 1,
                              "  Comprehensive framework for POS system security testing.",
                              curses.color_pair(COLOR_NORMAL))

    def _draw_log_panel(self, stdscr, start_y, end_y, width):
        """Draw the log output panel."""
        try:
            sep = "-" * (width - 1)
            stdscr.addstr(start_y, 0, sep, curses.color_pair(COLOR_HEADER))
            stdscr.addstr(start_y, 1, "[ Log (L:toggle, C:clear, PgUp/PgDn:scroll) ]",
                          curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        records = self.log_handler.get_records()
        available_lines = end_y - start_y - 1
        if available_lines <= 0:
            return

        # Apply scroll offset
        total_records = len(records)
        max_offset = max(0, total_records - available_lines)
        effective_offset = min(self.scroll_offset, max_offset)

        if effective_offset > 0:
            display_records = records[-(available_lines + effective_offset):-effective_offset]
        else:
            display_records = records[-available_lines:]

        y = start_y + 1
        for levelno, msg in display_records:
            if y >= end_y:
                break
            if levelno >= logging.ERROR:
                color = COLOR_ERROR
            elif levelno >= logging.WARNING:
                color = COLOR_WARNING
            elif levelno <= logging.DEBUG:
                color = COLOR_NORMAL
            else:
                color = COLOR_SUCCESS
            self._safe_addstr(stdscr, y, 1, msg[:width - 2], curses.color_pair(color))
            y += 1

    def _draw_status_bar(self, stdscr, height, width):
        """Draw the status bar at the bottom."""
        try:
            stats = self.db.get_stats()
            ap_count = stats.get("access_points", 0)
            pos_count = stats.get("pos_access_points", 0)
            client_count = stats.get("clients", 0)
            pos_clients = stats.get("pos_clients", 0)
            cred_count = stats.get("credentials", 0)
        except Exception:
            ap_count = pos_count = client_count = pos_clients = cred_count = 0

        # Engines running indicator
        engines = []
        if self.recon_running:
            engines.append("RECON")
        if self.attack_running:
            engines.append("ATTACK")
        if self.mitm_running:
            engines.append("MITM")
        if self.printer_running:
            engines.append("PRINTER")
        engine_str = ",".join(engines) if engines else "None"

        # Status line
        status_line = (
            f" APs:{ap_count}({pos_count}POS) | Clients:{client_count}({pos_clients}POS) | "
            f"Creds:{cred_count} | Engines:[{engine_str}] | {self.status_message}"
        )
        # Help line
        help_line = " [Tab/1-6]:Switch | [Arrows]:Navigate | [Enter]:Action | [Space]:Toggle | [L]:Log | [q]:Quit "

        try:
            # Status bar (second to last line)
            stdscr.addstr(height - 2, 0, " " * (width - 1), curses.color_pair(COLOR_STATUS))
            stdscr.addstr(height - 2, 0, status_line[:width - 1], curses.color_pair(COLOR_STATUS))
        except curses.error:
            pass
        try:
            # Help bar (last line)
            stdscr.addstr(height - 1, 0, " " * (width - 1), curses.color_pair(COLOR_STATUS))
            stdscr.addstr(height - 1, 0, help_line[:width - 1],
                          curses.color_pair(COLOR_STATUS) | curses.A_DIM)
        except curses.error:
            pass

    # ---- Data Access Methods ----

    def _get_access_points(self):
        """Fetch access points from database."""
        try:
            # Use the DB method for POS APs first
            aps = self.db.get_pos_access_points()
            results = []
            if aps:
                for ap in aps:
                    if len(ap) >= 6:
                        bssid, ssid, channel, vendor, security, rssi = ap[:6]
                        results.append({
                            "bssid": bssid,
                            "ssid": ssid or "<hidden>",
                            "channel": channel,
                            "vendor": vendor,
                            "security": security,
                            "rssi": rssi,
                            "is_pos": True,
                        })

            # Also fetch non-POS APs
            try:
                conn = self.db.conn
                if conn:
                    cursor = conn.execute(
                        "SELECT bssid, ssid, channel, vendor, security, rssi, is_pos "
                        "FROM access_points WHERE is_pos = 0 "
                        "ORDER BY rssi DESC LIMIT 30"
                    )
                    for row in cursor.fetchall():
                        results.append({
                            "bssid": row[0],
                            "ssid": row[1] or "<hidden>",
                            "channel": row[2],
                            "vendor": row[3],
                            "security": row[4],
                            "rssi": row[5],
                            "is_pos": False,
                        })
            except Exception:
                pass

            # Sort by RSSI descending
            results.sort(key=lambda x: x.get("rssi") or -100, reverse=True)
            return results[:50]
        except Exception:
            return []

    def _get_clients(self):
        """Fetch discovered clients from database."""
        try:
            ap_clients = self.db.get_all_ap_clients()
            results = []
            if ap_clients:
                for bssid, clients in ap_clients.items():
                    for client_mac in clients:
                        results.append({
                            "mac": client_mac,
                            "vendor": "Unknown",
                            "associated_ap": bssid,
                            "rssi": "N/A",
                            "is_pos": False,
                        })
            return results[:30]
        except Exception:
            return []

    def _get_credentials(self):
        """Fetch captured credentials from database."""
        try:
            conn = self.db.conn
            if conn is None:
                return []
            cursor = conn.execute(
                "SELECT timestamp, client_ip, username, password, url "
                "FROM credentials ORDER BY timestamp DESC LIMIT 50"
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "timestamp": str(row[0])[:11] if row[0] else "?",
                    "source_ip": row[1] or "?",
                    "username": row[2] or "?",
                    "password": row[3] or "****",
                    "url": row[4] or "?",
                    "protocol": "HTTP",
                })
            return results
        except Exception:
            return []

    def _get_credential_count(self):
        """Get total credential count."""
        try:
            stats = self.db.get_stats()
            return stats.get("credentials", 0)
        except Exception:
            return 0

    def _get_printers(self):
        """Fetch discovered printers from database."""
        try:
            printers = self.db.get_printers()
            if not printers:
                return []
            results = []
            for p in printers:
                results.append({
                    "ip": p.get("ip", "?"),
                    "model": p.get("model", "?"),
                    "manufacturer": p.get("manufacturer", "?"),
                    "hostname": p.get("hostname", "?"),
                    "firmware": p.get("firmware", "?"),
                    "default_creds": p.get("default_creds", False),
                    "vulns": p.get("vulns", 0),
                })
            return results
        except Exception:
            return []

    def _get_print_jobs(self):
        """Fetch intercepted print jobs from database."""
        try:
            jobs = self.db.get_print_jobs()
            if not jobs:
                return []
            results = []
            for j in jobs:
                results.append({
                    "timestamp": j.get("timestamp", "?"),
                    "printer_ip": j.get("printer_ip", "?"),
                    "source": j.get("source", "?"),
                    "document": j.get("document", "?"),
                    "type": j.get("type", "?"),
                    "pages": j.get("pages", "?"),
                })
            return results
        except Exception:
            return []

    def _get_printer_credentials(self):
        """Fetch printer credentials from database."""
        try:
            conn = self.db.conn
            if conn is None:
                return []
            cursor = conn.execute(
                "SELECT printer_ip, protocol, username, password "
                "FROM printer_credentials ORDER BY rowid DESC LIMIT 20"
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "printer_ip": row[0] or "?",
                    "protocol": row[1] or "?",
                    "username": row[2] or "?",
                    "password": row[3] or "****",
                })
            return results
        except Exception:
            return []


def main():
    """Launch the POSFramework CLI Terminal UI."""
    ui = TerminalUI()
    ui.run()


if __name__ == "__main__":
    main()
