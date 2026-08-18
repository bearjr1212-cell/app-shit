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
  auto    - Full lifecycle flow (env setup -> recon -> score -> attack -> cleanup)

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
import threading
import select

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
from .intel_enricher import IntelEnricher


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
    from . import __version__

    parser = argparse.ArgumentParser(
        description="POS Recon & Attack Framework v2 (Stage 2 Enhanced)",
        epilog="Scanned values auto-feed attack modules. No manual targeting required.")

    # Version flag
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}",
                        help="Show framework version and exit")

    # Global config arguments (before subcommand)
    parser.add_argument("--config", dest="config_file", default=None,
                        help="Path to YAML config file (default: posframework.yaml)")
    parser.add_argument("--profile", default=None,
                        help="Activate a named config profile (e.g., stealth, aggressive, recon-only)")

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
    attack.add_argument("--rssi-limit", type=int, default=-80,
                        choices=range(-100, 1), metavar="DBM",
                        help="Min RSSI for deauth targets in dBm (-100 to 0, default: -80)")
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
    full.add_argument("--rssi-limit", type=int, default=-80,
                      choices=range(-100, 1), metavar="DBM",
                      help="Min RSSI for deauth targets in dBm (-100 to 0, default: -80)")
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

    # ── GUI mode ──────────────────────────────────────────────────────────────
    sub.add_parser("gui", help="Launch curses-based CLI terminal UI")

    # ── Auto mode ─────────────────────────────────────────────────────────────
    auto = sub.add_parser("auto",
        help="Fully automated recon-to-attack flow (environment -> recon -> attack -> cleanup)")
    auto.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE,
                      help=f"Monitor mode interface (default: {DEFAULT_MONITOR_IFACE})")
    auto.add_argument("-a", "--ap-interface", default=DEFAULT_AP_IFACE,
                      help=f"AP/injection interface (default: {DEFAULT_AP_IFACE})")
    auto.add_argument("--5ghz", dest="use_5ghz", action="store_true",
                      help="Include 5GHz channels in scan")
    auto.add_argument("--auto-duration", type=int, default=300,
                      choices=range(10, 86401),
                      metavar="SECONDS",
                      help="Total operation time in seconds (10-86400, default: 300)")
    auto.add_argument("--auto-max-targets", type=int, default=3,
                      choices=range(1, 51),
                      metavar="N",
                      help="Maximum number of targets to attack (1-50, default: 3)")
    auto.add_argument("--stealth", action="store_true",
                      help="Use slower/quieter techniques for reduced detection")
    auto.add_argument("--plugins-dir", default=None,
                      help="Additional plugins directory to scan")

    # ── Plugins mode ──────────────────────────────────────────────────────────
    plugins_parser = sub.add_parser("plugins",
        help="Plugin management (list, info)")
    plugins_parser.add_argument("--plugins-dir", default=None,
                                help="Additional plugins directory to scan")
    plugins_parser.add_argument("--list-plugins", action="store_true", default=True,
                                help="List all available plugins (default action)")

    # Add --plugins-dir and --list-plugins to attack and full modes
    for p in (attack, full):
        p.add_argument("--plugins-dir", default=None,
                       help="Additional plugins directory to scan")
        p.add_argument("--plugins", nargs="*", default=None,
                       help="Plugin names to enable (space-separated)")

    return parser


def _monitor_for_attack_key(recon_thread, scanner):
    """
    Monitor stdin for 'a' keypress to transition from recon to attack mode.

    Returns True if 'a' was pressed, False if recon ended naturally.
    Works on both Linux (select-based) and Windows (msvcrt).
    """
    import sys

    if IS_WINDOWS:
        try:
            import msvcrt
            while recon_thread.is_alive():
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch in (b'a', b'A'):
                        log.info("Attack key pressed - stopping recon...")
                        scanner.running = False
                        scanner._stop_event.set()
                        return True
                time.sleep(0.1)
        except ImportError:
            # msvcrt not available, just wait
            recon_thread.join()
    else:
        import termios
        import tty

        # Save terminal settings
        try:
            old_settings = termios.tcgetattr(sys.stdin.fileno())
        except (termios.error, ValueError, OSError):
            # Not a terminal (e.g., piped input), just wait
            recon_thread.join()
            return False

        try:
            # Set terminal to raw mode for single-char reading
            tty.setcbreak(sys.stdin.fileno())
            while recon_thread.is_alive():
                # Check if input is available (non-blocking)
                rlist, _, _ = select.select([sys.stdin], [], [], 0.2)
                if rlist:
                    ch = sys.stdin.read(1)
                    if ch in ('a', 'A'):
                        log.info("Attack key pressed - stopping recon...")
                        scanner.running = False
                        scanner._stop_event.set()
                        return True
        except (OSError, ValueError):
            recon_thread.join()
        finally:
            # Restore terminal settings
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
            except (termios.error, ValueError, OSError):
                pass

    return False


def main():
    verify_privileges()
    parser = build_parser()
    args = parser.parse_args()

    # Load config file early (before any other setup)
    config = None
    if getattr(args, 'config_file', None) or getattr(args, 'profile', None):
        from .config import load_config
        config = load_config(
            path=getattr(args, 'config_file', None),
            profile=getattr(args, 'profile', None),
        )
    else:
        # Still try to load default config file if it exists
        from .config import load_config
        config = load_config()

    if getattr(args, 'list_ifaces', False):
        list_interfaces()
        return

    # Modes that don't need an interface
    if args.mode in ("analyze", "export", "gui"):
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
            scanner.running = False
            scanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, shutdown)

    if args.mode == "recon":
        db = POSDatabase()
        scanner = None
        try:
            # Create intel enricher for background tool integration
            enricher = IntelEnricher(interface=args.interface, db=db)
            scanner = ReconEngine(args.interface, db, channels=channels,
                                  intel_enricher=enricher)
            if getattr(args, 'verbose', False):
                scanner.enable_verbose()
            log.info("Starting passive recon (Ctrl+C to stop, 'a' to stop and attack)...")

            # Run recon in a thread so we can monitor stdin for 'a' keypress
            recon_thread = threading.Thread(
                target=scanner.start, kwargs={"timeout": args.timeout}, daemon=True
            )
            recon_thread.start()

            # Monitor for 'a' keypress to transition to attack mode
            attack_requested = _monitor_for_attack_key(recon_thread, scanner)

            # Ensure scanner is stopped
            if scanner.running:
                scanner.stop()
            recon_thread.join(timeout=5)

            stats = db.get_stats()
            log.info(f"Final: {stats['access_points']} APs ({stats['pos_access_points']} POS), "
                     f"{stats['clients']} clients ({stats['pos_clients']} POS)")

            if attack_requested:
                log.info("=" * 60)
                log.info("TRANSITIONING TO ATTACK MODE (using discovered targets)")
                log.info("=" * 60)
                # Auto-transition to attack with partial recon data
                ap_iface = getattr(args, 'ap_interface', DEFAULT_AP_IFACE)
                orchestrator = AttackOrchestrator(
                    monitor_iface=args.interface,
                    ap_iface=ap_iface,
                    db=db,
                    channels=channels,
                    recon_duration=0,  # Skip recon phase - we already have data
                )
                if orchestrator.start():
                    while orchestrator.running:
                        time.sleep(1)
                else:
                    log.error("Attack failed to start (no targets found)")
                    sys.exit(1)
        except Exception as e:
            log.error(f"Recon mode error: {e}")
            sys.exit(1)
        finally:
            # Always clean up resources regardless of how we exit
            if scanner and scanner.running:
                scanner.stop()
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
            plugins=getattr(args, 'plugins', None),
            plugins_dir=getattr(args, 'plugins_dir', None),
        )
        # Load plugins if plugin system is requested
        if getattr(args, 'plugins_dir', None) or getattr(args, 'plugins', None):
            orchestrator.load_plugins()
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
            plugins=getattr(args, 'plugins', None),
            plugins_dir=getattr(args, 'plugins_dir', None),
        )
        # Load plugins if plugin system is requested
        if getattr(args, 'plugins_dir', None) or getattr(args, 'plugins', None):
            orchestrator.load_plugins()
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

    elif args.mode == "gui":
        # CLI Terminal UI (curses-based)
        from .gui import main as gui_main
        gui_main()

    elif args.mode == "auto":
        # Fully automated recon-to-attack flow
        from .attack_flow import ReconAttackFlow
        flow = ReconAttackFlow(
            interface=args.interface,
            ap_interface=args.ap_interface,
            duration=args.auto_duration,
            max_targets=args.auto_max_targets,
            stealth=getattr(args, 'stealth', False),
            use_5ghz=getattr(args, 'use_5ghz', False),
            plugins_dir=getattr(args, 'plugins_dir', None),
            config=config,
        )

        def auto_shutdown(signum, frame):
            log.info("Shutting down auto flow...")
            flow.stop()

        signal.signal(signal.SIGINT, auto_shutdown)
        if not IS_WINDOWS:
            signal.signal(signal.SIGTERM, auto_shutdown)

        results = flow.run()
        log.info(f"Auto mode complete. Results: {results}")

    elif args.mode == "plugins":
        # Plugin management mode
        from .plugin_system import PluginManager
        from pathlib import Path
        manager = PluginManager()
        dirs = [Path(args.plugins_dir)] if args.plugins_dir else []
        for d in dirs:
            if d.is_dir():
                manager.discover(d)
        status = manager.get_all_status()
        print("\nAvailable Plugins:")
        if status:
            for s in status:
                print(f"  {s['name']} v{s['version']} [{s['type']}] - {s['state']}")
        else:
            print("  No plugins loaded.")
        print()


if __name__ == "__main__":
    main()
