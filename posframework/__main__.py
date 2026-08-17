"""
POS Framework — CLI Entry Point
────────────────────────────────────────────────────────────────────────────────
Lean, fully-automated wireless security assessment CLI.
Zero-config operation with intelligent auto-detection and auto-targeting.

Usage:
  sudo python3 -m posframework full                     # Zero-config kill chain
  sudo python3 -m posframework full --profile stealth   # Named profile
  sudo python3 -m posframework recon --auto-iface       # Passive recon only
  sudo python3 -m posframework config-gen               # Generate YAML from recon
  sudo python3 -m posframework attack -t AA:BB:CC:DD:EE:FF
  sudo python3 -m posframework iface                    # Show interfaces
  sudo python3 -m posframework analyze                  # Post-attack analysis
  sudo python3 -m posframework export -o results/       # Export findings
  sudo python3 -m posframework plugins                  # List available plugins

Subcommands:
  recon       Passive 802.11 scan (populate database)
  attack      Targeted attack using recon data
  full        Zero-config automated operation (recon → target → attack)
  config-gen  Generate YAML config from live recon data
  iface       Interface discovery and capability report
  analyze     Post-attack analysis and reporting
  export      Export captured data (creds, handshakes, reports)
  plugins     Plugin management and listing
"""

import os
import sys
import signal
import time
import argparse
import atexit
import ctypes

from .config import (
    DB_NAME, CHANNELS_24GHZ, CHANNELS_5GHZ, IS_WINDOWS, IS_LINUX,
    DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE, log,
)
from .database import POSDatabase
from .recon import ReconEngine
from .orchestrator import AttackOrchestrator
from .interface_manager import auto_detect_interfaces, setup_dual_interfaces, InterfaceManager


# ─── Global State ─────────────────────────────────────────────────────────────

_active_interface_manager = None


# ─── Privilege & Interface Helpers ────────────────────────────────────────────

def _is_admin() -> bool:
    """Check for elevated privileges (cross-platform)."""
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.getuid() == 0


def _verify_privileges():
    """Exit if not running as root/admin."""
    if not _is_admin():
        if IS_WINDOWS:
            sys.exit("ERROR: Requires Administrator. Right-click terminal → 'Run as Administrator'.")
        else:
            sys.exit("ERROR: Requires root. Run with sudo.")


def _interface_exists(iface: str) -> bool:
    """Check if a wireless interface exists without exiting."""
    if IS_WINDOWS:
        return os.path.isdir(r"C:\Windows\System32\Npcap")
    try:
        import subprocess
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _verify_interface(iface: str):
    """Verify interface exists; exit with helpful message on failure."""
    import subprocess
    if IS_WINDOWS:
        npcap_path = r"C:\Windows\System32\Npcap"
        if not os.path.isdir(npcap_path):
            sys.exit("ERROR: Npcap not found. Install from https://npcap.com/")
        log.info(f"Interface: {iface} (Npcap detected)")
    else:
        try:
            r = subprocess.run(["iw", "dev", iface, "info"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                sys.exit(f"ERROR: Interface '{iface}' not found. Use 'iface' subcommand to discover.")
        except FileNotFoundError:
            sys.exit("ERROR: 'iw' not found. Install: sudo apt install iw")
        except subprocess.TimeoutExpired:
            pass


def _teardown_interfaces():
    """Atexit handler: restore interfaces to original state."""
    global _active_interface_manager
    if _active_interface_manager is not None:
        try:
            log.info("Restoring interfaces to original state...")
            _active_interface_manager.teardown()
        except Exception as e:
            log.warning(f"Interface teardown error: {e}")
        finally:
            _active_interface_manager = None


def _resolve_interfaces(args) -> bool:
    """
    Resolve interface assignments via auto-detection when needed.

    Auto-detection triggers when:
      - --auto-iface flag is set, OR
      - No explicit -i given AND the default monitor interface doesn't exist

    Returns True if auto-detection handled interfaces (skip verify_interface).
    """
    global _active_interface_manager

    auto_iface = getattr(args, 'auto_iface', False)
    has_explicit_iface = getattr(args, '_explicit_interface', False)
    has_explicit_ap = getattr(args, '_explicit_ap_interface', False)

    should_auto = False
    if auto_iface:
        should_auto = True
    elif not has_explicit_iface:
        iface = getattr(args, 'interface', DEFAULT_MONITOR_IFACE)
        if not _interface_exists(iface):
            log.info(f"Default interface '{iface}' not found — triggering auto-detection.")
            should_auto = True

    if not should_auto:
        return False

    prefer_monitor = args.interface if has_explicit_iface else None
    prefer_ap = getattr(args, 'ap_interface', None) if has_explicit_ap else None

    log.info("Running interface auto-detection...")
    monitor_name, ap_name, manager = setup_dual_interfaces(
        prefer_monitor=prefer_monitor,
        prefer_ap=prefer_ap,
    )

    if monitor_name is None:
        log.error("Auto-detection failed: no suitable monitor interface found.")
        sys.exit(1)

    args.interface = monitor_name
    if hasattr(args, 'ap_interface') and ap_name:
        args.ap_interface = ap_name

    _active_interface_manager = manager
    atexit.register(_teardown_interfaces)

    log.info(f"Monitor interface: {monitor_name}")
    if ap_name:
        log.info(f"AP interface: {ap_name}")

    return True


def _resolve_channels(args) -> list:
    """Determine channel list from --channels argument."""
    ch = getattr(args, 'channels', '2.4ghz')
    if ch == 'all':
        return CHANNELS_24GHZ + CHANNELS_5GHZ
    elif ch == '5ghz':
        return CHANNELS_5GHZ
    return CHANNELS_24GHZ


def _resolve_output_dir(args):
    """Ensure output directory exists."""
    output_dir = getattr(args, 'output_dir', None)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    return output_dir or 'exports'


# ─── Custom argparse Action ──────────────────────────────────────────────────

class _TrackExplicitAction(argparse.Action):
    """Track whether user explicitly provided -i or -a."""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, f'_explicit_{self.dest}', True)


# ─── Attack Options (shared between attack/full parsers) ─────────────────────

def _add_attack_options(parser):
    """Add all configurable attack options to a subparser."""
    grp = parser.add_argument_group("attack configuration")
    grp.add_argument("--recon-time", type=int, default=30, metavar="SEC",
                     help="Recon duration in seconds (default: 30)")
    grp.add_argument("--rssi-limit", type=int, default=-80, metavar="DBM",
                     help="Min RSSI for targeting (default: -80)")
    grp.add_argument("--deauth-burst", type=int, default=5, metavar="N",
                     help="Deauth frames per burst (default: 5)")
    grp.add_argument("--beacon-interval", type=float, default=0.1, metavar="SEC",
                     help="Beacon flood interval (default: 0.1)")
    grp.add_argument("--ap-mode", choices=["captive", "bridge", "hybrid"],
                     default="bridge", help="Rogue AP mode (default: bridge)")
    grp.add_argument("--enable-karma", action="store_true", default=True,
                     help="Enable KARMA probe response (default: enabled)")
    grp.add_argument("--no-karma", action="store_true",
                     help="Disable KARMA attack")
    grp.add_argument("--enable-krack", action="store_true", default=False,
                     help="Enable KRACK attack on captured handshakes")
    grp.add_argument("--no-krack", action="store_true",
                     help="Disable KRACK attack")
    grp.add_argument("--enable-dos", action="store_true", default=False,
                     help="Enable WiFi DoS module")
    grp.add_argument("--dos-mode", choices=["cts_flood", "beacon_exhaust", "qos_null", "fragment"],
                     default="cts_flood", help="DoS mode (default: cts_flood)")
    grp.add_argument("--enable-printers", action="store_true", default=False,
                     help="Enable printer exploitation modules")
    grp.add_argument("--no-printers", action="store_true",
                     help="Disable printer attacks")
    grp.add_argument("-t", "--target", default=None, metavar="BSSID",
                     help="Target BSSID (auto-selected from recon if omitted)")
    grp.add_argument("--channels", choices=["2.4ghz", "5ghz", "all"],
                     default="2.4ghz", help="Channel range (default: 2.4ghz)")
    grp.add_argument("--test-creds", action="store_true", default=False,
                     help="Auto-test captured credentials against real AP")
    grp.add_argument("--no-beacons", action="store_true",
                     help="Disable beacon flooding")
    grp.add_argument("--enable-ap-clone", action="store_true", default=False,
                     help="Clone target AP after deauth")
    grp.add_argument("--enable-client-isolation", action="store_true", default=False,
                     help="Enable client isolation attack")

    plg = parser.add_argument_group("plugins")
    plg.add_argument("--plugins-dir", default=None, metavar="DIR",
                     help="Additional plugins directory")
    plg.add_argument("--plugins", nargs="*", default=None, metavar="NAME",
                     help="Plugin names to enable (space-separated)")


# ─── Parser Construction ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the complete argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="posframework",
        description="POS Framework — Automated Wireless Security Assessment",
        epilog="Run 'posframework full' for zero-config automated operation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Global options ────────────────────────────────────────────────────────
    parser.add_argument("-c", "--config", dest="config_file", default=None,
                        metavar="FILE", help="Load YAML config file")
    parser.add_argument("-p", "--profile", default=None,
                        choices=["stealth", "aggressive", "recon-only"],
                        help="Activate named profile")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show planned actions without executing")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Minimal output (errors only)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show all packets)")
    parser.add_argument("-o", "--output-dir", default=None, metavar="DIR",
                        help="Output directory for reports/handshakes/exports")

    sub = parser.add_subparsers(dest="mode", required=True,
                                metavar="COMMAND")

    # ── recon ─────────────────────────────────────────────────────────────────
    recon = sub.add_parser("recon", help="Passive 802.11 scan (populate database)")
    recon.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE,
                       action=_TrackExplicitAction,
                       help=f"Monitor interface (default: {DEFAULT_MONITOR_IFACE})")
    recon.add_argument("--auto-iface", action="store_true",
                       help="Auto-detect and assign interfaces")
    recon.add_argument("--channels", choices=["2.4ghz", "5ghz", "all"],
                       default="2.4ghz", help="Channel range (default: 2.4ghz)")
    recon.add_argument("--timeout", type=int, default=None, metavar="SEC",
                       help="Scan duration in seconds (infinite if omitted)")

    # ── attack ────────────────────────────────────────────────────────────────
    attack = sub.add_parser("attack",
        help="Targeted attack using recon data (quick recon if DB empty)")
    attack.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE,
                        action=_TrackExplicitAction,
                        help=f"Monitor interface (default: {DEFAULT_MONITOR_IFACE})")
    attack.add_argument("-a", "--ap-interface", default=DEFAULT_AP_IFACE,
                        action=_TrackExplicitAction,
                        help=f"AP interface (default: {DEFAULT_AP_IFACE})")
    attack.add_argument("--auto-iface", action="store_true",
                        help="Auto-detect and assign interfaces")
    _add_attack_options(attack)

    # ── full (primary mode — zero-config) ─────────────────────────────────────
    full = sub.add_parser("full",
        help="Zero-config automated kill chain (recon → target → attack)")
    full.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE,
                      action=_TrackExplicitAction,
                      help=f"Monitor interface (default: {DEFAULT_MONITOR_IFACE})")
    full.add_argument("-a", "--ap-interface", default=DEFAULT_AP_IFACE,
                      action=_TrackExplicitAction,
                      help=f"AP interface (default: {DEFAULT_AP_IFACE})")
    full.add_argument("--auto-iface", action="store_true", default=True,
                      help="Auto-detect interfaces (default: enabled)")
    _add_attack_options(full)
    # Override recon-time default for full mode (longer scan)
    for action in full._actions:
        if '--recon-time' in getattr(action, 'option_strings', []):
            action.default = 60

    # ── config-gen ────────────────────────────────────────────────────────────
    config_gen = sub.add_parser("config-gen",
        help="Generate YAML config from live recon data")
    config_gen.add_argument("-i", "--interface", default=DEFAULT_MONITOR_IFACE,
                            action=_TrackExplicitAction,
                            help=f"Monitor interface (default: {DEFAULT_MONITOR_IFACE})")
    config_gen.add_argument("--auto-iface", action="store_true", default=True,
                            help="Auto-detect interfaces (default: enabled)")
    config_gen.add_argument("--recon-time", type=int, default=15, metavar="SEC",
                            help="Quick recon duration (default: 15s)")
    config_gen.add_argument("--output", default="posframework.yaml", metavar="FILE",
                            help="Output YAML file (default: posframework.yaml)")

    # ── iface ─────────────────────────────────────────────────────────────────
    iface = sub.add_parser("iface",
        help="Discover and display wireless interface capabilities")
    iface.add_argument("--prefer-monitor", default=None, metavar="IFACE",
                       help="Prefer this interface for monitor role")
    iface.add_argument("--prefer-ap", default=None, metavar="IFACE",
                       help="Prefer this interface for AP role")
    iface.add_argument("--json", dest="output_json", action="store_true",
                       help="Output as JSON")

    # ── analyze ───────────────────────────────────────────────────────────────
    analyze = sub.add_parser("analyze",
        help="Post-attack analysis and reporting")
    analyze.add_argument("-d", "--db", default=DB_NAME, metavar="FILE",
                         help=f"Database file (default: {DB_NAME})")

    # ── export ────────────────────────────────────────────────────────────────
    export = sub.add_parser("export",
        help="Export captured data (credentials, handshakes)")
    export.add_argument("-d", "--db", default=DB_NAME, metavar="FILE",
                        help=f"Database file (default: {DB_NAME})")
    export.add_argument("--format", choices=["json", "csv", "pcap"],
                        default="json", help="Export format (default: json)")

    # ── plugins ───────────────────────────────────────────────────────────────
    plugins_p = sub.add_parser("plugins",
        help="List and manage attack plugins")
    plugins_p.add_argument("--plugins-dir", default=None, metavar="DIR",
                           help="Additional plugins directory")
    plugins_p.add_argument("--info", default=None, metavar="NAME",
                           help="Show detailed info about a specific plugin")

    return parser


# ─── Config Loading ──────────────────────────────────────────────────────────

def _load_config(args):
    """
    Load YAML config and apply profile overlays.
    CLI arguments always take precedence over config file values.
    """
    from .config import load_config
    config = load_config(
        path=getattr(args, 'config_file', None),
        profile=getattr(args, 'profile', None),
    )
    return config


# ─── Config Generation ───────────────────────────────────────────────────────

def _run_config_gen(args):
    """
    Run a quick recon and generate a YAML config with auto-filled parameters.

    Produces posframework.yaml with:
      - interfaces (auto-detected)
      - target (strongest POS AP, or strongest AP)
      - channels (from target's band)
      - attack modules (based on what's detected)
    """
    channels = _resolve_channels(args)

    # Auto-detect interfaces
    auto_handled = _resolve_interfaces(args)
    if not auto_handled:
        _verify_interface(args.interface)

    log.info(f"Running quick {args.recon_time}s recon for config generation...")
    db = POSDatabase()
    scanner = ReconEngine(args.interface, db, channels=channels)
    scanner.start(timeout=args.recon_time)
    scanner.stop()

    stats = db.get_stats()
    log.info(f"Recon complete: {stats['access_points']} APs, {stats['pos_access_points']} POS")

    # Select best target: prefer strongest POS AP, fallback to strongest AP
    target_bssid = None
    target_ssid = None
    target_channel = None

    # Try POS APs first
    # get_pos_access_points() returns tuples: (bssid, ssid, channel, vendor, security, rssi)
    try:
        pos_aps = db.get_pos_access_points()
        if pos_aps:
            best = max(pos_aps, key=lambda ap: ap[5] if ap[5] is not None else -100)
            target_bssid = best[0]
            target_ssid = best[1] or 'Unknown'
            target_channel = best[2] or 1
    except Exception:
        pass

    # Fallback to any AP
    # get_strongest_ap() returns a single tuple: (bssid, ssid, channel, vendor, rssi)
    if not target_bssid:
        try:
            best = db.get_strongest_ap()
            if best:
                target_bssid = best[0]
                target_ssid = best[1] or 'Unknown'
                target_channel = best[2] or 1
        except Exception:
            pass

    db.close()

    # Determine channel band from target
    if target_channel and target_channel > 14:
        channel_band = "5ghz"
    elif target_channel:
        channel_band = "2.4ghz"
    else:
        channel_band = "all"

    # Determine attack modules
    enable_printers = stats.get('pos_access_points', 0) > 0

    # Build YAML config
    config_data = {
        "general": {
            "interface": getattr(args, 'interface', DEFAULT_MONITOR_IFACE),
            "ap_interface": getattr(args, 'ap_interface', DEFAULT_AP_IFACE),
            "channels": channel_band,
            "output_dir": "exports",
        },
        "target": {
            "bssid": target_bssid,
            "ssid": target_ssid,
            "channel": target_channel,
            "auto_select": target_bssid is None,
        },
        "recon": {
            "timeout": 30,
            "rssi_limit": -80,
        },
        "attack": {
            "deauth_burst": 5,
            "beacon_interval": 0.1,
            "ap_mode": "bridge",
            "enable_karma": True,
            "enable_krack": False,
            "enable_dos": False,
            "dos_mode": "cts_flood",
            "enable_printers": enable_printers,
            "enable_ap_clone": True,
            "enable_client_isolation": False,
            "test_creds": True,
        },
        "plugins": {
            "enabled": [],
            "plugins_dir": None,
        },
    }

    # Write YAML
    output_file = args.output
    try:
        import yaml
        with open(output_file, 'w') as f:
            f.write("# POS Framework Configuration\n")
            f.write(f"# Auto-generated from {args.recon_time}s recon scan\n")
            f.write(f"# Target: {target_ssid or 'auto'} ({target_bssid or 'auto-select'})\n")
            f.write("#\n")
            f.write("# Usage: sudo python3 -m posframework full -c posframework.yaml\n\n")
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
        log.info(f"Config written to: {output_file}")
        if target_bssid:
            log.info(f"Target: {target_ssid} ({target_bssid}) on channel {target_channel}")
        else:
            log.warning("No targets found — config set to auto-select mode.")
    except ImportError:
        # Fallback: write as formatted text if PyYAML not available
        log.warning("PyYAML not installed — writing config as plain text.")
        with open(output_file, 'w') as f:
            f.write(f"# POS Framework Configuration (install PyYAML for proper format)\n")
            f.write(f"# Target: {target_ssid or 'auto'} ({target_bssid or 'auto-select'})\n\n")
            for section, values in config_data.items():
                f.write(f"{section}:\n")
                for key, val in values.items():
                    f.write(f"  {key}: {val}\n")
                f.write("\n")
        log.info(f"Config written to: {output_file}")


# ─── Dry-Run Display ────────────────────────────────────────────────────────

def _show_dry_run(args, channels):
    """Display planned actions without executing."""
    print("\n" + "=" * 60)
    print("  DRY RUN — Planned Actions")
    print("=" * 60)
    print(f"  Mode:           {args.mode}")
    print(f"  Interface:      {getattr(args, 'interface', 'N/A')}")
    print(f"  AP Interface:   {getattr(args, 'ap_interface', 'N/A')}")
    print(f"  Channels:       {getattr(args, 'channels', '2.4ghz')} ({len(channels)} channels)")
    print(f"  Target:         {getattr(args, 'target', None) or 'auto-select'}")
    print(f"  Recon Time:     {getattr(args, 'recon_time', 30)}s")
    print(f"  RSSI Limit:     {getattr(args, 'rssi_limit', -80)} dBm")
    print(f"  Deauth Burst:   {getattr(args, 'deauth_burst', 5)} frames")
    print(f"  Beacon Interval:{getattr(args, 'beacon_interval', 0.1)}s")
    print(f"  AP Mode:        {getattr(args, 'ap_mode', 'bridge')}")
    print(f"  KARMA:          {'disabled' if getattr(args, 'no_karma', False) else 'enabled'}")
    print(f"  KRACK:          {'enabled' if getattr(args, 'enable_krack', False) else 'disabled'}")
    print(f"  DoS:            {'enabled' if getattr(args, 'enable_dos', False) else 'disabled'}")
    print(f"  Printers:       {'enabled' if getattr(args, 'enable_printers', False) else 'disabled'}")
    print(f"  AP Clone:       {'enabled' if getattr(args, 'enable_ap_clone', False) else 'disabled'}")
    print(f"  Test Creds:     {'yes' if getattr(args, 'test_creds', False) else 'no'}")
    print(f"  Profile:        {getattr(args, 'profile', None) or 'default'}")
    print(f"  Output Dir:     {getattr(args, 'output_dir', None) or 'exports/'}")

    plugins = getattr(args, 'plugins', None)
    if plugins:
        print(f"  Plugins:        {', '.join(plugins)}")

    print("=" * 60)
    print("  No actions executed (--dry-run mode).")
    print("=" * 60 + "\n")


# ─── Subcommand Handlers ────────────────────────────────────────────────────

def _run_recon(args):
    """Execute passive recon scan."""
    channels = _resolve_channels(args)

    auto_handled = _resolve_interfaces(args)
    if not auto_handled:
        _verify_interface(args.interface)

    if getattr(args, 'dry_run', False):
        _show_dry_run(args, channels)
        return

    db = POSDatabase()
    scanner = ReconEngine(args.interface, db, channels=channels)

    if getattr(args, 'verbose', False):
        scanner.enable_verbose()

    log.info(f"Starting passive recon on {args.interface} (Ctrl+C to stop)...")
    scanner.start(timeout=args.timeout)
    scanner.stop()

    stats = db.get_stats()
    log.info(f"Results: {stats['access_points']} APs ({stats['pos_access_points']} POS), "
             f"{stats['clients']} clients ({stats['pos_clients']} POS)")
    db.close()


def _run_attack(args):
    """Execute targeted attack."""
    channels = _resolve_channels(args)

    auto_handled = _resolve_interfaces(args)
    if not auto_handled:
        _verify_interface(args.interface)

    if getattr(args, 'dry_run', False):
        _show_dry_run(args, channels)
        return

    output_dir = _resolve_output_dir(args)

    orchestrator = AttackOrchestrator(
        monitor_iface=args.interface,
        ap_iface=args.ap_interface,
        channels=channels,
        target_bssid=getattr(args, 'target', None),
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
        enable_printer_attacks=getattr(args, 'enable_printers', False),
        plugins=getattr(args, 'plugins', None),
        plugins_dir=getattr(args, 'plugins_dir', None),
    )

    if getattr(args, 'plugins_dir', None) or getattr(args, 'plugins', None):
        orchestrator.load_plugins()

    if orchestrator.start():
        while orchestrator.running:
            time.sleep(1)
    else:
        sys.exit(1)


def _run_full(args):
    """
    Zero-config automated operation: recon → target → attack.

    This is the primary mode. With no arguments it will:
      1. Auto-detect interfaces
      2. Run recon
      3. Auto-select best target from results
      4. Auto-configure all attack parameters
      5. Execute the full kill chain
    """
    channels = _resolve_channels(args)

    auto_handled = _resolve_interfaces(args)
    if not auto_handled:
        _verify_interface(args.interface)

    if getattr(args, 'dry_run', False):
        _show_dry_run(args, channels)
        return

    output_dir = _resolve_output_dir(args)
    log.info("Full automated mode — zero-config kill chain engaged.")

    orchestrator = AttackOrchestrator(
        monitor_iface=args.interface,
        ap_iface=args.ap_interface,
        channels=channels,
        target_bssid=getattr(args, 'target', None),
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
        enable_printer_attacks=getattr(args, 'enable_printers', False),
        plugins=getattr(args, 'plugins', None),
        plugins_dir=getattr(args, 'plugins_dir', None),
    )

    if getattr(args, 'plugins_dir', None) or getattr(args, 'plugins', None):
        orchestrator.load_plugins()

    if orchestrator.start():
        while orchestrator.running:
            time.sleep(1)
    else:
        sys.exit(1)


def _run_iface(args):
    """Display interface discovery results."""
    assignment = auto_detect_interfaces(
        prefer_monitor=args.prefer_monitor,
        prefer_ap=args.prefer_ap,
    )

    if getattr(args, 'output_json', False):
        import json
        result = {
            "monitor": assignment.monitor_name,
            "ap": assignment.ap_name,
            "complete": assignment.is_complete,
            "errors": assignment.errors,
        }
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "=" * 60)
        print("  Interface Auto-Discovery Results")
        print("=" * 60)
        print(assignment.summary())
        if assignment.errors:
            print("\nErrors:")
            for err in assignment.errors:
                print(f"  ⚠ {err}")
        print("=" * 60 + "\n")


def _run_analyze(args):
    """Post-attack analysis and reporting."""
    from .post_attack import PostAttackAnalyzer

    output_dir = _resolve_output_dir(args)
    db = POSDatabase(args.db)
    analyzer = PostAttackAnalyzer(db)

    if getattr(args, 'quiet', False):
        analyzer.export_credentials(os.path.join(output_dir, "credentials.json"))
        analyzer.export_handshakes()
        analyzer.generate_report(os.path.join(output_dir, "attack_report.json"))
    else:
        analyzer.print_summary()
        analyzer.export_credentials(os.path.join(output_dir, "credentials.json"))
        analyzer.export_handshakes()
        analyzer.generate_report(os.path.join(output_dir, "attack_report.json"))

    db.close()
    log.info(f"Analysis complete. Reports saved to {output_dir}/")


def _run_export(args):
    """Export captured data."""
    from .post_attack import PostAttackAnalyzer

    output_dir = _resolve_output_dir(args)
    db = POSDatabase(args.db)
    analyzer = PostAttackAnalyzer(db)

    fmt = getattr(args, 'format', 'json')
    analyzer.export_credentials(os.path.join(output_dir, f"credentials.{fmt}"))
    analyzer.export_handshakes()

    db.close()
    log.info(f"Export complete ({fmt} format). Files in {output_dir}/")


def _run_plugins(args):
    """List and manage plugins."""
    from .plugin_loader import PluginLoader

    dirs = [args.plugins_dir] if args.plugins_dir else None
    loader = PluginLoader(plugin_dirs=dirs)
    loader.discover()

    if getattr(args, 'info', None):
        # Show detailed info about a specific plugin
        info = loader.get_plugin_info(args.info) if hasattr(loader, 'get_plugin_info') else None
        if info:
            print(f"\nPlugin: {args.info}")
            for k, v in info.items():
                print(f"  {k}: {v}")
            print()
        else:
            print(f"Plugin '{args.info}' not found.")
    else:
        table = loader.print_plugin_table()
        print("\nAvailable Plugins:")
        print(table)
        categories = loader.list_categories()
        if categories:
            print(f"\nCategories: {', '.join(f'{k}({v})' for k, v in categories.items())}")
        print()


# ─── Main Entry Point ────────────────────────────────────────────────────────

def main():
    """CLI entry point."""
    _verify_privileges()
    parser = build_parser()
    args = parser.parse_args()

    # Initialize tracking attributes if not set by _TrackExplicitAction
    if not hasattr(args, '_explicit_interface'):
        args._explicit_interface = False
    if not hasattr(args, '_explicit_ap_interface'):
        args._explicit_ap_interface = False

    # Load config file (CLI args override config values)
    _load_config(args)

    # Configure logging level
    if getattr(args, 'quiet', False):
        import logging
        log.setLevel(logging.ERROR)
    elif getattr(args, 'verbose', False):
        import logging
        log.setLevel(logging.DEBUG)

    # Signal handling
    orchestrator_ref = [None]

    def shutdown(signum, frame):
        log.info("Shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, shutdown)

    # Dispatch to subcommand handler
    handlers = {
        "recon": _run_recon,
        "attack": _run_attack,
        "full": _run_full,
        "config-gen": _run_config_gen,
        "iface": _run_iface,
        "analyze": _run_analyze,
        "export": _run_export,
        "plugins": _run_plugins,
    }

    handler = handlers.get(args.mode)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
