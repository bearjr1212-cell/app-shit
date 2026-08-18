"""
Configuration constants for the POS Recon & Attack Framework.
Cross-platform (Windows + Linux).

All timing values are in SECONDS unless otherwise noted.
All signal values are in dBm.
All port values are TCP/UDP port numbers (1-65535).
"""

import os
import sys
import logging
import tempfile

# ─── Platform Detection ──────────────────────────────────────────────────────
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

# ─── Database ─────────────────────────────────────────────────────────────────
DB_NAME = "pos_recon_data.db"
COMMIT_INTERVAL = 2  # seconds — how often to flush buffered writes to disk

# ─── Recon Thresholds ─────────────────────────────────────────────────────────
DEAUTH_THRESHOLD = 5      # number of deauths from same src before flagging as attack
DEAUTH_WINDOW = 10        # seconds — time window for deauth flood detection
CHANNEL_HOP_INTERVAL = 0.3  # seconds — delay between channel hops (0.1-2.0 recommended)
STATUS_INTERVAL = 30      # seconds — how often to print recon status summary

# ─── Deauth Attack ───────────────────────────────────────────────────────────
DEAUTH_BURST_COUNT = 5    # frames — number of deauth frames per burst (1-20)
DEAUTH_BURST_INTERVAL = 0.1  # seconds — delay between deauth bursts (0.05-1.0)

# ─── Beacon Flood ────────────────────────────────────────────────────────────
BEACON_INTERVAL = 0.1        # seconds — delay between beacon transmissions
KNOWN_BEACON_BATCH = 60      # count — SSIDs to broadcast per rotation cycle
KNOWN_BEACON_ROTATE = 20     # seconds — how often to rotate the SSID batch

# ─── Rogue AP / Captive Portal ───────────────────────────────────────────────
CAPTIVE_PORTAL_PORT = 80          # TCP port for HTTP captive portal
CAPTIVE_PORTAL_SSL_PORT = 443     # TCP port for HTTPS captive portal
NETWORK_GW_IP = os.environ.get("POSFW_NETWORK_GW", "10.0.0.1")
NETWORK_MASK = os.environ.get("POSFW_NETWORK_MASK", "255.255.255.0")
NETWORK_IP = os.environ.get("POSFW_NETWORK_IP", "10.0.0.0")
DHCP_LEASE = os.environ.get("POSFW_DHCP_LEASE", "10.0.0.2,10.0.0.100,12h")
DNS_CONF_PATH = os.path.join(tempfile.gettempdir(), "dnsmasq.conf")

# ─── Channels ────────────────────────────────────────────────────────────────
# 2.4 GHz channels 1-13 (worldwide, excluding Japan-only ch14)
CHANNELS_24GHZ = list(range(1, 14))
# 5 GHz channels (UNII-1, UNII-2, UNII-2e, UNII-3)
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]

# ─── Constants ───────────────────────────────────────────────────────────────
WIFI_BROADCAST = "ff:ff:ff:ff:ff:ff"

# ─── Default Interface Names ─────────────────────────────────────────────────
# Windows: "WiFi" = Intel Dual Band Wireless-AC 7260 (monitor/capture)
#          "WiFi 2" = Broadcom 802.11n (AP/injection)
DEFAULT_MONITOR_IFACE = "WiFi" if IS_WINDOWS else "wlan0mon"
DEFAULT_AP_IFACE = "WiFi 2" if IS_WINDOWS else "wlan1"

# ─── Monitor Mode Settings ───────────────────────────────────────────────────
MONITOR_MODE_RETRY_COUNT = 3   # attempts — retries per method before trying next
MONITOR_MODE_RETRY_DELAY = 2   # seconds — delay between retry attempts

# ─── KRACK Attack ─────────────────────────────────────────────────────────────
KRACK_REPLAY_COUNT = 3         # frames — number of msg3 replays per attempt
KRACK_MAX_MSG3_REPLAYS = 10    # attempts — safety limit on total replay attempts

# ─── WiFi DoS ────────────────────────────────────────────────────────────────
DOS_CTS_INTERVAL = 0.01       # seconds — inter-packet delay for CTS flood
DOS_BEACON_INTERVAL = 0.005   # seconds — inter-packet delay for beacon exhaust
DOS_QOS_INTERVAL = 0.02       # seconds — inter-packet delay for QoS null
DOS_FRAGMENT_INTERVAL = 0.01  # seconds — inter-packet delay for fragmentation attack

# ─── Printer Exploitation ────────────────────────────────────────────────────
PRINTER_SCAN_TIMEOUT = 30      # seconds — per-host scan timeout
IPP_DEFAULT_PORT = 631         # TCP port — Internet Printing Protocol
PRINTER_RAW_PORT = 9100        # TCP port — raw printing (JetDirect)
LPD_PORT = 515                 # TCP port — Line Printer Daemon
SNMP_DEFAULT_PORT = 161        # UDP port — SNMP queries
PRINTER_SNMP_COMMUNITY = "public"  # SNMP community string for discovery
PRINTER_HTTP_TIMEOUT = 5       # seconds — HTTP request timeout for printer web UIs

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("POSFramework")


# ─── Config File Loading ─────────────────────────────────────────────────────

def load_config(path=None, profile=None):
    """
    Load configuration from a YAML file and update module-level constants.

    Uses ConfigLoader to read a YAML config file, then updates the
    module-level constants in this module with the loaded values.
    Existing defaults serve as fallbacks for any values not specified
    in the config file.

    Args:
        path: Path to a YAML config file. If None, searches default locations.
        profile: Name of a profile to activate for overrides.

    Returns:
        The ConfigLoader instance for further access.
    """
    from .config_loader import ConfigLoader

    config = ConfigLoader(config_path=path, profile=profile)

    # Update module-level constants from loaded config
    global CHANNEL_HOP_INTERVAL, STATUS_INTERVAL
    global DEAUTH_BURST_COUNT, DEAUTH_BURST_INTERVAL
    global BEACON_INTERVAL
    global CAPTIVE_PORTAL_PORT, CAPTIVE_PORTAL_SSL_PORT
    global NETWORK_GW_IP, NETWORK_MASK, NETWORK_IP, DHCP_LEASE
    global DEFAULT_MONITOR_IFACE, DEFAULT_AP_IFACE

    CHANNEL_HOP_INTERVAL = config.get("recon.channel_hop_interval", CHANNEL_HOP_INTERVAL)
    STATUS_INTERVAL = config.get("recon.status_interval", STATUS_INTERVAL)
    DEAUTH_BURST_COUNT = config.get("attack.deauth_burst_count", DEAUTH_BURST_COUNT)
    DEAUTH_BURST_INTERVAL = config.get("attack.deauth_burst_interval", DEAUTH_BURST_INTERVAL)
    BEACON_INTERVAL = config.get("attack.beacon_interval", BEACON_INTERVAL)
    CAPTIVE_PORTAL_PORT = config.get("rogue_ap.captive_portal_port", CAPTIVE_PORTAL_PORT)
    CAPTIVE_PORTAL_SSL_PORT = config.get("rogue_ap.captive_portal_ssl_port", CAPTIVE_PORTAL_SSL_PORT)

    # Only update network settings if they resolve to non-empty values
    gw = config.get("rogue_ap.network_gw_ip", "")
    if gw:
        NETWORK_GW_IP = gw
    mask = config.get("rogue_ap.network_mask", "")
    if mask:
        NETWORK_MASK = mask
    net_ip = config.get("rogue_ap.network_ip", "")
    if net_ip:
        NETWORK_IP = net_ip
    lease = config.get("rogue_ap.dhcp_lease", "")
    if lease:
        DHCP_LEASE = lease

    # Update interface defaults
    iface = config.get("general.interface", None)
    if iface:
        DEFAULT_MONITOR_IFACE = iface
    ap_iface = config.get("general.ap_interface", None)
    if ap_iface:
        DEFAULT_AP_IFACE = ap_iface

    return config


def dump_effective_config():
    """
    Print the current effective configuration to the log.

    Useful for debugging to see which values are active after config
    file loading and environment variable resolution. Sensitive network
    details (IPs, ports) are included since this is an attack tool
    where the operator needs full visibility.

    Returns:
        Dictionary of all effective configuration values.
    """
    effective = {
        "platform": "windows" if IS_WINDOWS else ("linux" if IS_LINUX else "unknown"),
        "database": {
            "db_name": DB_NAME,
            "commit_interval_s": COMMIT_INTERVAL,
        },
        "recon": {
            "deauth_threshold": DEAUTH_THRESHOLD,
            "deauth_window_s": DEAUTH_WINDOW,
            "channel_hop_interval_s": CHANNEL_HOP_INTERVAL,
            "status_interval_s": STATUS_INTERVAL,
            "channels_24ghz": CHANNELS_24GHZ,
            "channels_5ghz_count": len(CHANNELS_5GHZ),
        },
        "attack": {
            "deauth_burst_count": DEAUTH_BURST_COUNT,
            "deauth_burst_interval_s": DEAUTH_BURST_INTERVAL,
            "beacon_interval_s": BEACON_INTERVAL,
            "known_beacon_batch": KNOWN_BEACON_BATCH,
            "known_beacon_rotate_s": KNOWN_BEACON_ROTATE,
        },
        "rogue_ap": {
            "captive_portal_port": CAPTIVE_PORTAL_PORT,
            "captive_portal_ssl_port": CAPTIVE_PORTAL_SSL_PORT,
            "network_gw_ip": NETWORK_GW_IP,
            "network_mask": NETWORK_MASK,
            "network_ip": NETWORK_IP,
            "dhcp_lease": DHCP_LEASE,
        },
        "interfaces": {
            "monitor": DEFAULT_MONITOR_IFACE,
            "ap": DEFAULT_AP_IFACE,
        },
        "monitor_mode": {
            "retry_count": MONITOR_MODE_RETRY_COUNT,
            "retry_delay_s": MONITOR_MODE_RETRY_DELAY,
        },
        "krack": {
            "replay_count": KRACK_REPLAY_COUNT,
            "max_msg3_replays": KRACK_MAX_MSG3_REPLAYS,
        },
        "dos": {
            "cts_interval_s": DOS_CTS_INTERVAL,
            "beacon_interval_s": DOS_BEACON_INTERVAL,
            "qos_interval_s": DOS_QOS_INTERVAL,
            "fragment_interval_s": DOS_FRAGMENT_INTERVAL,
        },
        "printer": {
            "scan_timeout_s": PRINTER_SCAN_TIMEOUT,
            "ipp_port": IPP_DEFAULT_PORT,
            "raw_port": PRINTER_RAW_PORT,
            "ldp_port": LPD_PORT,
            "snmp_port": SNMP_DEFAULT_PORT,
            "snmp_community": PRINTER_SNMP_COMMUNITY,
            "http_timeout_s": PRINTER_HTTP_TIMEOUT,
        },
    }

    log.info("═" * 50)
    log.info("EFFECTIVE CONFIGURATION")
    log.info("═" * 50)
    for section, values in effective.items():
        if isinstance(values, dict):
            log.info(f"  [{section}]")
            for key, val in values.items():
                log.info(f"    {key} = {val}")
        else:
            log.info(f"  {section} = {values}")
    log.info("═" * 50)

    return effective
