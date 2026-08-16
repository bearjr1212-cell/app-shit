"""
Configuration constants for the POS Recon & Attack Framework.
Cross-platform (Windows + Linux).
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
COMMIT_INTERVAL = 2

# ─── Recon Thresholds ─────────────────────────────────────────────────────────
DEAUTH_THRESHOLD = 5
DEAUTH_WINDOW = 10
CHANNEL_HOP_INTERVAL = 0.3
STATUS_INTERVAL = 30

# ─── Deauth Attack ───────────────────────────────────────────────────────────
DEAUTH_BURST_COUNT = 5
DEAUTH_BURST_INTERVAL = 0.1

# ─── Beacon Flood ────────────────────────────────────────────────────────────
BEACON_INTERVAL = 0.1
KNOWN_BEACON_BATCH = 60
KNOWN_BEACON_ROTATE = 20

# ─── Rogue AP / Captive Portal ───────────────────────────────────────────────
CAPTIVE_PORTAL_PORT = 80
CAPTIVE_PORTAL_SSL_PORT = 443
NETWORK_GW_IP = os.environ.get("POSFW_NETWORK_GW", "10.0.0.1")
NETWORK_MASK = os.environ.get("POSFW_NETWORK_MASK", "255.255.255.0")
NETWORK_IP = os.environ.get("POSFW_NETWORK_IP", "10.0.0.0")
DHCP_LEASE = os.environ.get("POSFW_DHCP_LEASE", "10.0.0.2,10.0.0.100,12h")
DNS_CONF_PATH = os.path.join(tempfile.gettempdir(), "dnsmasq.conf")

# ─── Channels ────────────────────────────────────────────────────────────────
CHANNELS_24GHZ = list(range(1, 15))
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
MONITOR_MODE_RETRY_COUNT = 3
MONITOR_MODE_RETRY_DELAY = 2

# ─── KRACK Attack ─────────────────────────────────────────────────────────────
KRACK_REPLAY_COUNT = 3
KRACK_MAX_MSG3_REPLAYS = 10

# ─── WiFi DoS ────────────────────────────────────────────────────────────────
DOS_CTS_INTERVAL = 0.01
DOS_BEACON_INTERVAL = 0.005
DOS_QOS_INTERVAL = 0.02
DOS_FRAGMENT_INTERVAL = 0.01

# ─── Printer Exploitation ────────────────────────────────────────────────────
PRINTER_SCAN_TIMEOUT = 30
IPP_DEFAULT_PORT = 631
PRINTER_RAW_PORT = 9100
LPD_PORT = 515
SNMP_DEFAULT_PORT = 161
PRINTER_SNMP_COMMUNITY = "public"
PRINTER_HTTP_TIMEOUT = 5

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("POSFramework")
