#!/bin/bash
# ============================================================================
# hostapd Setup for POSFramework Rogue Access Point
# ============================================================================
# Prerequisites: Linux system with wireless card in AP mode support
# Installs and configures hostapd, dnsmasq, and iptables for rogue AP
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/hostapd_configs"
LOG_FILE="/var/log/posframework_hostapd_setup.log"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use: sudo $0)"
fi

log "Starting hostapd setup for POSFramework..."

# Create configuration directory
mkdir -p "$CONFIG_DIR"
log "Configuration directory: $CONFIG_DIR"

# Install required packages
log "Installing required packages..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y hostapd dnsmasq iproute2 iptables rfkill wireless-tools
elif command -v dnf &> /dev/null; then
    dnf install -y hostapd dnsmasq iproute wireless-tools
else
    error "Unsupported package manager. Please install: hostapd, dnsmasq, iproute2, iptables, rfkill"
fi

log "Packages installed successfully"

# Stop existing hostapd/dnsmasq instances
log "Stopping existing services..."
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
killall hostapd 2>/dev/null || true
killall dnsmasq 2>/dev/null || true

# Backup original configs
if [[ -f /etc/hostapd/hostapd.conf ]]; then
    log "Backing up original hostapd.conf..."
    cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.backup.$(date +%s)
fi

# Create enhanced hostapd configuration
log "Creating hostapd configuration templates..."

# Template 1: Standard Open Network
cat > "$CONFIG_DIR/hostapd-open.conf" << 'EOF'
# ============================================================================
# Hostapd Configuration - Open Network (No Authentication)
# ============================================================================

# Interface settings
interface=wlan0
driver=nl80211
country_code=US

# SSID & beacon settings
ssid=FreeWiFi
ignore_broadcast_ssid=0
beacon_int=100

# WiFi mode settings
hw_mode=g
channel=6
ieee80211n=1
ieee80211ac=0

# Power saving
wmm_enabled=1
uapsd_advertisement_enabled=0

# Security settings
macaddr_acl=0
auth_algs=1
wpa=0

# Performance & stability
max_num_sta=255
rts_threshold=2347
frag_threshold=2346

# Logging
logger_syslog=-1
logger_syslog_level=0
logger_stdout=-1
logger_stdout_level=0

# Optional: AP isolation (clients can't see each other)
# ap_isolate=0

# Optional: Spectrum management for DFS
# spectrum_mgmt_required=0

EOF

# Template 2: WPA2 Secure Network
cat > "$CONFIG_DIR/hostapd-wpa2.conf" << 'EOF'
# ============================================================================
# Hostapd Configuration - WPA2-PSK Secure Network
# ============================================================================

interface=wlan0
driver=nl80211
country_code=US

ssid=SecureWiFi
ignore_broadcast_ssid=0
beacon_int=100

hw_mode=g
channel=6
ieee80211n=1
ieee80211ac=0

wmm_enabled=1

macaddr_acl=0
auth_algs=1

# WPA2 Configuration
wpa=2
wpa_passphrase=DefaultPassword123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_preauth=0
rsn_pairwise=CCMP

# Performance
max_num_sta=255
rts_threshold=2347
frag_threshold=2346

logger_syslog=-1
logger_stdout=-1

EOF

# Template 3: Dual-band (2.4 GHz focus, extendable to 5 GHz)
cat > "$CONFIG_DIR/hostapd-dual.conf" << 'EOF'
# ============================================================================
# Hostapd Configuration - Dual-band Ready
# ============================================================================

interface=wlan0
driver=nl80211
country_code=US

ssid=DualBandAP
ignore_broadcast_ssid=0
beacon_int=100

# 2.4 GHz Settings
hw_mode=g
channel=6
ieee80211n=1

wmm_enabled=1
uapsd_advertisement_enabled=0

macaddr_acl=0
auth_algs=1
wpa=0

# Power management
power_save_profile=1

# Performance
max_num_sta=255
rts_threshold=2347
frag_threshold=2346
dtim_period=2

# Logging
logger_syslog=-1
logger_stdout=-1

EOF

log "Configuration templates created in: $CONFIG_DIR"

# Create network setup script
cat > "$CONFIG_DIR/setup_network.sh" << 'NETSCRIPT'
#!/bin/bash
# ============================================================================
# Network Interface Setup for Rogue AP
# ============================================================================

set -e

INTERFACE="${1:-wlan0}"
GATEWAY_IP="${2:-10.0.0.1}"
NETMASK="${3:-255.255.255.0}"

if [[ -z "$INTERFACE" ]]; then
    echo "Usage: $0 <interface> [gateway_ip] [netmask]"
    exit 1
fi

echo "[*] Configuring interface: $INTERFACE"

# Bring interface down
ip link set "$INTERFACE" down

# Flush any existing configuration
ip addr flush dev "$INTERFACE"

# Bring interface up
ip link set "$INTERFACE" up

# Set IP address and gateway
ip addr add "$GATEWAY_IP/24" dev "$INTERFACE"

echo "[+] Interface $INTERFACE configured:"
echo "    IP: $GATEWAY_IP"
echo "    Netmask: $NETMASK"
echo ""
echo "[*] Verifying configuration:"
ip addr show "$INTERFACE"

NETSCRIPT

chmod +x "$CONFIG_DIR/setup_network.sh"

# Create cleanup script
cat > "$CONFIG_DIR/cleanup_rogue_ap.sh" << 'CLEANSCRIPT'
#!/bin/bash
# ============================================================================
# Cleanup Script - Stop Rogue AP and Restore Network
# ============================================================================

set -e

echo "[*] Stopping Rogue AP services..."

# Stop services
systemctl stop hostapd 2>/dev/null || killall hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || killall dnsmasq 2>/dev/null || true

echo "[+] Services stopped"

# Flush iptables rules
echo "[*] Flushing iptables rules..."
iptables -F
iptables -t nat -F
iptables -t mangle -F
echo "[+] iptables flushed"

# Remove temporary config files
rm -f /tmp/hostapd-rogue.conf
rm -f /tmp/dnsmasq.conf

echo "[*] Cleaning up temporary files..."
echo "[+] Cleanup complete"

CLEANSCRIPT

chmod +x "$CONFIG_DIR/cleanup_rogue_ap.sh"

# Create dnsmasq configuration template
cat > "$CONFIG_DIR/dnsmasq-captive.conf" << 'EOF'
# ============================================================================
# Dnsmasq Configuration for Captive Portal
# ============================================================================

# Do not read /etc/resolv.conf
no-resolv

# Listen on AP interface only
interface=wlan0
bind-interfaces

# DHCP Configuration
dhcp-range=10.0.0.2,10.0.0.100,12h
dhcp-option=option:router,10.0.0.1
dhcp-option=option:dns-server,10.0.0.1

# Wildcard DNS (redirect all queries to gateway)
address=/#/10.0.0.1

# Logging
log-queries
log-facility=/var/log/dnsmasq.log

# Cache DNS results
cache-size=1024

# Disable DNS resolution cache for captive portal (forces redirect)
# Uncomment for aggressive DNS hijacking:
# no-cache

EOF

log "Dnsmasq configuration template created"

# Create iptables setup script
cat > "$CONFIG_DIR/setup_iptables.sh" << 'IPTSCRIPT'
#!/bin/bash
# ============================================================================
# IPTables Setup for Captive Portal & Traffic Redirect
# ============================================================================

set -e

INTERFACE="${1:-wlan0}"
GATEWAY_IP="${2:-10.0.0.1}"
PORTAL_PORT="${3:-80}"

if [[ -z "$INTERFACE" ]]; then
    echo "Usage: $0 <interface> [gateway_ip] [portal_port]"
    exit 1
fi

echo "[*] Configuring iptables for $INTERFACE..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# DNS Redirect (UDP & TCP port 53 → 10.0.0.1:53)
echo "[*] Setting up DNS redirection..."
iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 \
    -j DNAT --to-destination "$GATEWAY_IP:53"
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 53 \
    -j DNAT --to-destination "$GATEWAY_IP:53"

# HTTP Redirect (port 80 → portal)
echo "[*] Setting up HTTP redirection..."
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 \
    -j DNAT --to-destination "$GATEWAY_IP:$PORTAL_PORT"

# HTTPS Redirect (port 443 → portal)
echo "[*] Setting up HTTPS redirection..."
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 \
    -j DNAT --to-destination "$GATEWAY_IP:$PORTAL_PORT"

# Masquerade outgoing traffic
echo "[*] Setting up IP masquerade..."
iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE

# Allow traffic on AP interface
iptables -A FORWARD -i "$INTERFACE" -j ACCEPT

echo "[+] iptables configured successfully"
echo ""
echo "[*] Active iptables rules:"
iptables -t nat -L -n -v

IPTSCRIPT

chmod +x "$CONFIG_DIR/setup_iptables.sh"

# Create integrated startup script
cat > "$CONFIG_DIR/start_rogue_ap.sh" << 'STARTSCRIPT'
#!/bin/bash
# ============================================================================
# Start Rogue AP - Integrated Startup Script
# ============================================================================

set -e

INTERFACE="${1:-wlan0}"
SSID="${2:-FreeWiFi}"
CHANNEL="${3:-6}"
WPA_PASS="${4:-}"
GATEWAY_IP="${5:-10.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[*]${NC} $1"
}

if [[ $EUID -ne 0 ]]; then
    error "This script requires root privileges"
fi

log "Starting Rogue AP..."
log "Interface: $INTERFACE"
log "SSID: $SSID"
log "Channel: $CHANNEL"
log "Gateway: $GATEWAY_IP"

# 1. Configure network interface
warn "Configuring network interface..."
"$SCRIPT_DIR/setup_network.sh" "$INTERFACE" "$GATEWAY_IP" "255.255.255.0"

# 2. Setup iptables
warn "Setting up iptables rules..."
"$SCRIPT_DIR/setup_iptables.sh" "$INTERFACE" "$GATEWAY_IP" "80"

# 3. Configure hostapd
warn "Configuring hostapd..."
HOSTAPD_CONF="/tmp/hostapd-rogue.conf"
cat > "$HOSTAPD_CONF" << HCONF
interface=$INTERFACE
driver=nl80211
country_code=US
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
HCONF

if [[ -n "$WPA_PASS" ]]; then
    cat >> "$HOSTAPD_CONF" << WPACONF
wpa=2
wpa_passphrase=$WPA_PASS
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
WPACONF
    log "WPA2 enabled with passphrase"
else
    echo "wpa=0" >> "$HOSTAPD_CONF"
    log "Open network (no authentication)"
fi

# 4. Start hostapd
warn "Starting hostapd..."
hostapd -B "$HOSTAPD_CONF" || error "Failed to start hostapd"
sleep 2
log "hostapd started"

# 5. Configure dnsmasq
warn "Configuring dnsmasq..."
DNSMASQ_CONF="/tmp/dnsmasq-rogue.conf"
cat > "$DNSMASQ_CONF" << DCONF
no-resolv
interface=$INTERFACE
bind-interfaces
dhcp-range=10.0.0.2,10.0.0.100,12h
dhcp-option=option:router,$GATEWAY_IP
dhcp-option=option:dns-server,$GATEWAY_IP
address=/#/$GATEWAY_IP
log-queries
cache-size=1024
DCONF

# 6. Start dnsmasq
warn "Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" || error "Failed to start dnsmasq"
sleep 1
log "dnsmasq started"

log ""
log "==============================================="
log "Rogue AP Started Successfully!"
log "==============================================="
log "SSID: $SSID"
log "Channel: $CHANNEL"
log "Gateway IP: $GATEWAY_IP"
log "DHCP Range: 10.0.0.2 - 10.0.0.100"
log ""
log "To stop the AP, run:"
log "  sudo $SCRIPT_DIR/cleanup_rogue_ap.sh"
log "==============================================="

STARTSCRIPT

chmod +x "$CONFIG_DIR/start_rogue_ap.sh"

# Create validation script
cat > "$CONFIG_DIR/validate_hostapd.sh" << 'VALSCRIPT'
#!/bin/bash
# ============================================================================
# Validate Hostapd & Rogue AP Setup
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check() {
    local name="$1"
    local cmd="$2"
    
    if eval "$cmd" &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} $name"
        return 0
    else
        echo -e "${RED}[✗]${NC} $name"
        return 1
    fi
}

echo "===== Hostapd/Rogue AP Validation ====="
echo ""

# Check packages
echo "1. Checking installed packages:"
check "hostapd installed" "which hostapd"
check "dnsmasq installed" "which dnsmasq"
check "iptables installed" "which iptables"

echo ""
echo "2. Checking kernel modules:"
check "nl80211 module" "lsmod | grep -q nl80211"
check "mac80211 module" "lsmod | grep -q mac80211"

echo ""
echo "3. Checking wireless interfaces:"
echo "Available wireless interfaces:"
iwconfig 2>/dev/null | grep -E "^[a-z]+" | cut -d' ' -f1 || echo "[!] No wireless interfaces detected"

echo ""
echo "4. Checking hostapd version:"
hostapd -v 2>&1 | head -1

echo ""
echo "5. Checking dnsmasq version:"
dnsmasq -v 2>&1 | head -1

echo ""
echo "6. Checking running services:"
check "hostapd running" "pgrep -x hostapd"
check "dnsmasq running" "pgrep -x dnsmasq"

echo ""
echo "7. Checking iptables configuration:"
if iptables -t nat -L -n 2>/dev/null | grep -q "DNAT"; then
    echo -e "${GREEN}[✓]${NC} iptables NAT rules present"
else
    echo -e "${YELLOW}[!]${NC} iptables NAT rules not present (not configured yet)"
fi

VALSCRIPT

chmod +x "$CONFIG_DIR/validate_hostapd.sh"

log "Creating systemd service files..."

# Create optional systemd service for hostapd
cat > "/etc/systemd/system/hostapd-rogue.service" << 'SYSTEMD'
[Unit]
Description=Hostapd Rogue AP Service (POSFramework)
After=network.target
Documentation=man:hostapd(8)

[Service]
Type=forking
ExecStart=/usr/sbin/hostapd -B /tmp/hostapd-rogue.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

log "All configuration and helper scripts created!"
log ""
log "=========================================="
log "Setup Complete!"
log "=========================================="
log ""
log "Configuration location: $CONFIG_DIR"
log ""
log "Available scripts:"
log "  • start_rogue_ap.sh       - Start rogue AP with full setup"
log "  • cleanup_rogue_ap.sh     - Stop services and clean up"
log "  • validate_hostapd.sh     - Validate installation"
log "  • setup_network.sh        - Configure network interface"
log "  • setup_iptables.sh       - Setup port redirects"
log ""
log "Configuration templates:"
log "  • hostapd-open.conf       - Open network"
log "  • hostapd-wpa2.conf       - WPA2-PSK secured network"
log "  • hostapd-dual.conf       - Dual-band ready"
log "  • dnsmasq-captive.conf    - Captive portal DNS"
log ""
log "Next steps:"
log "  1. Review and customize configs in: $CONFIG_DIR"
log "  2. Test with: sudo $CONFIG_DIR/validate_hostapd.sh"
log "  3. Check wireless interface: iwconfig"
log "  4. Start rogue AP: sudo $CONFIG_DIR/start_rogue_ap.sh <interface> <SSID> <channel>"
log ""
log "Example:"
log "  sudo $CONFIG_DIR/start_rogue_ap.sh wlan1 'FreeWiFi' 6"
log "=========================================="

exit 0
