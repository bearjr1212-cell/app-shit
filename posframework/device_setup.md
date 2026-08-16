# F6D4230 v3 USB WiFi Adapter Setup Guide

## Device Information
- **Model**: F6D4230 v3
- **Chipset**: Ralink RT3070 / RT3572 (common for this model)
- **Purpose**: 802.11 packet injection & monitor mode

## Prerequisites

### 1. Install Npcap (Required)
Download and install from: https://npcap.com/

- Select "Install Npcap in WinPcap API-compatible Mode"
- Enable "Install Npcap in Datagram Capture Mode (DLT_NULL)"

### 2. Install WinPcap Developer's Pack (Optional)
If you plan to compile drivers:
- Download: https://www.winpcap.org/devel.htm
- Extract to `C:\WpdPack`

## Setup Steps

### Method 1: Using AirCrack-ng Drivers (Recommended)

1. **Download Aircrack-ng**:
   - Visit: https://www.aircrack-ng.org/
   - Download the latest version

2. **Install Aircrack-ng**:
   - Run installer
   - Select "Install driver" option

3. **Switch to Monitor Mode**:
   ```powershell
   # List interfaces
   aircrack-ng.bat
   
   # Set monitor mode on interface
   airmon-ng start Wi-Fi
   ```

### Method 2: Using Npcap Monitor Mode

1. **Open Npcap Diagnostic Tool**:
   - Start → Search "Npcap Diagnostic Tool"
   - Run as Administrator

2. **Enable Monitor Mode**:
   - In Npcap Diagnostic Tool:
     - Select your "F6D4230 v3" interface
     - Check "Enable Monitor Mode"
     - Click "Apply"

3. **Verify Monitor Mode**:
   ```powershell
   python3 -m posframework recon --list-ifaces
   ```

### Method 3: Manual Driver Replacement

**WARNING**: This requires admin access and may void warranty.

1. **Download Ralink RT3572 Windows Driver**:
   - From manufacturer or trusted source
   - Must support monitor mode

2. **Install Driver**:
   - Device Manager → Network Adapters
   - Right-click "F6D4230 v3"
   - Update Driver → Browse → Select extracted driver folder
   - Check "Allow incompatible drivers"

3. **Configure Monitor Mode**:
   - Some drivers expose monitor mode through registry:
   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}
   ```

## Verify Setup

### Check Interface List
```powershell
python3 C:\Users\VIPIN\kiro\run.py recon --list-ifaces
```

### Test Monitor Mode
```powershell
python3 C:\Users\VIPIN\kiro\run.py recon -i "F6D4230 v3" -v
```

### Expected Output
You should see beacon frames from nearby networks:
```
[Beacon] RSSI:-45dBm | XX:XX:XX:XX:XX:XX | 'YourNetwork'
```

## Troubleshooting

### "Interface not found" Error
1. Check device is detected:
   ```
   Device Manager → Network Adapters
   ```
2. Restart Npcap service:
   ```powershell
   net stop npf
   net start npf
   ```
3. Reinstall Npcap

### No Packets Captured
1. Check interface is in monitor mode
2. Move closer to WiFi networks
3. Try different channels:
   ```powershell
   python3 C:\Users\VIPIN\kiro\run.py recon -i "F6D4230 v3" --5ghz
   ```

### Driver Issues
- Some F6D4230 v3 units use different chipsets
- Check exact chipset with Device Manager
- Search for specific driver for your chipset

## Using with POS Framework

Once setup is complete:

```powershell
# Passive recon
python3 C:\Users\VIPIN\kiro\run.py recon -i "F6D4230 v3"

# Full attack mode
python3 C:\Users\VIPIN\kiro\run.py attack -i "F6D4230 v3" -a "Wi-Fi 2"

# Terminal UI
python3 C:\Users\VIPIN\kiro\run.py terminal -i "F6D4230 v3" -a "Wi-Fi 2"
```

## Legal Notice
Only use this tool on networks you own or have explicit permission to test. Unauthorized wireless attacks may violate local laws.