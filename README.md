# POSFramework v2.1.0

A real-world 802.11 passive reconnaissance and automated attack framework targeting Point-of-Sale (POS) terminals, payment infrastructure, and retail networking gear.

## Features

- **Passive Recon**: OUI vendor lookups, SSID heuristics, RSN/WPA IE parsing, EAPOL handshake detection, deauth flood monitoring
- **Automated Attacks**: Evil Twin AP, targeted deauthentication, known beacon flooding, captive portal credential harvesting
- **MITM**: ARP poisoning with man-in-the-middle interception
- **SSL Stripping**: HTTPS to HTTP downgrade attacks
- **DNS Spoofing**: DNS redirection attacks
- **Credential Harvesting**: HTTP/FTP/IMAP credential capture
- **Network Disruption**: Deauth storms, jamming, rate limiting
- **Advanced WiFi**: KRACK (CVE-2017-13077/13078), WiFi DoS (CTS flood, beacon exhaust), client isolation
- **AP Cloning**: Auto-clone target AP SSID after deauth
- **Printer Exploitation**: mDNS/SNMP/HTTP discovery, IPP scanning, print interception, credential harvesting
- **Post-Attack Analysis**: Automated next-steps generation from captured data

## Requirements

- Python 3.8+
- Root/Administrator privileges (required for raw socket access)
- Wireless adapter with monitor mode support
- Linux: `iw`, `ip` tools (standard on most distributions)
- Windows: Npcap with WinPcap API-compatible mode

## Installation

```bash
# Clone the repository
git clone https://github.com/bearjr1212-cell/app-shit.git
cd app-shit

# Install in development mode
pip install -e .
```

## Usage

POSFramework provides multiple CLI modes:

```bash
# Passive reconnaissance (scan for POS devices)
posframework recon --interface wlan0 --timeout 120

# Full automated flow (recon + auto-targeted attacks)
posframework full --interface wlan0 --timeout 300

# Attack mode (targeted against discovered devices)
posframework attack --interface wlan0

# Analyze captured data
posframework analyze --db pos_recon_data.db

# Export results to file
posframework export --format json --output results.json

# Interactive terminal mode
posframework terminal

# CLI Terminal UI (curses-based)
posframework gui
```

### CLI Modes

| Mode       | Description                                         |
|------------|-----------------------------------------------------|
| `recon`    | Passive scanning and POS device identification      |
| `attack`   | Launch attacks against discovered targets           |
| `full`     | Combined recon + automated attack pipeline          |
| `analyze`  | Post-attack analysis of captured data               |
| `export`   | Export scan/attack results in various formats       |
| `terminal` | Interactive terminal for manual operations          |
| `gui`      | Curses-based CLI terminal UI                        |

## Platform Support

| Platform | Monitor Mode | Channel Hopping | MAC Spoofing |
|----------|-------------|-----------------|--------------|
| Linux    | Full (iw/ip) | Yes            | Yes          |
| Windows  | Npcap-based  | Limited        | Registry-based |

## Project Structure

```
posframework/
  config.py          - Constants, thresholds, platform detection
  recon.py           - Passive 802.11 scanner engine
  monitor_mode.py    - Cross-platform monitor mode management
  orchestrator.py    - Auto-targeting attack pipeline
  database.py        - SQLite layer (WAL mode)
  deauth.py          - Deauth frame injection
  beacons.py         - Known beacon flood
  rogueap.py         - Rogue AP + captive portal
  __main__.py        - CLI entry point
```

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer networks is illegal. Always obtain proper authorization before using this tool.

## License

See LICENSE file for details.
