# POSFramework Capabilities

Complete list of all attack, reconnaissance, and exploitation capabilities.

---

## Autonomous Attack Engine (AutoPwn)

| Capability | Description | Status |
|---|---|---|
| State Machine | Full async state machine: IDLE, SCANNING, ANALYZING, ATTACKING, CRACKING, PAUSED, STOPPING | Active |
| Multi-Target | Concurrent attacks on up to 3 targets simultaneously | Active |
| Session Persistence | JSON session save/resume with auto-save every 30s | Active |
| Full Channel Scan | Scans all 2.4GHz (1-13) and 5GHz (36-165) channels | Active |
| EventBus Integration | Pub/sub events at every state transition for real-time monitoring | Active |
| Battery Safety | Auto-stops at configurable battery threshold | Active |
| Duration Limits | Configurable max session duration | Active |
| Target Priority Queue | Async priority-based target selection with cooldown | Active |

## Attack Chain (All Enabled)

| Attack | Type | Technique | Requirements |
|---|---|---|---|
| PMKID Capture | Clientless | Sends auth+assoc to AP, extracts PMKID from EAPOL M1 RSN KDE | Monitor + Injection |
| Deauth + Handshake | Client-dependent | Targeted deauth (reason 7), captures 4-way EAPOL handshake | Monitor + Injection + Active clients |
| WPA3 Downgrade | WPA3 Transition | Blocks SAE auth frames (reject reason 13), forces WPA2 fallback | Monitor + Injection + WPA3 target |
| Evil Twin | Rogue AP | hostapd AP + dnsmasq DHCP/DNS + captive portal credential phishing | Two interfaces (monitor + AP) |
| KARMA/MANA | Probe Response | Auto-responds to all client probe requests with matching SSID | Monitor + Injection |

## WiFi Attacks (Orchestrator)

| Module | Description | Status |
|---|---|---|
| Targeted Deauthentication | Signal-filtered deauth with RSSI threshold | Enabled |
| Rogue AP (Evil Twin) | Same SSID/channel AP with captive portal | Enabled |
| Known Beacon Flood | Broadcasts SSIDs from client probe history | Enabled |
| KARMA | Responds to all probe requests | Enabled |
| AP Clone | Auto-clones target AP after deauth | Enabled |
| KRACK | Key reinstallation attack (CVE-2017-13077/13078) | Enabled |
| WiFi DoS | CTS flood, beacon exhaust, QoS null, fragmentation | Enabled |
| Client Isolation Bypass | Subtle disassociation and handoff forcing | Enabled |
| WPA3 SAE Downgrade | Forces transition mode to WPA2 | Enabled |

## Credential Capture

| Module | Description | Status |
|---|---|---|
| Handshake Capture | Full 4-way EAPOL handshake to .cap (hashcat mode 22000) | Enabled |
| PMKID Extraction | Saves to hashcat mode 16800 format | Enabled |
| Captive Portal Phishing | HTTP credential harvesting via rogue AP | Enabled |
| Credential Harvester | HTTP/FTP/IMAP/POP3 cleartext credential capture | Enabled |
| NTLM Capture | NTLMv1/v2 hash capture from SMB/HTTP NTLM auth | Enabled |
| Kerberos Capture | Kerberos ticket and AS-REP roasting | Enabled |
| LDAP Capture | LDAP bind credential interception | Enabled |
| Cloud Credential Detection | AWS/Azure/GCP key detection in traffic | Enabled |
| Browser Credential Extract | Extract saved passwords from connected clients | Enabled |
| Printer Credential Harvest | SNMP/IPP/JetDirect printer credential extraction | Enabled |

## Man-in-the-Middle

| Module | Description | Status |
|---|---|---|
| MITM Engine | ARP poisoning for traffic interception | Enabled |
| SSL Strip | HTTPS to HTTP downgrade (HSTS bypass) | Enabled |
| DNS Spoofing | DNS response injection for domain redirect | Enabled |
| Session Hijacking | Cookie theft and session token replay | Enabled |
| HTTPS Intercept | TLS interception with on-the-fly certificate generation | Enabled |

## Cracking and Post-Exploitation

| Module | Description | Status |
|---|---|---|
| Hashcat Integration | GPU-accelerated WPA/WPA2 cracking | Enabled |
| Credential Testing | Auto-verify captured credentials against real AP | Enabled |
| Auto-Pivot | Automatic network pivoting after successful auth | Enabled |
| Credential Enrichment | Cross-reference and enrich captured credentials | Enabled |
| Credential Correlation | Link credentials across services and targets | Enabled |
| Credential Spraying | Test captured creds against multiple services | Enabled |

## Reconnaissance

| Module | Description | Status |
|---|---|---|
| Passive Recon | OUI vendor lookup, SSID heuristics, RSN/WPA IE parsing | Enabled |
| EAPOL Detection | Handshake and PMKID detection in passive mode | Enabled |
| Signal Targeting | RSSI-based client filtering for precision attacks | Enabled |
| Client Profiling | OS fingerprinting, behavior analysis, device classification | Enabled |
| POS Detection | Point-of-sale terminal identification via vendor/SSID patterns | Enabled |
| VLAN Discovery | 802.1Q/CDP/LLDP/DTP VLAN enumeration | Enabled |
| Network Mapping | Full network segmentation and ACL gap detection | Enabled |
| Printer Recon | Network printer discovery via mDNS/SNMP/IPP | Enabled |
| Chip Detection | WiFi chipset identification for capability assessment | Enabled |

## Radio Management

| Capability | Description | Status |
|---|---|---|
| Multi-Interface | Manages multiple WiFi adapters simultaneously | Active |
| Task Allocation | Lock-based interface pool (SCAN/CAPTURE/DEAUTH/MONITOR/INJECT) | Active |
| Capability Detection | Auto-detects bands, channels, monitor mode, injection support | Active |
| 5GHz/6GHz Support | Full 5GHz and WiFi 6E channel support | Active |
| DFS Awareness | Identifies and handles DFS channels requiring radar detection | Active |
| Auto Mode Switch | Automatically sets monitor/managed mode per task | Active |
| Error Recovery | Graceful degradation on adapter failures with error tracking | Active |

## Target Scoring

| Criteria | Weight | Description |
|---|---|---|
| POS Vendor Match | +50 | Highest priority for point-of-sale targets |
| Strong Signal (>-60dBm) | +20 | Close proximity targets |
| WPA2-PSK | +15 | Easier to crack than WPA3 |
| Active Clients | +20 base + 2/client | Required for handshake attacks |
| PMKID Vulnerable | +25 | Clientless attack possible |
| Client Proximity | +10 | Clients with strong RSSI |
| WPA3 | -10 | Harder but downgrade may work |
| Open Network | +5 | Easy but less valuable |
| Isolation Detected | -20 | Limits attack effectiveness |

## Session Management

| Feature | Description |
|---|---|
| Auto-Save | Saves session state every 30 seconds |
| Resume | Can resume from paused or interrupted sessions |
| History | Maintains last 10 sessions with full attack logs |
| Atomic Writes | Crash-safe JSON persistence via temp file + rename |
| Event Log | Tracks up to 1000 events per session |
| Statistics | Real-time stats: targets, attacks, captures, cracks |

## Output Formats

| Format | Use Case |
|---|---|
| .cap (pcap) | WPA handshakes for aircrack-ng/hashcat mode 22000 |
| .16800 | PMKID hashes for hashcat mode 16800 |
| .json | Session data, attack reports, network maps |
| .hccapx | Legacy hashcat WPA format |

---

## Operating Modes

- **AGGRESSIVE**: All attacks enabled, 3 concurrent targets, 15s scan interval, auto-retry
- **BALANCED**: Selective attacks, 1 target at a time, 30s scan interval, longer cooldowns
- **PASSIVE**: Scan and analyze only, no active attacks, reconnaissance mode

---

## BLE (Bluetooth Low Energy) Module

| Capability | Description | Status |
|---|---|---|
| BLE Scanner | Async device discovery via bleak, RSSI tracking, continuous scan | Enabled |
| iBeacon Parsing | Apple company ID 0x004C, struct-based UUID/major/minor/TX extraction | Enabled |
| Eddystone Parsing | Service UUID 0xFEAA, UID/URL/TLM frame decoding | Enabled |
| Beacon Spoofer | hcitool LE advertising: fake iBeacon and Eddystone-URL broadcast | Enabled |
| GATT Explorer | Full service/characteristic enumeration, read/write, notifications | Enabled |
| HID Injection | Bluetooth keyboard emulation, keystroke injection, payload delivery | Enabled |
| Distance Estimation | Log-distance path-loss model from RSSI + TX power | Enabled |

## SDR (Software-Defined Radio) Module

| Capability | Description | Status |
|---|---|---|
| Device Discovery | RTL-SDR, RTL-SDR V4 (R828D), HackRF detection | Enabled |
| RTL-SDR V4 HF | Direct sampling for HF reception (500 kHz - 28 MHz) | Enabled |
| Bias Tee Control | V4 bias tee for powered antennas/LNAs | Enabled |
| Spectrum Analyzer | FFT-based PSD with numpy, peak detection, frequency sweep | Enabled |
| OOK Decoder | Amplitude envelope extraction, adaptive threshold, 433 MHz devices | Enabled |
| FSK Decoder | Phase-difference demodulation, IoT sensor decoding, 868 MHz | Enabled |
| Signal Identification | Known device signature matching (weather, garage, car remotes) | Enabled |
| IQ Sample Capture | Raw complex sample capture via pyrtlsdr | Enabled |

## GPS Module

| Capability | Description | Status |
|---|---|---|
| gpsd Client | Async TCP connection to gpsd (port 2947), JSON streaming protocol | Enabled |
| Auto-Reconnect | Automatic reconnection with configurable delay and max attempts | Enabled |
| TPV Parsing | Time-Position-Velocity message extraction (lat, lon, alt, speed) | Enabled |
| SKY Parsing | Satellite visibility and fix quality tracking | Enabled |
| Haversine Distance | WGS84 great-circle distance calculation between coordinates | Enabled |
| Bearing Calculation | Initial bearing from point A to point B (0-360 degrees) | Enabled |
| Distance Tracker | Cumulative distance with jitter/glitch filtering | Enabled |
| Wardriving | GPS + WiFi scan correlation for network mapping | Enabled |

## WPA3 Detection and Attack Module

| Capability | Description | Status |
|---|---|---|
| RSN IE Parsing | Parse AKM suite type 8 (SAE) from iw scan output | Enabled |
| PMF Detection | RSN capabilities bit 6 (MFPC) and bit 7 (MFPR) | Enabled |
| Transition Mode Detection | Identify WPA2+WPA3 mixed mode (downgrade possible) | Enabled |
| OWE Detection | AKM type 18, WFA vendor IE for OWE transition | Enabled |
| Downgrade Attack | Deauth reason 13 to block SAE, force WPA2 fallback | Enabled |
| SAE Flood DoS | Dragonblood-style commit frame flooding via mdk4 | Enabled |
| Attack Auto-Selection | Automatic best-vector selection based on target capabilities | Enabled |
| Capture Conversion | hcxpcapngtool conversion to hashcat 22000 format | Enabled |

## John the Ripper Integration

| Capability | Description | Status |
|---|---|---|
| Wordlist Attack | --wordlist mode with any dictionary file | Enabled |
| Incremental Mode | Brute-force with charset-based incremental | Enabled |
| Mask Attack | --mask=?a?a?a?a pattern-based generation | Enabled |
| Rules Mode | --rules=best64/Jumbo/KoreLogic mutations | Enabled |
| WPAPSK Format | WiFi handshake cracking (john wpapsk format) | Enabled |
| Progress Monitoring | Real-time speed/progress via --status parsing | Enabled |
| Potfile Management | Cracked password storage and retrieval via --show | Enabled |
| Capture Conversion | hccap2john/wpapcap2john format conversion | Enabled |
| Runtime Cap | Configurable max runtime with watchdog enforcement | Enabled |
