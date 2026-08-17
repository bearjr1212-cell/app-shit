POS Framework - Wireless Security Assessment Tool
================================================

Project Structure:
  posframework/
  ├── __main__.py          # CLI entry point
  ├── __init__.py          # Package exports
  ├── config.py            # Configuration constants
  ├── config_loader.py     # YAML config file loader
  ├── database.py          # SQLite data layer
  ├── orchestrator.py      # Attack pipeline orchestrator
  ├── interface_manager.py # Auto-discovery & interface assignment
  ├── monitor_mode.py      # Monitor mode management
  ├── recon.py             # Passive 802.11 scanner
  ├── deauth.py            # Deauthentication engine
  ├── beacons.py           # Known beacon flooding
  ├── rogueap.py           # Rogue AP + captive portal
  ├── mitm.py              # Man-in-the-middle
  ├── ssl_strip.py         # SSL stripping
  ├── dns_spoof.py         # DNS spoofing
  ├── krack.py             # KRACK attack
  ├── dos_wifi.py          # WiFi DoS modes
  ├── karma.py             # KARMA probe response
  ├── ap_clone.py          # AP cloning
  ├── client_isolation.py  # Client isolation
  ├── network_disruption.py# Network disruption tools
  ├── handshake.py         # WPA handshake capture
  ├── signal_targeting.py  # RSSI-based targeting
  ├── crypto.py            # RSN/WPA IE parsing (Python)
  ├── intel.py             # POS vendor intelligence
  ├── cred_harvester.py    # Credential harvesting
  ├── cred_tester.py       # Credential testing
  ├── printer_recon.py     # Printer discovery
  ├── ipp_scanner.py       # IPP scanner
  ├── print_interceptor.py # Print job interception
  ├── printer_creds.py     # Printer credential harvest
  ├── hostapd_helper.py    # Hostapd configuration
  ├── plugin_loader.py     # Plugin system
  ├── post_attack.py       # Post-attack analysis
  ├── gui.py               # Tkinter GUI
  ├── main.py              # Multi-terminal UI
  │
  ├── native/              # Python ctypes wrappers for C libraries
  │   ├── __init__.py
  │   ├── packet_engine.py
  │   ├── channel_hop.py
  │   ├── crypto_parse.py
  │   └── deauth_craft.py
  │
  ├── csrc/                # C shared library source code
  │   ├── Makefile
  │   ├── packet_engine.c/h
  │   ├── channel_hop.c/h
  │   ├── crypto_parse.c/h
  │   └── deauth_craft.c/h
  │
  ├── lib/                 # Compiled .so shared libraries
  │   └── (built by: cd csrc && make && make install)
  │
  ├── plugins/             # Attack plugins
  │   ├── deauth_plugin.py
  │   ├── mitm_plugin.py
  │   └── dos_plugin.py
  │
  └── handshakes/          # Captured WPA handshakes (PCAP)

Build Native Libraries:
  cd posframework/csrc
  make
  make install

Run:
  sudo python3 -m posframework recon --auto-iface
  sudo python3 -m posframework attack --auto-iface
  sudo python3 -m posframework full --auto-iface
  sudo python3 -m posframework iface              # Show detected interfaces
