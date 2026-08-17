"""
Enhanced Monitor Mode Manager

Provides an intelligent monitor mode manager that:
    - Auto-detects the WiFi chipset via ChipDetector
    - Selects the optimal monitor mode method via MonitorMethodSelector
    - Implements enable/disable with automatic cleanup (atexit + signal handlers)
    - Tracks full interface state throughout the lifecycle
    - Retries with fallback methods if the primary method fails
"""

import atexit
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .config import (
    IS_LINUX,
    IS_WINDOWS,
    MONITOR_MODE_RETRY_COUNT,
    MONITOR_MODE_RETRY_DELAY,
    log,
)
from .chip_detector import ChipDetector, ChipInfo, MonitorMethod, MonitorMethodSelector


# ─── State Tracking ───────────────────────────────────────────────────────────


@dataclass
class MonitorState:
    """Tracks the full state of an interface throughout the monitor mode lifecycle."""
    original_name: str = ""
    current_name: str = ""
    original_mode: str = "managed"
    original_mac: str = ""
    monitor_active: bool = False
    method_used: str = ""
    chip_info: Optional[ChipInfo] = None
    channel: Optional[int] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Return the state as a dictionary."""
        return {
            "original_name": self.original_name,
            "current_name": self.current_name,
            "original_mode": self.original_mode,
            "original_mac": self.original_mac,
            "monitor_active": self.monitor_active,
            "method_used": self.method_used,
            "chip_info": self.chip_info.summary() if self.chip_info else None,
            "channel": self.channel,
            "errors": list(self.errors),
        }


# ─── Enhanced Monitor Manager ─────────────────────────────────────────────────


class EnhancedMonitorManager:
    """
    Enhanced monitor mode manager with automatic chip detection, method selection,
    atexit/signal cleanup, state tracking, and retry with fallback.

    Usage:
        manager = EnhancedMonitorManager("wlan0")
        success = manager.enable_monitor_mode()
        if success:
            print(f"Monitor active on: {manager.state.current_name}")
            manager.set_channel(6)
        # Cleanup is automatic via atexit and signal handlers
        # Or explicitly:
        manager.disable_monitor_mode()
    """

    def __init__(
        self,
        interface: str,
        auto_cleanup: bool = True,
        retry_count: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ):
        """
        Initialize the enhanced monitor manager.

        Args:
            interface: Network interface name (e.g., 'wlan0').
            auto_cleanup: Register atexit and signal handlers for cleanup.
            retry_count: Number of retries per method (default from config).
            retry_delay: Delay between retries in seconds (default from config).
        """
        self.interface = interface
        self._retry_count = retry_count if retry_count is not None else MONITOR_MODE_RETRY_COUNT
        self._retry_delay = retry_delay if retry_delay is not None else MONITOR_MODE_RETRY_DELAY

        # Components
        self._detector = ChipDetector()
        self._selector = MonitorMethodSelector()

        # State
        self.state = MonitorState(
            original_name=interface,
            current_name=interface,
        )

        # Cleanup registration
        self._cleanup_registered = False
        self._original_sigint: Optional[Callable] = None
        self._original_sigterm: Optional[Callable] = None

        if auto_cleanup:
            self._register_cleanup()

    # ─── Public Interface ─────────────────────────────────────────────────────

    def enable_monitor_mode(self) -> bool:
        """
        Enable monitor mode using automatic chip detection and best method.

        Performs:
            1. Detect chipset via ChipDetector
            2. Select best method via MonitorMethodSelector
            3. Attempt to enable with primary method (with retries)
            4. If primary fails, try fallback methods
            5. Track state throughout

        Returns:
            True if monitor mode was successfully enabled.
        """
        if not IS_LINUX:
            log.warning("EnhancedMonitorManager is only supported on Linux")
            return False

        if self.state.monitor_active:
            log.info(f"Monitor mode already active on {self.state.current_name}")
            return True

        # Save original MAC
        self.state.original_mac = self._get_mac_address(self.interface) or ""

        # Step 1: Detect chip
        log.info(f"Detecting chipset for {self.interface}...")
        chip_info = self._detector.detect(self.interface)
        self.state.chip_info = chip_info

        # Step 2: Select methods
        methods = self._selector.select(chip_info)
        if not methods:
            log.error("No monitor mode methods available")
            self.state.errors.append("No methods available")
            return False

        log.info(
            f"Selected methods (priority order): "
            f"{[m.name for m in methods]}"
        )

        # Step 3: Try each method with retries
        for method in methods:
            log.info(f"Trying method: {method.name} (priority {method.priority})")
            success = self._try_method(method)
            if success:
                self.state.monitor_active = True
                self.state.method_used = method.name
                log.info(
                    f"Monitor mode enabled via '{method.name}' "
                    f"on {self.state.current_name}"
                )
                return True
            else:
                log.warning(f"Method '{method.name}' failed, trying next...")

        # All methods failed
        log.error(
            f"All monitor mode methods failed for {self.interface}. "
            f"Tried: {[m.name for m in methods]}"
        )
        self.state.errors.append("All methods failed")
        return False

    def disable_monitor_mode(self) -> bool:
        """
        Disable monitor mode and restore the interface to its original state.

        Returns:
            True if monitor mode was successfully disabled.
        """
        if not self.state.monitor_active:
            log.info("Monitor mode is not active, nothing to disable")
            return True

        log.info(f"Disabling monitor mode on {self.state.current_name}...")
        success = False

        method_name = self.state.method_used

        if method_name == "airmon-ng":
            success = self._disable_airmon()
        elif method_name == "iw":
            success = self._disable_iw()
        elif method_name == "driver":
            success = self._disable_driver()
        else:
            # Try generic iw method
            success = self._disable_iw()

        if success:
            self.state.monitor_active = False
            self.state.current_name = self.state.original_name
            log.info(f"Monitor mode disabled, restored: {self.state.original_name}")
            # Unregister the atexit handler since cleanup is no longer needed
            atexit.unregister(self.cleanup)
        else:
            log.error("Failed to disable monitor mode cleanly")
            self.state.errors.append("Disable failed")

        return success

    def cleanup(self) -> None:
        """
        Cleanup handler for atexit and signal handlers.

        Restores the interface to managed mode if monitor mode is active.
        Safe to call multiple times.
        """
        if self.state.monitor_active:
            log.info("Cleanup: restoring interface from monitor mode...")
            try:
                self.disable_monitor_mode()
            except Exception as e:
                log.error(f"Cleanup error: {e}")
                # Last resort: try to force the interface back to managed
                self._force_restore()

    def set_channel(self, channel: int) -> bool:
        """
        Set the wireless channel on the monitor interface.

        Args:
            channel: WiFi channel number.

        Returns:
            True if channel was set successfully.
        """
        target = self.state.current_name
        try:
            result = subprocess.run(
                ["iw", "dev", target, "set", "channel", str(channel)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                self.state.channel = channel
                log.debug(f"Channel set to {channel} on {target}")
                return True
            else:
                log.warning(
                    f"Failed to set channel {channel} on {target}: "
                    f"{result.stderr.strip()}"
                )
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.error(f"Error setting channel: {e}")
            return False

    def get_status(self) -> Dict[str, object]:
        """
        Get the current status of the monitor interface.

        Returns:
            Dictionary with current state information.
        """
        return self.state.to_dict()

    # ─── Private: Method Execution ────────────────────────────────────────────

    def _try_method(self, method: MonitorMethod) -> bool:
        """
        Try to enable monitor mode using the given method, with retries.

        Args:
            method: The MonitorMethod to attempt.

        Returns:
            True if successful.
        """
        for attempt in range(1, self._retry_count + 1):
            log.debug(
                f"Attempt {attempt}/{self._retry_count} "
                f"for method '{method.name}'"
            )

            if method.name == "airmon-ng":
                success = self._enable_airmon()
            elif method.name == "iw":
                success = self._enable_iw()
            elif method.name == "driver":
                success = self._enable_driver()
            else:
                log.error(f"Unknown method: {method.name}")
                return False

            if success:
                return True

            if attempt < self._retry_count:
                log.debug(f"Retrying in {self._retry_delay}s...")
                time.sleep(self._retry_delay)

        return False

    def _enable_airmon(self) -> bool:
        """Enable monitor mode using airmon-ng."""
        interface = self.state.original_name

        # Kill interfering processes
        self._run_cmd(["airmon-ng", "check", "kill"])

        # Start monitor mode
        success, output = self._run_cmd(["airmon-ng", "start", interface])
        if not success:
            return False

        # Determine the monitor interface name
        # airmon-ng typically creates <iface>mon or reports it
        mon_name = self._find_monitor_interface(interface, output)
        if mon_name:
            self.state.current_name = mon_name
        else:
            # Default assumption
            self.state.current_name = f"{interface}mon"

        # Verify monitor mode is active
        return self._verify_monitor_mode(self.state.current_name)

    def _enable_iw(self) -> bool:
        """Enable monitor mode using iw/ip commands."""
        interface = self.state.original_name

        # Bring interface down
        success, _ = self._run_cmd(
            ["ip", "link", "set", "dev", interface, "down"]
        )
        if not success:
            return False

        # Set monitor type
        success, _ = self._run_cmd(
            ["iw", "dev", interface, "set", "type", "monitor"]
        )
        if not success:
            # Restore interface up on failure
            self._run_cmd(["ip", "link", "set", "dev", interface, "up"])
            return False

        # Optionally rename to <iface>mon
        mon_name = f"{interface}mon" if not interface.endswith("mon") else interface
        if mon_name != interface:
            success_rename, _ = self._run_cmd(
                ["ip", "link", "set", "dev", interface, "name", mon_name]
            )
            if not success_rename:
                # Keep original name
                mon_name = interface
                log.debug(f"Could not rename to {mon_name}, keeping {interface}")

        # Bring monitor interface up
        success, _ = self._run_cmd(
            ["ip", "link", "set", "dev", mon_name, "up"]
        )
        if not success:
            return False

        self.state.current_name = mon_name
        return True

    def _enable_driver(self) -> bool:
        """Enable monitor mode using driver-specific commands (iwconfig)."""
        interface = self.state.original_name

        # Bring interface down
        success, _ = self._run_cmd(
            ["ip", "link", "set", "dev", interface, "down"]
        )
        if not success:
            return False

        # Set monitor mode via iwconfig
        success, _ = self._run_cmd(
            ["iwconfig", interface, "mode", "monitor"]
        )
        if not success:
            self._run_cmd(["ip", "link", "set", "dev", interface, "up"])
            return False

        # Bring interface up
        success, _ = self._run_cmd(
            ["ip", "link", "set", "dev", interface, "up"]
        )
        if not success:
            return False

        self.state.current_name = interface
        return True

    def _disable_airmon(self) -> bool:
        """Disable monitor mode using airmon-ng."""
        mon_name = self.state.current_name
        success, _ = self._run_cmd(["airmon-ng", "stop", mon_name])
        if success:
            # Restart network manager if available
            self._run_cmd(["systemctl", "start", "NetworkManager"])
        return success

    def _disable_iw(self) -> bool:
        """Disable monitor mode using iw/ip commands."""
        current = self.state.current_name
        original = self.state.original_name

        # Bring down
        self._run_cmd(["ip", "link", "set", "dev", current, "down"])

        # Set managed mode
        self._run_cmd(["iw", "dev", current, "set", "type", "managed"])

        # Rename back if needed
        if current != original:
            self._run_cmd(
                ["ip", "link", "set", "dev", current, "name", original]
            )

        # Restore original MAC if saved
        if self.state.original_mac:
            self._run_cmd(
                ["ip", "link", "set", "dev", original, "address", self.state.original_mac]
            )

        # Bring up
        success, _ = self._run_cmd(
            ["ip", "link", "set", "dev", original, "up"]
        )
        return success

    def _disable_driver(self) -> bool:
        """Disable monitor mode using driver-specific commands."""
        current = self.state.current_name

        self._run_cmd(["ip", "link", "set", "dev", current, "down"])
        self._run_cmd(["iwconfig", current, "mode", "managed"])
        success, _ = self._run_cmd(
            ["ip", "link", "set", "dev", current, "up"]
        )
        return success

    # ─── Private: Helpers ─────────────────────────────────────────────────────

    def _run_cmd(
        self, cmd: List[str], timeout: int = 10
    ) -> Tuple[bool, str]:
        """Run a shell command and return (success, output)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip()
            if result.returncode != 0:
                err = result.stderr.strip()
                log.debug(f"Command failed: {' '.join(cmd)} -> {err}")
                return (False, err)
            return (True, output)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            log.debug(f"Error running {' '.join(cmd)}: {e}")
            return (False, str(e))

    def _find_monitor_interface(self, base_interface: str, airmon_output: str) -> Optional[str]:
        """Parse airmon-ng output to find the created monitor interface name."""
        # Look for patterns like "(monitor mode vif enabled on wlan0mon)"
        # or "monitor mode enabled on wlan0mon"
        patterns = [
            rf"enabled\s+(?:for|on)\s+\[?([^\]\s]+)",
            rf"({re.escape(base_interface)}mon)\b",
            rf"monitor\s+mode.*?(\w+mon)\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, airmon_output, re.IGNORECASE)
            if match:
                return match.group(1)

        # Check if <iface>mon exists in the system
        mon_name = f"{base_interface}mon"
        if os.path.exists(f"/sys/class/net/{mon_name}"):
            return mon_name

        return None

    def _verify_monitor_mode(self, interface: str) -> bool:
        """Verify that the interface is actually in monitor mode."""
        success, output = self._run_cmd(["iw", "dev", interface, "info"])
        if success and "type monitor" in output:
            return True

        # Also check via iwconfig as a fallback
        success, output = self._run_cmd(["iwconfig", interface])
        if success and "Mode:Monitor" in output:
            return True

        return False

    def _get_mac_address(self, interface: str) -> Optional[str]:
        """Get the MAC address for an interface."""
        success, output = self._run_cmd(["ip", "link", "show", interface])
        if not success:
            return None

        mac_match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", output)
        if mac_match:
            return mac_match.group(1).lower()
        return None

    def _force_restore(self) -> None:
        """Last resort: force interface back to managed mode."""
        current = self.state.current_name
        original = self.state.original_name
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", current, "down"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["iw", "dev", current, "set", "type", "managed"],
                capture_output=True, timeout=5
            )
            if current != original:
                subprocess.run(
                    ["ip", "link", "set", "dev", current, "name", original],
                    capture_output=True, timeout=5
                )
            subprocess.run(
                ["ip", "link", "set", "dev", original, "up"],
                capture_output=True, timeout=5
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    # ─── Private: Cleanup Registration ────────────────────────────────────────

    def _register_cleanup(self) -> None:
        """Register atexit handler and signal handlers for cleanup."""
        if self._cleanup_registered:
            return

        # Register atexit handler
        atexit.register(self.cleanup)

        # Register signal handlers (only on Linux, and only for main thread safety)
        if IS_LINUX:
            try:
                self._original_sigint = signal.getsignal(signal.SIGINT)
                self._original_sigterm = signal.getsignal(signal.SIGTERM)
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
            except (ValueError, OSError):
                # Cannot set signal handlers outside main thread
                log.warning("Could not register signal handlers (not in main thread)")

        self._cleanup_registered = True
        log.debug("Cleanup handlers registered (atexit + signals)")

    def _signal_handler(self, signum: int, frame: object) -> None:
        """Handle SIGINT/SIGTERM by running cleanup, then re-raising."""
        log.info(f"Received signal {signum}, cleaning up monitor mode...")
        self.cleanup()

        # Restore original signal handler and re-raise
        if signum == signal.SIGINT and self._original_sigint:
            signal.signal(signal.SIGINT, self._original_sigint)
            if callable(self._original_sigint):
                self._original_sigint(signum, frame)
        elif signum == signal.SIGTERM and self._original_sigterm:
            signal.signal(signal.SIGTERM, self._original_sigterm)
            if callable(self._original_sigterm):
                self._original_sigterm(signum, frame)
