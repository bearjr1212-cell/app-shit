"""
posframework.native.channel_hop - ctypes wrapper for libchannel_hop.so

Provides direct nl80211 channel switching without iw subprocess calls.
Falls back to subprocess `iw` calls if the native library is not compiled.

Requires root/CAP_NET_ADMIN. Linux only.
"""

import ctypes
from ctypes import c_int, c_char_p
import subprocess
import re
from typing import Optional

from posframework.config import log
from posframework.native import get_lib

# ─── Native Library Setup ─────────────────────────────────────────────────────

_lib = get_lib("libchannel_hop")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # int set_channel(const char *iface, int channel)
    _lib.set_channel.argtypes = [c_char_p, c_int]
    _lib.set_channel.restype = c_int

    # int set_channel_ht40(const char *iface, int channel, int ht40_plus)
    _lib.set_channel_ht40.argtypes = [c_char_p, c_int, c_int]
    _lib.set_channel_ht40.restype = c_int

    # int get_channel(const char *iface)
    _lib.get_channel.argtypes = [c_char_p]
    _lib.get_channel.restype = c_int

    log.debug("channel_hop: using native nl80211 implementation")
else:
    log.warning("channel_hop: libchannel_hop.so not available, using iw subprocess fallback")


# ─── Channel-to-Frequency Helpers ─────────────────────────────────────────────

def _channel_to_freq(channel: int) -> int:
    """Convert WiFi channel number to frequency in MHz."""
    if 1 <= channel <= 14:
        if channel == 14:
            return 2484
        return 2407 + channel * 5
    elif 36 <= channel <= 165:
        return 5000 + channel * 5
    return 0


def _freq_to_channel(freq: int) -> int:
    """Convert frequency in MHz to WiFi channel number."""
    if freq == 2484:
        return 14
    elif 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    elif 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    return 0


# ─── Public API ────────────────────────────────────────────────────────────────

def set_channel(iface: str, channel: int) -> bool:
    """
    Set the channel on a wireless interface (20MHz width).

    Args:
        iface: Interface name (e.g., 'wlan0mon')
        channel: Channel number (1-14 for 2.4GHz, 36-165 for 5GHz)

    Returns:
        True on success, False on failure.
    """
    if _USE_NATIVE:
        result = _lib.set_channel(iface.encode("utf-8"), channel)
        if result < 0:
            log.warning(f"channel_hop: set_channel('{iface}', {channel}) failed")
            return False
        return True
    else:
        return _iw_set_channel(iface, channel)


def set_channel_ht40(iface: str, channel: int, ht40_plus: bool = True) -> bool:
    """
    Set the channel with HT40+/HT40- bandwidth.

    Args:
        iface: Interface name (e.g., 'wlan0mon')
        channel: Channel number
        ht40_plus: True for HT40+, False for HT40-

    Returns:
        True on success, False on failure.
    """
    if _USE_NATIVE:
        result = _lib.set_channel_ht40(
            iface.encode("utf-8"), channel, 1 if ht40_plus else 0
        )
        if result < 0:
            log.warning(
                f"channel_hop: set_channel_ht40('{iface}', {channel}, "
                f"{'HT40+' if ht40_plus else 'HT40-'}) failed"
            )
            return False
        return True
    else:
        return _iw_set_channel_ht40(iface, channel, ht40_plus)


def get_channel(iface: str) -> int:
    """
    Get the current channel of a wireless interface.

    Args:
        iface: Interface name (e.g., 'wlan0mon')

    Returns:
        Channel number on success, -1 on error.
    """
    if _USE_NATIVE:
        result = _lib.get_channel(iface.encode("utf-8"))
        if result < 0:
            log.warning(f"channel_hop: get_channel('{iface}') failed")
        return result
    else:
        return _iw_get_channel(iface)


# ─── Subprocess Fallbacks ──────────────────────────────────────────────────────

def _iw_set_channel(iface: str, channel: int) -> bool:
    """Set channel using iw subprocess (fallback)."""
    try:
        freq = _channel_to_freq(channel)
        if freq == 0:
            log.error(f"channel_hop: invalid channel {channel}")
            return False
        result = subprocess.run(
            ["iw", "dev", iface, "set", "freq", str(freq)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            log.warning(
                f"channel_hop: iw set freq failed: {result.stderr.strip()}"
            )
            return False
        return True
    except FileNotFoundError:
        log.error("channel_hop: 'iw' command not found")
        return False
    except subprocess.TimeoutExpired:
        log.error("channel_hop: iw command timed out")
        return False
    except Exception as e:
        log.error(f"channel_hop: iw fallback error: {e}")
        return False


def _iw_set_channel_ht40(iface: str, channel: int, ht40_plus: bool) -> bool:
    """Set channel with HT40 width using iw subprocess (fallback)."""
    try:
        freq = _channel_to_freq(channel)
        if freq == 0:
            log.error(f"channel_hop: invalid channel {channel}")
            return False
        ht_str = "HT40+" if ht40_plus else "HT40-"
        result = subprocess.run(
            ["iw", "dev", iface, "set", "freq", str(freq), ht_str],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            log.warning(
                f"channel_hop: iw set freq HT40 failed: {result.stderr.strip()}"
            )
            return False
        return True
    except FileNotFoundError:
        log.error("channel_hop: 'iw' command not found")
        return False
    except subprocess.TimeoutExpired:
        log.error("channel_hop: iw command timed out")
        return False
    except Exception as e:
        log.error(f"channel_hop: iw fallback error: {e}")
        return False


def _iw_get_channel(iface: str) -> int:
    """Get current channel using iw subprocess (fallback)."""
    try:
        result = subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            log.warning(f"channel_hop: iw info failed: {result.stderr.strip()}")
            return -1

        # Parse "channel X (YYYY MHz)" from output
        match = re.search(r"channel\s+(\d+)", result.stdout)
        if match:
            return int(match.group(1))

        # Try frequency-based parsing
        freq_match = re.search(r"(\d{4})\s+MHz", result.stdout)
        if freq_match:
            return _freq_to_channel(int(freq_match.group(1)))

        log.warning(f"channel_hop: could not parse channel from iw output")
        return -1
    except FileNotFoundError:
        log.error("channel_hop: 'iw' command not found")
        return -1
    except subprocess.TimeoutExpired:
        log.error("channel_hop: iw command timed out")
        return -1
    except Exception as e:
        log.error(f"channel_hop: iw fallback error: {e}")
        return -1
