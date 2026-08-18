"""
posframework.native.state_machine - ctypes wrapper for libstate_machine.so

Provides a validated state machine with:
- Legal state transition enforcement
- Concurrent attack target tracking
- Session timing and battery safety
- Per-state time statistics

Used by autopwn_engine.py for high-performance state management.
Falls back to Python implementation if native library is not compiled.
"""

import ctypes
import time
from ctypes import (c_int, c_uint64, c_char_p, c_void_p, Structure, POINTER)
from typing import Dict, List, Optional

from posframework.config import log
from posframework.native import get_lib

# --- State Constants ---

STATE_IDLE = 0
STATE_SCANNING = 1
STATE_ANALYZING = 2
STATE_ATTACKING = 3
STATE_CRACKING = 4
STATE_PAUSED = 5
STATE_STOPPING = 6
STATE_COUNT = 7

STATE_NAMES = [
    "IDLE", "SCANNING", "ANALYZING", "ATTACKING",
    "CRACKING", "PAUSED", "STOPPING",
]

# Attack status
ATTACK_PENDING = 0
ATTACK_ACTIVE = 1
ATTACK_SUCCESS = 2
ATTACK_FAILED = 3
ATTACK_TIMEOUT = 4

MAX_CONCURRENT = 8


# --- ctypes Structs ---

class SmStats(Structure):
    """Mirrors sm_stats_t from state_machine.h."""
    _fields_ = [
        ("session_start", c_uint64),
        ("total_scan_time", c_uint64),
        ("total_attack_time", c_uint64),
        ("total_crack_time", c_uint64),
        ("transition_count", c_int),
        ("targets_attacked", c_int),
        ("targets_cracked", c_int),
        ("targets_failed", c_int),
        ("scans_completed", c_int),
    ]


# --- Native Library Setup ---

_lib = get_lib("libstate_machine")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    _lib.sm_create.argtypes = [c_int, c_uint64, c_int]
    _lib.sm_create.restype = c_void_p

    _lib.sm_destroy.argtypes = [c_void_p]
    _lib.sm_destroy.restype = None

    _lib.sm_get_state.argtypes = [c_void_p]
    _lib.sm_get_state.restype = c_int

    _lib.sm_can_transition.argtypes = [c_void_p, c_int]
    _lib.sm_can_transition.restype = c_int

    _lib.sm_transition.argtypes = [c_void_p, c_int]
    _lib.sm_transition.restype = c_int

    _lib.sm_register_attack.argtypes = [c_void_p, c_char_p, c_int, c_uint64]
    _lib.sm_register_attack.restype = c_int

    _lib.sm_update_attack.argtypes = [c_void_p, c_int, c_int]
    _lib.sm_update_attack.restype = c_int

    _lib.sm_active_attacks.argtypes = [c_void_p]
    _lib.sm_active_attacks.restype = c_int

    _lib.sm_check_timeouts.argtypes = [c_void_p, c_uint64]
    _lib.sm_check_timeouts.restype = c_int

    _lib.sm_check_duration.argtypes = [c_void_p, c_uint64]
    _lib.sm_check_duration.restype = c_int

    _lib.sm_check_battery.argtypes = [c_void_p, c_int]
    _lib.sm_check_battery.restype = c_int

    _lib.sm_get_stats.argtypes = [c_void_p, POINTER(SmStats)]
    _lib.sm_get_stats.restype = c_int

    _lib.sm_state_name.argtypes = [c_int]
    _lib.sm_state_name.restype = c_char_p

    _lib.sm_reset.argtypes = [c_void_p]
    _lib.sm_reset.restype = None

    log.debug("state_machine: using native C implementation")
else:
    log.warning("state_machine: libstate_machine.so not available, using Python fallback")


# --- Valid Transitions Table (for fallback) ---

_VALID_TRANSITIONS = {
    STATE_IDLE: {STATE_SCANNING, STATE_STOPPING},
    STATE_SCANNING: {STATE_ANALYZING, STATE_PAUSED, STATE_STOPPING},
    STATE_ANALYZING: {STATE_SCANNING, STATE_ATTACKING, STATE_PAUSED, STATE_STOPPING},
    STATE_ATTACKING: {STATE_SCANNING, STATE_ANALYZING, STATE_CRACKING, STATE_PAUSED, STATE_STOPPING},
    STATE_CRACKING: {STATE_SCANNING, STATE_ANALYZING, STATE_PAUSED, STATE_STOPPING},
    STATE_PAUSED: {STATE_IDLE, STATE_SCANNING, STATE_ANALYZING, STATE_ATTACKING, STATE_STOPPING},
    STATE_STOPPING: {STATE_IDLE},
}


# --- Public API ---

class NativeStateMachine:
    """
    High-performance state machine for AutoPwn engine.

    Enforces valid state transitions, tracks concurrent attacks,
    monitors session duration, and checks battery safety.

    Usage:
        sm = NativeStateMachine(max_concurrent=3, max_duration_sec=3600)
        sm.transition(STATE_SCANNING)
        slot = sm.register_attack("AA:BB:CC:DD:EE:FF", channel=6)
        sm.update_attack(slot, ATTACK_SUCCESS)
    """

    def __init__(self, max_concurrent: int = 3,
                 max_duration_sec: int = 0,
                 battery_threshold: int = 20) -> None:
        self._handle = None
        self._py_state = STATE_IDLE
        self._py_attacks: Dict[int, Dict] = {}
        self._py_stats = {
            "transition_count": 0,
            "targets_attacked": 0,
            "targets_cracked": 0,
            "targets_failed": 0,
            "scans_completed": 0,
        }
        self._max_concurrent = max_concurrent
        self._start_time = time.monotonic()

        max_duration_ms = max_duration_sec * 1000 if max_duration_sec > 0 else 0

        if _USE_NATIVE:
            handle = _lib.sm_create(max_concurrent, max_duration_ms, battery_threshold)
            if handle:
                self._handle = handle
                self._use_native = True
            else:
                self._use_native = False
        else:
            self._use_native = False

    @property
    def state(self) -> int:
        """Get current state."""
        if self._use_native and self._handle:
            return _lib.sm_get_state(self._handle)
        return self._py_state

    @property
    def state_name(self) -> str:
        """Get current state name string."""
        s = self.state
        if s < 0 or s >= STATE_COUNT:
            return "UNKNOWN"
        return STATE_NAMES[s]

    def can_transition(self, to_state: int) -> bool:
        """Check if a transition is valid."""
        if self._use_native and self._handle:
            return bool(_lib.sm_can_transition(self._handle, to_state))
        return to_state in _VALID_TRANSITIONS.get(self._py_state, set())

    def transition(self, to_state: int) -> bool:
        """
        Attempt a state transition.

        Returns:
            True if transition succeeded, False if invalid.
        """
        if self._use_native and self._handle:
            result = _lib.sm_transition(self._handle, to_state)
            return result == 0
        else:
            if to_state not in _VALID_TRANSITIONS.get(self._py_state, set()):
                return False
            self._py_state = to_state
            self._py_stats["transition_count"] += 1
            return True

    def register_attack(self, bssid: str, channel: int = 0,
                        timeout_sec: int = 300) -> int:
        """
        Register an attack target in a concurrent slot.

        Returns:
            Slot index on success, -1 if no slots available.
        """
        timeout_ms = timeout_sec * 1000

        if self._use_native and self._handle:
            return _lib.sm_register_attack(
                self._handle, bssid.encode("utf-8"), channel, timeout_ms
            )
        else:
            active = sum(1 for a in self._py_attacks.values()
                         if a["status"] == ATTACK_ACTIVE)
            if active >= self._max_concurrent:
                return -1
            slot = len(self._py_attacks)
            self._py_attacks[slot] = {
                "bssid": bssid,
                "channel": channel,
                "status": ATTACK_ACTIVE,
                "start": time.monotonic(),
                "timeout": timeout_sec,
            }
            self._py_stats["targets_attacked"] += 1
            return slot

    def update_attack(self, slot: int, status: int) -> bool:
        """Update the status of an attack slot."""
        if self._use_native and self._handle:
            return _lib.sm_update_attack(self._handle, slot, status) == 0
        else:
            if slot not in self._py_attacks:
                return False
            self._py_attacks[slot]["status"] = status
            if status == ATTACK_SUCCESS:
                self._py_stats["targets_cracked"] += 1
            elif status in (ATTACK_FAILED, ATTACK_TIMEOUT):
                self._py_stats["targets_failed"] += 1
            return True

    def active_attacks(self) -> int:
        """Get number of currently active attacks."""
        if self._use_native and self._handle:
            return _lib.sm_active_attacks(self._handle)
        return sum(1 for a in self._py_attacks.values()
                   if a["status"] == ATTACK_ACTIVE)

    def check_timeouts(self) -> int:
        """Check for and mark timed-out attacks."""
        if self._use_native and self._handle:
            now_ms = int(time.monotonic() * 1000)
            return _lib.sm_check_timeouts(self._handle, now_ms)
        else:
            now = time.monotonic()
            timed_out = 0
            for slot, attack in self._py_attacks.items():
                if attack["status"] == ATTACK_ACTIVE:
                    if now - attack["start"] >= attack["timeout"]:
                        attack["status"] = ATTACK_TIMEOUT
                        self._py_stats["targets_failed"] += 1
                        timed_out += 1
            return timed_out

    def check_duration(self) -> bool:
        """Check if session duration limit has been reached."""
        if self._use_native and self._handle:
            now_ms = int(time.monotonic() * 1000)
            return bool(_lib.sm_check_duration(self._handle, now_ms))
        return False

    def check_battery(self, battery_percent: int) -> bool:
        """Check if battery is below threshold."""
        if self._use_native and self._handle:
            return bool(_lib.sm_check_battery(self._handle, battery_percent))
        return False

    def get_stats(self) -> Dict:
        """Get session statistics."""
        if self._use_native and self._handle:
            stats = SmStats()
            if _lib.sm_get_stats(self._handle, ctypes.byref(stats)) == 0:
                return {
                    "session_start_ms": stats.session_start,
                    "total_scan_time_ms": stats.total_scan_time,
                    "total_attack_time_ms": stats.total_attack_time,
                    "total_crack_time_ms": stats.total_crack_time,
                    "transition_count": stats.transition_count,
                    "targets_attacked": stats.targets_attacked,
                    "targets_cracked": stats.targets_cracked,
                    "targets_failed": stats.targets_failed,
                    "scans_completed": stats.scans_completed,
                }
        return dict(self._py_stats)

    def reset(self) -> None:
        """Reset state machine to IDLE."""
        if self._use_native and self._handle:
            _lib.sm_reset(self._handle)
        else:
            self._py_state = STATE_IDLE
            self._py_attacks.clear()
            self._py_stats = {k: 0 for k in self._py_stats}

    def close(self) -> None:
        """Destroy the state machine."""
        if self._use_native and self._handle:
            _lib.sm_destroy(self._handle)
            self._handle = None

    def __enter__(self) -> "NativeStateMachine":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        if self._handle:
            self.close()
