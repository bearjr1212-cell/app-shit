"""
posframework.native.target_pqueue - ctypes wrapper for libtarget_pqueue.so

Provides a high-performance priority queue for target selection with
native C acceleration. Used by target_queue.py and target_scorer.py
for fast re-prioritization during scanning.

Falls back to Python heapq if the native library is not compiled.
"""

import ctypes
import heapq
from ctypes import (c_int, c_uint32, c_double, c_char, c_char_p,
                    c_void_p, Structure, POINTER)
from typing import Dict, List, Optional

from posframework.config import log
from posframework.native import get_lib

# --- ctypes Struct Definitions ---

BSSID_LEN = 18
SSID_LEN = 33
PQUEUE_MAX_TARGETS = 512


class PQueueTarget(Structure):
    """Mirrors pqueue_target_t from target_pqueue.h."""
    _fields_ = [
        ("bssid", c_char * BSSID_LEN),
        ("ssid", c_char * SSID_LEN),
        ("rssi", c_int),
        ("client_count", c_int),
        ("vector_count", c_int),
        ("is_pos", c_int),
        ("is_enterprise", c_int),
        ("channel", c_int),
        ("cooldown_until", c_uint32),
        ("priority", c_double),
    ]


# --- Native Library Setup ---

_lib = get_lib("libtarget_pqueue")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    _lib.pqueue_create.argtypes = []
    _lib.pqueue_create.restype = c_void_p

    _lib.pqueue_destroy.argtypes = [c_void_p]
    _lib.pqueue_destroy.restype = None

    _lib.pqueue_clear.argtypes = [c_void_p]
    _lib.pqueue_clear.restype = None

    _lib.pqueue_calculate_priority.argtypes = [c_int, c_int, c_int, c_int, c_int]
    _lib.pqueue_calculate_priority.restype = c_double

    _lib.pqueue_insert.argtypes = [
        c_void_p, c_char_p, c_char_p,
        c_int, c_int, c_int, c_int, c_int, c_int,
    ]
    _lib.pqueue_insert.restype = c_int

    _lib.pqueue_peek.argtypes = [c_void_p, POINTER(PQueueTarget)]
    _lib.pqueue_peek.restype = c_int

    _lib.pqueue_pop.argtypes = [c_void_p, POINTER(PQueueTarget)]
    _lib.pqueue_pop.restype = c_int

    _lib.pqueue_size.argtypes = [c_void_p]
    _lib.pqueue_size.restype = c_int

    _lib.pqueue_batch_sort.argtypes = [POINTER(PQueueTarget), c_int]
    _lib.pqueue_batch_sort.restype = c_int

    _lib.pqueue_set_cooldown.argtypes = [c_void_p, c_char_p, c_uint32]
    _lib.pqueue_set_cooldown.restype = c_int

    _lib.pqueue_get_sorted.argtypes = [c_void_p, POINTER(PQueueTarget), c_int]
    _lib.pqueue_get_sorted.restype = c_int

    log.debug("target_pqueue: using native C implementation")
else:
    log.warning("target_pqueue: libtarget_pqueue.so not available, using Python fallback")


# --- Public API ---

def calculate_priority(rssi: int, is_pos: bool, is_enterprise: bool,
                       client_count: int, vector_count: int) -> float:
    """
    Calculate priority score for a target.

    Args:
        rssi: Signal strength (-100 to 0)
        is_pos: Whether target is a POS system
        is_enterprise: Whether target is enterprise
        client_count: Number of associated clients
        vector_count: Number of attack vectors

    Returns:
        Priority score (higher = more interesting).
    """
    if _USE_NATIVE:
        return _lib.pqueue_calculate_priority(
            rssi, 1 if is_pos else 0, 1 if is_enterprise else 0,
            client_count, vector_count
        )
    else:
        score = 0.0
        if is_pos:
            score += 150.0
        clamped = max(-100, min(0, rssi))
        score += (clamped + 100) * 0.5
        score += min(client_count * 5, 30)
        score += vector_count * 3.0
        if is_enterprise:
            score += 25.0
        return score


class NativePriorityQueue:
    """
    High-performance priority queue for WiFi targets.

    Uses a native C max-heap for O(log n) operations.
    Falls back to Python heapq if native library unavailable.
    """

    def __init__(self) -> None:
        self._handle = None
        self._py_heap: List = []

        if _USE_NATIVE:
            handle = _lib.pqueue_create()
            if handle:
                self._handle = handle
                self._use_native = True
            else:
                self._use_native = False
                log.warning("target_pqueue: native create failed")
        else:
            self._use_native = False

    @property
    def size(self) -> int:
        """Number of targets in queue."""
        if self._use_native and self._handle:
            return _lib.pqueue_size(self._handle)
        return len(self._py_heap)

    def clear(self) -> None:
        """Remove all targets from queue."""
        if self._use_native and self._handle:
            _lib.pqueue_clear(self._handle)
        else:
            self._py_heap.clear()

    def insert(self, bssid: str, ssid: str, rssi: int,
               client_count: int, vector_count: int,
               is_pos: bool = False, is_enterprise: bool = False,
               channel: int = 0) -> int:
        """
        Insert a target into the priority queue.

        Returns:
            0 on success, -1 if queue full.
        """
        if self._use_native and self._handle:
            return _lib.pqueue_insert(
                self._handle,
                bssid.encode("utf-8"),
                ssid.encode("utf-8"),
                rssi, client_count, vector_count,
                1 if is_pos else 0,
                1 if is_enterprise else 0,
                channel,
            )
        else:
            priority = calculate_priority(rssi, is_pos, is_enterprise,
                                          client_count, vector_count)
            # Python heapq is min-heap, negate for max-heap behavior
            heapq.heappush(self._py_heap, (
                -priority,
                {
                    "bssid": bssid,
                    "ssid": ssid,
                    "rssi": rssi,
                    "client_count": client_count,
                    "vector_count": vector_count,
                    "is_pos": is_pos,
                    "is_enterprise": is_enterprise,
                    "channel": channel,
                    "priority": priority,
                }
            ))
            return 0

    def peek(self) -> Optional[Dict]:
        """Get highest-priority target without removing it."""
        if self._use_native and self._handle:
            target = PQueueTarget()
            if _lib.pqueue_peek(self._handle, ctypes.byref(target)) == 0:
                return self._target_to_dict(target)
            return None
        else:
            if self._py_heap:
                return self._py_heap[0][1]
            return None

    def pop(self) -> Optional[Dict]:
        """Remove and return highest-priority target."""
        if self._use_native and self._handle:
            target = PQueueTarget()
            if _lib.pqueue_pop(self._handle, ctypes.byref(target)) == 0:
                return self._target_to_dict(target)
            return None
        else:
            if self._py_heap:
                return heapq.heappop(self._py_heap)[1]
            return None

    def set_cooldown(self, bssid: str, seconds: int) -> int:
        """Apply cooldown to prevent re-attacking a target."""
        if self._use_native and self._handle:
            return _lib.pqueue_set_cooldown(
                self._handle, bssid.encode("utf-8"), seconds
            )
        return -1

    def get_sorted(self, max_count: int = 50) -> List[Dict]:
        """Get all targets sorted by priority (descending)."""
        if self._use_native and self._handle:
            arr_type = PQueueTarget * max_count
            arr = arr_type()
            count = _lib.pqueue_get_sorted(self._handle, arr, max_count)
            if count < 0:
                return []
            return [self._target_to_dict(arr[i]) for i in range(count)]
        else:
            sorted_heap = sorted(self._py_heap, key=lambda x: x[0])
            return [item[1] for item in sorted_heap[:max_count]]

    def close(self) -> None:
        """Destroy the queue and free resources."""
        if self._use_native and self._handle:
            _lib.pqueue_destroy(self._handle)
            self._handle = None

    def __enter__(self) -> "NativePriorityQueue":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        if self._handle:
            self.close()

    @staticmethod
    def _target_to_dict(target: PQueueTarget) -> Dict:
        """Convert PQueueTarget struct to Python dict."""
        return {
            "bssid": target.bssid.decode("utf-8", errors="replace").rstrip("\x00"),
            "ssid": target.ssid.decode("utf-8", errors="replace").rstrip("\x00"),
            "rssi": target.rssi,
            "client_count": target.client_count,
            "vector_count": target.vector_count,
            "is_pos": bool(target.is_pos),
            "is_enterprise": bool(target.is_enterprise),
            "channel": target.channel,
            "cooldown_until": target.cooldown_until,
            "priority": target.priority,
        }
