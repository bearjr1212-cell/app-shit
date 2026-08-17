"""
posframework.native.packet_engine - ctypes wrapper for libpacket_engine.so

Provides a RawSocket class for high-performance raw frame injection
via AF_PACKET sockets. Falls back to scapy sendp() if the native
library is not compiled.

Requires root/CAP_NET_RAW. Linux only.
"""

import ctypes
from ctypes import c_int, c_uint8, c_size_t, c_char_p, POINTER
from typing import List, Optional

from posframework.config import log
from posframework.native import get_lib

# ─── Native Library Setup ─────────────────────────────────────────────────────

_lib = get_lib("libpacket_engine")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # int init_raw_socket(const char *iface)
    _lib.init_raw_socket.argtypes = [c_char_p]
    _lib.init_raw_socket.restype = c_int

    # int send_frame(int sock_fd, const uint8_t *frame, size_t len)
    _lib.send_frame.argtypes = [c_int, POINTER(c_uint8), c_size_t]
    _lib.send_frame.restype = c_int

    # int send_frame_batch(int sock_fd, const uint8_t **frames, size_t *lens, int count)
    _lib.send_frame_batch.argtypes = [
        c_int,
        POINTER(POINTER(c_uint8)),
        POINTER(c_size_t),
        c_int,
    ]
    _lib.send_frame_batch.restype = c_int

    # void close_raw_socket(int sock_fd)
    _lib.close_raw_socket.argtypes = [c_int]
    _lib.close_raw_socket.restype = None

    log.debug("packet_engine: using native C implementation")
else:
    log.warning("packet_engine: libpacket_engine.so not available, using scapy fallback")


# ─── RawSocket Class ──────────────────────────────────────────────────────────


class RawSocket:
    """
    High-performance raw socket for 802.11 frame injection.

    Uses native C AF_PACKET implementation when available,
    falls back to scapy's sendp() otherwise.

    Usage:
        sock = RawSocket()
        sock.init_raw_socket("wlan0mon")
        sock.send_frame(frame_bytes)
        sock.close()
    """

    def __init__(self) -> None:
        self._fd: int = -1
        self._iface: Optional[str] = None
        self._scapy_l2: Optional[object] = None

    @property
    def fd(self) -> int:
        """Return the underlying socket file descriptor (-1 if not open)."""
        return self._fd

    @property
    def iface(self) -> Optional[str]:
        """Return the bound interface name."""
        return self._iface

    def init_raw_socket(self, iface: str) -> int:
        """
        Initialize a raw socket bound to the given interface.

        Args:
            iface: Network interface name (e.g., 'wlan0mon')

        Returns:
            Socket file descriptor on success, -1 on error.

        Raises:
            RuntimeError: If socket creation fails (native mode).
        """
        self._iface = iface

        if _USE_NATIVE:
            fd = _lib.init_raw_socket(iface.encode("utf-8"))
            if fd < 0:
                log.error(f"packet_engine: init_raw_socket('{iface}') failed (fd={fd})")
                raise RuntimeError(f"Failed to open raw socket on {iface}")
            self._fd = fd
            log.debug(f"packet_engine: raw socket fd={fd} bound to {iface}")
            return fd
        else:
            # Scapy fallback - import lazily
            try:
                from scapy.all import conf, L2Socket
                self._scapy_l2 = L2Socket(iface=iface)
                self._fd = self._scapy_l2.ins.fileno()
                log.debug(f"packet_engine: scapy L2Socket on {iface}")
                return self._fd
            except Exception as e:
                log.error(f"packet_engine: scapy fallback failed: {e}")
                raise RuntimeError(f"Failed to open raw socket on {iface}: {e}")

    def send_frame(self, data: bytes) -> int:
        """
        Send a single raw frame (including radiotap header).

        Args:
            data: Complete frame bytes (radiotap + 802.11 frame)

        Returns:
            0 on success, -1 on error.
        """
        if _USE_NATIVE:
            if self._fd < 0:
                log.error("packet_engine: send_frame called on closed socket")
                return -1
            buf = (c_uint8 * len(data))(*data)
            result = _lib.send_frame(self._fd, buf, len(data))
            if result < 0:
                log.warning(f"packet_engine: send_frame failed (fd={self._fd})")
            return result
        else:
            # Scapy fallback
            try:
                from scapy.all import sendp, RadioTap
                if self._scapy_l2:
                    self._scapy_l2.send(RadioTap(data))
                else:
                    sendp(RadioTap(data), iface=self._iface, verbose=False)
                return 0
            except Exception as e:
                log.warning(f"packet_engine: scapy send_frame failed: {e}")
                return -1

    def send_batch(self, frames_list: List[bytes]) -> int:
        """
        Send a batch of raw frames.

        Args:
            frames_list: List of frame bytes (each including radiotap header)

        Returns:
            Number of frames successfully sent, or -1 on fatal error.
        """
        if not frames_list:
            return 0

        if _USE_NATIVE:
            if self._fd < 0:
                log.error("packet_engine: send_batch called on closed socket")
                return -1

            count = len(frames_list)

            # Build arrays of pointers and lengths
            frame_arrays = []
            for frame in frames_list:
                arr = (c_uint8 * len(frame))(*frame)
                frame_arrays.append(arr)

            # Array of pointers to uint8 arrays
            frames_ptr_type = POINTER(c_uint8) * count
            frames_ptrs = frames_ptr_type()
            for i, arr in enumerate(frame_arrays):
                frames_ptrs[i] = ctypes.cast(arr, POINTER(c_uint8))

            # Array of lengths
            lens_type = c_size_t * count
            lens = lens_type(*[len(f) for f in frames_list])

            result = _lib.send_frame_batch(
                self._fd,
                ctypes.cast(frames_ptrs, POINTER(POINTER(c_uint8))),
                lens,
                count,
            )
            if result < 0:
                log.warning(f"packet_engine: send_batch failed (fd={self._fd})")
            return result
        else:
            # Scapy fallback - send one by one
            sent = 0
            for frame in frames_list:
                if self.send_frame(frame) == 0:
                    sent += 1
            return sent

    def close(self) -> None:
        """Close the raw socket and release resources."""
        if _USE_NATIVE:
            if self._fd >= 0:
                _lib.close_raw_socket(self._fd)
                log.debug(f"packet_engine: closed socket fd={self._fd}")
                self._fd = -1
        else:
            if self._scapy_l2:
                try:
                    self._scapy_l2.close()
                except Exception:
                    pass
                self._scapy_l2 = None
            self._fd = -1

        self._iface = None

    def __enter__(self) -> "RawSocket":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        if self._fd >= 0:
            self.close()
