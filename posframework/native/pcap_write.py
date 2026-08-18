"""
posframework.native.pcap_write - ctypes wrapper for libpcap_write.so

Provides fast PCAP file writing for handshake capture. Falls back
to Python struct-based PCAP writing if the native library is not compiled.

Used by handshake.py for writing captured EAPOL frames to standard
PCAP format compatible with hashcat and aircrack-ng.
"""

import ctypes
import struct
import time
from ctypes import c_int, c_uint8, c_uint32, c_uint64, c_size_t, c_char_p, c_void_p, POINTER
from typing import List, Optional, Tuple

from posframework.config import log
from posframework.native import get_lib

# --- Native Library Setup ---

_lib = get_lib("libpcap_write")
_USE_NATIVE = _lib is not None

if _USE_NATIVE:
    # pcap_writer_t *pcap_writer_open(const char *filename, uint32_t link_type, uint32_t snaplen)
    _lib.pcap_writer_open.argtypes = [c_char_p, c_uint32, c_uint32]
    _lib.pcap_writer_open.restype = c_void_p

    # int pcap_writer_write_frame(pcap_writer_t *writer,
    #                             const uint8_t *data, size_t len,
    #                             uint32_t ts_sec, uint32_t ts_usec)
    _lib.pcap_writer_write_frame.argtypes = [
        c_void_p, POINTER(c_uint8), c_size_t, c_uint32, c_uint32,
    ]
    _lib.pcap_writer_write_frame.restype = c_int

    # int pcap_writer_write_batch(pcap_writer_t *writer,
    #                             const uint8_t **frames, const size_t *lens,
    #                             const uint32_t *ts_secs, const uint32_t *ts_usecs,
    #                             int count)
    _lib.pcap_writer_write_batch.argtypes = [
        c_void_p,
        POINTER(POINTER(c_uint8)), POINTER(c_size_t),
        POINTER(c_uint32), POINTER(c_uint32),
        c_int,
    ]
    _lib.pcap_writer_write_batch.restype = c_int

    # void pcap_writer_close(pcap_writer_t *writer)
    _lib.pcap_writer_close.argtypes = [c_void_p]
    _lib.pcap_writer_close.restype = None

    # uint32_t pcap_writer_frame_count(const pcap_writer_t *writer)
    _lib.pcap_writer_frame_count.argtypes = [c_void_p]
    _lib.pcap_writer_frame_count.restype = c_uint32

    # uint64_t pcap_writer_file_size(const pcap_writer_t *writer)
    _lib.pcap_writer_file_size.argtypes = [c_void_p]
    _lib.pcap_writer_file_size.restype = c_uint64

    # int pcap_write_file(const char *filename, uint32_t link_type,
    #                     const uint8_t **frames, const size_t *lens,
    #                     const uint32_t *ts_secs, const uint32_t *ts_usecs,
    #                     int count)
    _lib.pcap_write_file.argtypes = [
        c_char_p, c_uint32,
        POINTER(POINTER(c_uint8)), POINTER(c_size_t),
        POINTER(c_uint32), POINTER(c_uint32),
        c_int,
    ]
    _lib.pcap_write_file.restype = c_int

    log.debug("pcap_write: using native C implementation")
else:
    log.warning("pcap_write: libpcap_write.so not available, using Python fallback")


# --- PCAP Constants ---

LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_RADIOTAP = 127

PCAP_MAGIC = 0xA1B2C3D4
PCAP_MAX_SNAPLEN = 65535


# --- Public API ---

class PcapWriter:
    """
    Fast PCAP file writer with native C acceleration.

    Creates standard PCAP files compatible with Wireshark,
    hashcat, aircrack-ng, and other tools.

    Usage:
        writer = PcapWriter("capture.pcap", LINKTYPE_RADIOTAP)
        writer.write_frame(frame_data)
        writer.close()
    """

    def __init__(self, filename: str, link_type: int = LINKTYPE_RADIOTAP,
                 snaplen: int = PCAP_MAX_SNAPLEN) -> None:
        self._filename = filename
        self._link_type = link_type
        self._snaplen = snaplen
        self._handle = None
        self._py_file = None
        self._frame_count = 0

        if _USE_NATIVE:
            handle = _lib.pcap_writer_open(
                filename.encode("utf-8"), link_type, snaplen
            )
            if not handle:
                log.warning(f"pcap_write: native open failed for '{filename}', using fallback")
                self._use_native = False
                self._open_fallback()
            else:
                self._handle = handle
                self._use_native = True
                log.debug(f"pcap_write: opened '{filename}' (native)")
        else:
            self._use_native = False
            self._open_fallback()

    def _open_fallback(self) -> None:
        """Open PCAP file using Python fallback."""
        self._py_file = open(self._filename, "wb")
        # Write global header
        header = struct.pack(
            "<IHHiIII",
            PCAP_MAGIC,  # magic
            2,           # version_major
            4,           # version_minor
            0,           # thiszone
            0,           # sigfigs
            self._snaplen,  # snaplen
            self._link_type,  # network
        )
        self._py_file.write(header)

    @property
    def frame_count(self) -> int:
        """Number of frames written."""
        if self._use_native and self._handle:
            return _lib.pcap_writer_frame_count(self._handle)
        return self._frame_count

    @property
    def file_size(self) -> int:
        """Current file size in bytes."""
        if self._use_native and self._handle:
            return _lib.pcap_writer_file_size(self._handle)
        return 0

    def write_frame(self, data: bytes, timestamp: Optional[float] = None) -> int:
        """
        Write a single frame to the PCAP file.

        Args:
            data: Frame data bytes
            timestamp: Unix timestamp (float). Uses current time if None.

        Returns:
            0 on success, -1 on error.
        """
        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)

        if self._use_native and self._handle:
            buf = (c_uint8 * len(data))(*data)
            result = _lib.pcap_writer_write_frame(
                self._handle, buf, len(data), ts_sec, ts_usec
            )
            if result < 0:
                log.warning(f"pcap_write: write_frame failed")
            return result
        else:
            return self._fallback_write_frame(data, ts_sec, ts_usec)

    def write_batch(self, frames: List[bytes],
                    timestamps: Optional[List[float]] = None) -> int:
        """
        Write multiple frames to the PCAP file.

        Args:
            frames: List of frame data bytes
            timestamps: Optional list of timestamps. Uses current time if None.

        Returns:
            Number of frames written, -1 on error.
        """
        if not frames:
            return 0

        now = time.time()
        if timestamps is None:
            timestamps = [now + i * 0.0001 for i in range(len(frames))]

        if self._use_native and self._handle:
            count = len(frames)

            # Build ctypes arrays
            frame_arrays = []
            for frame in frames:
                arr = (c_uint8 * len(frame))(*frame)
                frame_arrays.append(arr)

            frames_ptr_type = POINTER(c_uint8) * count
            frames_ptrs = frames_ptr_type()
            for i, arr in enumerate(frame_arrays):
                frames_ptrs[i] = ctypes.cast(arr, POINTER(c_uint8))

            lens_type = c_size_t * count
            lens = lens_type(*[len(f) for f in frames])

            ts_secs_type = c_uint32 * count
            ts_usecs_type = c_uint32 * count
            ts_secs = ts_secs_type(*[int(t) for t in timestamps])
            ts_usecs = ts_usecs_type(*[int((t - int(t)) * 1_000_000) for t in timestamps])

            result = _lib.pcap_writer_write_batch(
                self._handle,
                ctypes.cast(frames_ptrs, POINTER(POINTER(c_uint8))),
                lens, ts_secs, ts_usecs, count,
            )
            if result < 0:
                log.warning(f"pcap_write: write_batch failed")
            return result
        else:
            written = 0
            for frame, ts in zip(frames, timestamps):
                if self.write_frame(frame, ts) == 0:
                    written += 1
            return written

    def close(self) -> None:
        """Flush and close the PCAP file."""
        if self._use_native and self._handle:
            _lib.pcap_writer_close(self._handle)
            self._handle = None
        elif self._py_file:
            self._py_file.flush()
            self._py_file.close()
            self._py_file = None

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        if self._handle or self._py_file:
            self.close()

    # --- Fallback Implementation ---

    def _fallback_write_frame(self, data: bytes, ts_sec: int, ts_usec: int) -> int:
        """Write a frame using Python struct.pack()."""
        if not self._py_file:
            return -1

        cap_len = min(len(data), self._snaplen)
        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, cap_len, len(data))
        try:
            self._py_file.write(pkt_header)
            self._py_file.write(data[:cap_len])
            self._frame_count += 1
            return 0
        except IOError as e:
            log.warning(f"pcap_write: fallback write failed: {e}")
            return -1


# --- Module-level convenience function ---

def write_pcap(filename: str, frames: List[bytes],
               link_type: int = LINKTYPE_RADIOTAP,
               timestamps: Optional[List[float]] = None) -> int:
    """
    Write a complete PCAP file in one shot.

    Convenience function for exporting captured frames.

    Args:
        filename: Output file path
        frames: List of frame data bytes
        link_type: PCAP link layer type
        timestamps: Optional timestamps for each frame

    Returns:
        0 on success, -1 on error.
    """
    if not frames:
        return 0

    writer = PcapWriter(filename, link_type)
    result = writer.write_batch(frames, timestamps)
    writer.close()

    return 0 if result >= 0 else -1
