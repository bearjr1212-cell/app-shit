"""
posframework.native - Python ctypes wrappers for C acceleration libraries.

Attempts to load compiled .so libraries from ../lib/ directory.
Falls back gracefully to Python implementations if libraries are not compiled.
"""

import ctypes
import os
from pathlib import Path
from typing import Optional, Dict

from posframework.config import log

# Path to compiled shared libraries
_LIB_DIR = Path(__file__).resolve().parent.parent / "lib"

# Registry of loaded native libraries
_loaded_libs: Dict[str, Optional[ctypes.CDLL]] = {}

# Library names we expect to find
_LIB_NAMES = [
    "libpacket_engine",
    "libchannel_hop",
    "libcrypto_parse",
    "libdeauth_craft",
    "libbeacon_flood",
    "libarp_spoof",
    "libsnmp_encode",
    "libpcap_write",
    "libtarget_pqueue",
    "libstate_machine",
    "libcrypto_accel",
    "libtkip_mic",
    "libccmp_aes",
]


def _load_lib(name: str) -> Optional[ctypes.CDLL]:
    """
    Attempt to load a shared library by name from the lib directory.

    Args:
        name: Library name without extension (e.g., 'libpacket_engine')

    Returns:
        ctypes.CDLL instance if loaded, None otherwise.
    """
    if name in _loaded_libs:
        return _loaded_libs[name]

    so_path = _LIB_DIR / f"{name}.so"

    if so_path.exists():
        try:
            lib = ctypes.CDLL(str(so_path))
            _loaded_libs[name] = lib
            log.debug(f"native: loaded {so_path}")
            return lib
        except OSError as e:
            log.warning(f"native: failed to load {so_path}: {e}")
            _loaded_libs[name] = None
            return None
    else:
        log.debug(f"native: {so_path} not found, will use Python fallback")
        _loaded_libs[name] = None
        return None


def load_all() -> Dict[str, bool]:
    """
    Attempt to load all native libraries.

    Returns:
        Dict mapping library names to load success status.
    """
    results = {}
    for name in _LIB_NAMES:
        lib = _load_lib(name)
        results[name] = lib is not None
    return results


def get_lib(name: str) -> Optional[ctypes.CDLL]:
    """
    Get a loaded library by name (loads lazily on first access).

    Args:
        name: Library name without extension (e.g., 'libpacket_engine')

    Returns:
        ctypes.CDLL instance or None if not available.
    """
    return _load_lib(name)


# Eagerly attempt to load all libraries on import
_load_status = load_all()

# Report summary
_native_count = sum(1 for v in _load_status.values() if v)
if _native_count > 0:
    log.info(f"native: {_native_count}/{len(_LIB_NAMES)} C acceleration libraries loaded")
else:
    log.info("native: no C acceleration libraries found, using Python fallbacks")
