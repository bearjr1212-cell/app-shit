"""
Tkinter Pre-flight Safety Checks
---------------------------------
Prevents segmentation faults when Tkinter cannot initialize safely.

On headless systems (no $DISPLAY on Linux, no display server), attempting
tk.Tk() can cause a C-level segfault that bypasses Python exception handling.
This module provides:
  1. Environment/display checks before touching Tkinter
  2. A subprocess-based probe that forks a child process to test tk.Tk()
     initialization -- if the child segfaults, the parent detects the
     non-zero exit code and reports gracefully instead of crashing.
"""

import os
import sys
import subprocess


def check_display_available():
    """
    Check whether a display server is available for GUI rendering.

    Returns:
        tuple: (available: bool, reason: str)
            - available is True if a display appears to be accessible
            - reason describes why the display is unavailable (empty if available)
    """
    # On Linux/Unix, $DISPLAY must be set for X11-based Tk
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        display = os.environ.get("DISPLAY", "")
        wayland = os.environ.get("WAYLAND_DISPLAY", "")
        # Accept either X11 or Wayland display
        if not display and not wayland:
            return False, (
                "No display server detected. "
                "$DISPLAY and $WAYLAND_DISPLAY are both unset. "
                "Run with a display server or use X forwarding (e.g., ssh -X)."
            )

    # On Windows, the display is always available if the session is interactive
    if sys.platform == "win32":
        # Check if the process is running in a Windows service (non-interactive)
        try:
            import ctypes
            hWinSta = ctypes.windll.user32.GetProcessWindowStation()
            if hWinSta == 0:
                return False, "No window station available (running as a service?)."
        except (AttributeError, OSError):
            # If we can't check, assume display is available
            pass

    return True, ""


def probe_tkinter_subprocess():
    """
    Fork a child process that attempts to initialize tk.Tk().

    If the child segfaults or crashes, the parent captures the exit code
    and returns a failure result instead of crashing the main process.

    Returns:
        tuple: (success: bool, reason: str)
            - success is True if tkinter initialized without crashing
            - reason describes the failure if success is False
    """
    # The probe script: try to create and immediately destroy a Tk instance
    probe_script = (
        "import sys\n"
        "try:\n"
        "    import tkinter as tk\n"
        "    root = tk.Tk()\n"
        "    root.withdraw()\n"
        "    root.destroy()\n"
        "    sys.exit(0)\n"
        "except Exception as e:\n"
        "    print(str(e), file=sys.stderr)\n"
        "    sys.exit(1)\n"
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", probe_script],
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return False, "Tkinter initialization timed out (possible hang or freeze)."
    except OSError as e:
        return False, f"Failed to spawn tkinter probe process: {e}"

    if result.returncode == 0:
        return True, ""

    # Negative return codes on Unix indicate signal-based termination
    # e.g., -11 = SIGSEGV (segfault)
    if result.returncode < 0:
        import signal as _signal
        sig_num = -result.returncode
        sig_name = "unknown signal"
        try:
            sig_name = _signal.Signals(sig_num).name
        except (ValueError, AttributeError):
            sig_name = f"signal {sig_num}"
        return False, (
            f"Tkinter probe crashed with {sig_name} (exit code {result.returncode}). "
            "This is typically caused by Tcl/Tk library conflicts with other "
            "native libraries (e.g., scapy's libcrypto). "
            "Try running without conflicting libraries loaded."
        )

    # Non-zero but positive exit code means a Python exception occurred
    stderr_msg = result.stderr.strip() if result.stderr else "unknown error"
    return False, f"Tkinter initialization failed: {stderr_msg}"


def preflight_check(verbose=True):
    """
    Run all pre-flight checks for Tkinter GUI initialization.

    This should be called BEFORE any attempt to import or use tkinter.Tk().

    Args:
        verbose: If True, print error messages to stderr on failure.

    Returns:
        bool: True if it is safe to proceed with Tkinter initialization.
    """
    # Step 1: Check if tkinter module is importable
    try:
        import tkinter  # noqa: F401
    except ImportError:
        if verbose:
            print(
                "ERROR: tkinter is not installed.\n"
                "Install it with:\n"
                "  Linux: sudo apt-get install python3-tk\n"
                "  Windows: Reinstall Python with 'tcl/tk and IDLE' checked\n"
                "  macOS: brew install python-tk",
                file=sys.stderr,
            )
        return False

    # Step 2: Check display environment
    display_ok, display_reason = check_display_available()
    if not display_ok:
        if verbose:
            print(
                f"ERROR: Cannot start GUI - {display_reason}",
                file=sys.stderr,
            )
        return False

    # Step 3: Subprocess probe to catch segfaults safely
    probe_ok, probe_reason = probe_tkinter_subprocess()
    if not probe_ok:
        if verbose:
            print(
                f"ERROR: Tkinter safety probe failed - {probe_reason}",
                file=sys.stderr,
            )
        return False

    return True
