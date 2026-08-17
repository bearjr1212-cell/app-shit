"""
POSFramework GUI Launcher
--------------------------
Simple entry point to launch the Tkinter GUI application.

Includes pre-flight safety checks to prevent segfaults on headless
systems or when Tcl/Tk conflicts with other native libraries.

Usage:
  python -m posframework.gui_main
  python posframework/gui_main.py
"""

import sys

from posframework.tk_preflight import preflight_check
from posframework.gui import main


def launch():
    """Launch GUI with pre-flight safety checks."""
    if not preflight_check(verbose=True):
        sys.exit(1)
    main()


if __name__ == "__main__":
    launch()
