"""
POSFramework CLI Terminal UI Launcher
--------------------------------------
Simple entry point to launch the curses-based terminal UI application.

Usage:
  python -m posframework.gui_main
  python posframework/gui_main.py
"""

from posframework.gui import main


if __name__ == "__main__":
    main()
