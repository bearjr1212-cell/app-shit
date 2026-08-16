#!/usr/bin/env python3
"""
POS Framework Launcher
──────────────────────
Sets up PYTHONPATH and launches the framework.
Run from the kiro/ directory:
    python3 run.py recon -i Wi-Fi
    python3 run.py terminal -i Wi-Fi
    python3 run.py attack -i Wi-Fi
    python3 run.py analyze
"""

import sys
import os

# Add the parent directory to path so posframework is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from posframework.__main__ import main

if __name__ == "__main__":
    main()
