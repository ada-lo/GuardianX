#!/usr/bin/env python
"""
GuardianX Entry Point
Thin wrapper that imports and runs the engine.

Usage:
    python run.py                  Start GuardianX with dashboard
    python run.py --no-dashboard   Start without dashboard
    python run.py --help           Show help
"""

import sys
import os

# Ensure the project root is on the Python path so that
# `import guardianx` works regardless of the working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardianx.engine import main

if __name__ == '__main__':
    main()
