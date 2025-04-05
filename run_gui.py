#!/usr/bin/env python3
"""
Launcher script for the macOS Security Compliance Tool GUI
"""

import os
import sys
from pathlib import Path

# Add the src directory to the Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

# Import and run the GUI
from gui import main

if __name__ == "__main__":
    main() 