#!/usr/bin/env python3
"""
Executable launcher for the Linux Security Hardening Toolkit.
Author: Kartik Soni
"""

import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.main import main

if __name__ == "__main__":
    sys.exit(main())
