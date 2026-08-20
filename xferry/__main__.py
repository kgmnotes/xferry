#!/usr/bin/env python3
"""
Allows running the package as: python -m xferry
"""

import sys

from xferry.management.cli import main

if __name__ == "__main__":
    sys.exit(main())
