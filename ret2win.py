#!/usr/bin/env python3
"""
ret2win.py - Developer and backwards-compatibility entrypoint.
Allows running `./ret2win.py` directly from the repository checkout.
"""
import os
import sys

# Ensure local repository directory is prioritized when running from source
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from ret2win.cli import (
    main,
    find_offset,
    build_payload,
    validate_offset,
    check_binary_executable,
    __version__,
)

if __name__ == "__main__":
    main()
