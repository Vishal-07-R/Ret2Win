#!/usr/bin/env python3
"""
core.py - Compatibility shim for local imports.
Directs imports to ret2win.core.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from ret2win.core import *
from ret2win.core import (
    analyze_binary,
    check_binary_executable,
    find_offset,
    parse_address,
    build_payload,
    format_payload_breakdown,
    format_colorized_hexdump,
    generate_solve_script,
    get_elf_functions,
    validate_offset,
    clean_core_dumps,
)
