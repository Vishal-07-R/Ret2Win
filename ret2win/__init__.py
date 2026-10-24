"""
Ret2Win - Automated CTF Return-to-Win Exploitation Toolkit & Interactive TUI
"""

__version__ = "1.3.4"

from ret2win.cli import main
from ret2win.core import (
    analyze_binary,
    find_offset,
    build_payload,
    validate_offset,
    parse_address,
    format_payload_breakdown,
    format_colorized_hexdump,
    generate_solve_script,
    check_binary_executable,
)

__all__ = [
    "__version__",
    "main",
    "analyze_binary",
    "find_offset",
    "build_payload",
    "validate_offset",
    "parse_address",
    "format_payload_breakdown",
    "format_colorized_hexdump",
    "generate_solve_script",
    "check_binary_executable",
]
