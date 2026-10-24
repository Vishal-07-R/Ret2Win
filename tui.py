#!/usr/bin/env python3
"""
tui.py - Compatibility shim for local imports.
Directs imports to ret2win.tui.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from ret2win.tui import *
from ret2win.tui import (
    launch_tui,
    create_header_renderable,
    RichRet2WinTUI,
)
