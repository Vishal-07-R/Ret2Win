"""
tests/test_cli.py - Tests for command line interface behavior and flags.
"""

import unittest
import subprocess
import sys


class TestCLI(unittest.TestCase):
    def test_cli_version_flag(self):
        res = subprocess.run(
            [sys.executable, "-m", "ret2win", "--version"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("1.3.4", res.stdout)

    def test_cli_help_flag(self):
        res = subprocess.run(
            [sys.executable, "-m", "ret2win", "--help"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Ret2Win CTF payload generator & TUI", res.stdout)
        self.assertIn("--diagnostics", res.stdout)
        self.assertIn("--binary", res.stdout)
        self.assertIn("--win-addr", res.stdout)
        self.assertIn("--offset", res.stdout)

    def test_cli_diagnostics_flag(self):
        res = subprocess.run(
            [sys.executable, "-m", "ret2win", "--diagnostics"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Ret2Win System & Platform Diagnostics", res.stdout)
        self.assertIn("Native Build Toolchain Audit", res.stdout)
        self.assertIn("Python Dependencies Audit", res.stdout)

    def test_cli_missing_required_args(self):
        res = subprocess.run(
            [sys.executable, "-m", "ret2win", "--binary", "dummy.bin"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Both --binary and --win-addr are required", res.stderr)

    def test_root_shim_execution(self):
        res = subprocess.run(
            [sys.executable, "ret2win.py", "--version"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("1.3.4", res.stdout)


if __name__ == "__main__":
    unittest.main()
