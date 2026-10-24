"""
tests/test_diagnostics.py - Tests for platform detection and diagnostics reporting.
"""

import unittest
from ret2win.diagnostics import (
    get_platform_info,
    is_termux,
    check_tool,
    check_build_toolchain,
    check_python_packages,
    check_path_visibility,
    diagnose_import_error,
)


class TestDiagnostics(unittest.TestCase):
    def test_get_platform_info_keys(self):
        info = get_platform_info()
        self.assertIn("system", info)
        self.assertIn("machine", info)
        self.assertIn("python_version", info)
        self.assertIn("is_termux", info)
        self.assertIn("distro_name", info)

    def test_check_tool_exists(self):
        exists, path = check_tool("python3")
        self.assertTrue(exists)
        self.assertIsNotNone(path)

    def test_check_tool_missing(self):
        exists, path = check_tool("nonexistent_tool_xyz_987654")
        self.assertFalse(exists)
        self.assertIsNone(path)

    def test_build_toolchain_keys(self):
        chain = check_build_toolchain()
        for tool in ["cmake", "clang", "gcc", "make", "pkg-config"]:
            self.assertIn(tool, chain)
            self.assertIn("installed", chain[tool])

    def test_python_packages_audit(self):
        pkgs = check_python_packages()
        for pkg in ["rich", "pwntools", "unicorn", "psutil"]:
            self.assertIn(pkg, pkgs)
            self.assertIn("installed", pkgs[pkg])

    def test_path_visibility(self):
        info = check_path_visibility()
        self.assertIn("expected_bin_dir", info)
        self.assertIn("in_path", info)
        self.assertIn("ret2win_in_path", info)

    def test_diagnose_import_error_message(self):
        dummy_err = ImportError("No module named 'pwn'")
        diag_msg = diagnose_import_error(dummy_err)
        self.assertIn("Ret2Win Startup Diagnostic", diag_msg)
        self.assertIn("ROOT CAUSE ANALYSIS", diag_msg)
        self.assertIn("RECOMMENDED FIX", diag_msg)


if __name__ == "__main__":
    unittest.main()
