"""
tests/test_packaging.py - Tests for package layout, exports, and entrypoints.
"""

import unittest
import importlib


class TestPackaging(unittest.TestCase):
    def test_version_defined(self):
        import ret2win
        self.assertTrue(hasattr(ret2win, "__version__"))
        self.assertIsInstance(ret2win.__version__, str)
        self.assertRegex(ret2win.__version__, r"^\d+\.\d+\.\d+$")

    def test_entrypoint_callable(self):
        from ret2win.cli import main
        self.assertTrue(callable(main))

    def test_public_api_exports(self):
        import ret2win
        expected_exports = [
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
        for name in expected_exports:
            self.assertTrue(hasattr(ret2win, name), f"Missing exported API: {name}")

    def test_submodules_namespaced(self):
        for submod in ["ret2win.core", "ret2win.tui", "ret2win.cli", "ret2win.diagnostics"]:
            mod = importlib.import_module(submod)
            self.assertIsNotNone(mod)

    def test_backwards_compat_shims(self):
        import core
        import tui
        import ret2win as root_r2w

        self.assertTrue(hasattr(core, "analyze_binary"))
        self.assertTrue(hasattr(tui, "launch_tui"))
        self.assertTrue(hasattr(root_r2w, "main"))


if __name__ == "__main__":
    unittest.main()
