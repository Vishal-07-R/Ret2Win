"""
ret2win/diagnostics.py - Platform-aware environment and dependency diagnostics.

Inspects system architecture, Python version, build toolchain (CMake, Clang, Make),
dependency status (pwntools, unicorn, psutil, rich), PATH visibility, and Linux
core dump configurations. Provides platform-specific remediation commands,
especially for Termux on Android.
"""

import os
import sys
import shutil
import platform
import subprocess
from typing import Dict, Any, List, Optional, Tuple


def is_termux() -> bool:
    """Detect whether running inside Android Termux environment."""
    if os.environ.get("TERMUX_VERSION"):
        return True
    if os.path.isdir("/data/data/com.termux"):
        return True
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    return False


def get_platform_info() -> Dict[str, Any]:
    """Gather operating system and platform architecture details."""
    system = platform.system()
    machine = platform.machine()
    python_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    termux_env = is_termux()

    distro_name = system
    if termux_env:
        distro_name = "Termux (Android)"
    elif os.path.isfile("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        distro_name = line.strip().split("=", 1)[1].strip('"\'')
                        break
        except Exception:
            pass

    return {
        "system": system,
        "machine": machine,
        "python_version": python_ver,
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "python_executable": sys.executable,
        "is_termux": termux_env,
        "distro_name": distro_name,
    }


def check_tool(name: str) -> Tuple[bool, Optional[str]]:
    """Check if an executable tool is present in PATH."""
    path = shutil.which(name)
    if path:
        return True, path
    return False, None


def check_build_toolchain() -> Dict[str, Dict[str, Any]]:
    """Verify presence of C/C++ compilation tools needed for native wheel builds."""
    tools = ["cmake", "clang", "gcc", "make", "pkg-config"]
    results = {}
    for t in tools:
        found, path = check_tool(t)
        results[t] = {"installed": found, "path": path}
    return results


def check_python_packages() -> Dict[str, Dict[str, Any]]:
    """Audit installed Python dependencies and version constraints."""
    package_module_map = {
        "pwntools": "pwn",
        "rich": "rich",
        "unicorn": "unicorn",
        "psutil": "psutil",
        "capstone": "capstone",
        "ropgadget": "ropgadget",
    }
    results = {}

    for pkg_name, mod_name in package_module_map.items():
        try:
            mod = __import__(mod_name)
            ver = getattr(mod, "__version__", None)
            if not ver:
                # Try pwnlib or importlib.metadata
                try:
                    import importlib.metadata
                    ver = importlib.metadata.version(pkg_name)
                except Exception:
                    ver = "installed"
            results[pkg_name] = {"installed": True, "version": ver, "error": None}
        except Exception as e:
            results[pkg_name] = {"installed": False, "version": None, "error": str(e)}

    return results


def check_path_visibility() -> Dict[str, Any]:
    """Check whether ~/.local/bin or $PREFIX/bin is properly configured in $PATH."""
    termux_env = is_termux()
    env_path = os.environ.get("PATH", "").split(os.path.pathsep)

    expected_dir = os.path.expanduser("~/.local/bin")
    if termux_env and "PREFIX" in os.environ:
        termux_bin = os.path.join(os.environ["PREFIX"], "bin")
        expected_dir = termux_bin

    is_visible = any(os.path.abspath(p) == os.path.abspath(expected_dir) for p in env_path if p)
    ret2win_bin = shutil.which("ret2win")

    return {
        "expected_bin_dir": expected_dir,
        "in_path": is_visible,
        "ret2win_in_path": ret2win_bin is not None,
        "ret2win_bin_path": ret2win_bin,
    }


def check_coredump_readiness() -> Dict[str, Any]:
    """Check Linux kernel core dump configuration for automated offset detection."""
    results = {"suid_dumpable": None, "core_pattern": None, "ulimit_c": "unknown"}

    if platform.system() != "Linux":
        return results

    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        if soft == resource.RLIM_INFINITY:
            results["ulimit_c"] = "unlimited"
        else:
            results["ulimit_c"] = str(soft)
    except Exception:
        pass

    if os.path.isfile("/proc/sys/fs/suid_dumpable"):
        try:
            with open("/proc/sys/fs/suid_dumpable", "r") as f:
                results["suid_dumpable"] = f.read().strip()
        except Exception:
            pass

    if os.path.isfile("/proc/sys/kernel/core_pattern"):
        try:
            with open("/proc/sys/kernel/core_pattern", "r") as f:
                results["core_pattern"] = f.read().strip()
        except Exception:
            pass

    return results


def diagnose_import_error(error: Exception) -> str:
    """
    Produce a detailed, platform-specific diagnostic message when pwntools
    or other core packages fail to import at startup.
    """
    termux_env = is_termux()
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    err_str = str(error)

    lines = [
        "",
        "=======================================================================",
        "  [!] Ret2Win Startup Diagnostic: Core Dependency Import Failure",
        "=======================================================================",
        f"  Error details: {type(error).__name__}: {error}",
        f"  Python version: {py_ver} ({sys.executable})",
        f"  Environment:    {'Termux (Android)' if termux_env else platform.system()}",
        "",
    ]

    if termux_env:
        lines.extend([
            "  ROOT CAUSE ANALYSIS (Termux on Android):",
            "  ---------------------------------------------------------------------",
            "  Ret2Win relies on pwntools for binary analysis, which requires native",
            "  C extensions (Unicorn Engine and psutil). On Android/Termux:",
            "    1. PyPI has no precompiled wheels for Android or Python 3.14.",
            "    2. Unicorn Engine must compile from source and requires CMake.",
            "    3. Upstream psutil fails with 'platform android is not supported';",
            "       Termux provides its own patched 'python-psutil' package instead.",
            "",
            "  RECOMMENDED FIX FOR TERMUX:",
            "  Run the following commands in your Termux terminal:",
            "",
            "    pkg update",
            "    pkg install -y clang cmake make pkg-config libffi openssl binutils python-psutil python-cryptography",
            "    pip install ret2win",
            "",
            "  Note: Ensure CMake and clang are installed BEFORE running pip install.",
        ])
    else:
        cmake_ok, _ = check_tool("cmake")
        lines.extend([
            "  ROOT CAUSE ANALYSIS:",
            "  ---------------------------------------------------------------------",
            "  pwntools requires underlying native libraries. If installation failed:",
        ])
        if not cmake_ok:
            lines.append("    • CMake is missing: Unicorn compilation requires cmake on platforms")
            lines.append("      without prebuilt wheels (e.g. Python 3.14, Alpine musl, Apple Silicon).")
        lines.extend([
            "",
            "  RECOMMENDED FIX:",
            "  • Ubuntu / Debian / Kali:",
            "      sudo apt update && sudo apt install -y build-essential cmake libffi-dev libssl-dev python3-dev",
            "      pip install ret2win",
            "  • Arch Linux / CachyOS:",
            "      sudo pacman -S --needed base-devel cmake python-pwntools",
            "  • macOS (Homebrew):",
            "      brew install cmake",
            "      pip install ret2win",
        ])

    lines.append("=======================================================================\n")
    return "\n".join(lines)


def run_diagnostics(console=None) -> int:
    """
    Execute full platform and dependency diagnostics and output results.
    Returns 0 if all essentials pass, or 1 if blocking issues exist.
    """
    plat = get_platform_info()
    tools = check_build_toolchain()
    pkgs = check_python_packages()
    path_info = check_path_visibility()
    cores = check_coredump_readiness()

    # ANSI formatting helpers
    use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    GREEN = "\033[1;32m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    RED = "\033[1;31m" if use_color else ""
    CYAN = "\033[1;36m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    print(f"\n{BOLD}{CYAN}Ret2Win System & Platform Diagnostics:{RESET}")
    print(f"  • Operating System:     {plat['distro_name']} ({plat['system']} {plat['machine']})")
    print(f"  • Python Runtime:       {plat['python_version']} ({plat['python_executable']})")
    print(f"  • Platform Type:        {'Termux on Android' if plat['is_termux'] else 'Standard Desktop/Server'}")

    # Build tools
    print(f"\n{BOLD}{CYAN}Native Build Toolchain Audit:{RESET}")
    cmake_info = tools["cmake"]
    if cmake_info["installed"]:
        print(f"  {GREEN}[✔] cmake:{RESET}       {cmake_info['path']}")
    else:
        print(f"  {RED}[✖] cmake:{RESET}       MISSING (Required to compile Unicorn from source on Python 3.14 / Android)")

    for t in ["clang", "gcc", "make", "pkg-config"]:
        info = tools[t]
        if info["installed"]:
            print(f"  {GREEN}[✔] {t}:{RESET}" + " " * (10 - len(t)) + f"{info['path']}")
        else:
            print(f"  {YELLOW}[⚠] {t}:{RESET}" + " " * (10 - len(t)) + "Not installed")

    # Python Dependencies
    print(f"\n{BOLD}{CYAN}Python Dependencies Audit:{RESET}")
    has_blocking = False
    for pkg in ["rich", "pwntools", "unicorn", "psutil", "capstone", "ropgadget"]:
        info = pkgs[pkg]
        if info["installed"]:
            print(f"  {GREEN}[✔] {pkg}:{RESET}" + " " * (12 - len(pkg)) + f"v{info['version']}")
        else:
            if pkg in ("pwntools", "rich"):
                has_blocking = True
                print(f"  {RED}[✖] {pkg}:{RESET}" + " " * (12 - len(pkg)) + f"NOT INSTALLED ({info['error']})")
            else:
                print(f"  {YELLOW}[⚠] {pkg}:{RESET}" + " " * (12 - len(pkg)) + f"Not installed directly ({info['error']})")

    # Path check
    print(f"\n{BOLD}{CYAN}PATH & Command Visibility Audit:{RESET}")
    if path_info["ret2win_in_path"]:
        print(f"  {GREEN}[✔] ret2win binary:{RESET} {path_info['ret2win_bin_path']}")
    else:
        print(f"  {RED}[✖] ret2win binary:{RESET} Not found in PATH!")
        print(f"       Expected location: {path_info['expected_bin_dir']}")
        if not path_info["in_path"]:
            print(f"       {YELLOW}Tip:{RESET} Add this to your shell profile (~/.bashrc or ~/.zshrc):")
            print(f"       export PATH=\"{path_info['expected_bin_dir']}:$PATH\"")

    # Core dump check
    if plat["system"] == "Linux":
        print(f"\n{BOLD}{CYAN}Linux Core Dump Readiness:{RESET}")
        print(f"  • Core limit (ulimit -c): {cores['ulimit_c']}")
        if cores["suid_dumpable"] is not None:
            print(f"  • fs.suid_dumpable:      {cores['suid_dumpable']}")
        if cores["core_pattern"]:
            print(f"  • kernel.core_pattern:   {cores['core_pattern']}")

    # Termux specific guidance
    if plat["is_termux"]:
        print(f"\n{BOLD}{YELLOW}Termux Environment Notice:{RESET}")
        print("  On Termux, binary packages with C/Rust extensions (unicorn, psutil, cryptography)")
        print("  cannot use standard manylinux wheels. Ensure you install native Termux packages:")
        print(f"  {CYAN}pkg update && pkg install -y clang cmake make pkg-config libffi openssl binutils python-psutil python-cryptography{RESET}")

    print()
    return 1 if has_blocking else 0


if __name__ == "__main__":
    sys.exit(run_diagnostics())
