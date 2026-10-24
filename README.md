<p align="center">
  <pre align="center">
<font color="#00ffff"><b> ██████╗ ███████╗████████╗██████╗ ██╗    ██╗██╗███╗   ██╗</b></font>
<font color="#00d7ff"><b> ██╔══██╗██╔════╝╚══██╔══╝╚════██╗██║    ██║██║████╗  ██║</b></font>
<font color="#00afff"><b> ██████╔╝█████╗     ██║    █████╔╝██║ █╗ ██║██║██╔██╗ ██║</b></font>
<font color="#0087ff"><b> ██╔══██╗██╔══╝     ██║   ██╔═══╝ ██║███╗██║██║██║╚██╗██║</b></font>
<font color="#005fff"><b> ██║  ██║███████╗   ██║   ███████╗╚███╔███╔╝██║██║ ╚████║</b></font>
<font color="#5f00ff"><b> ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝</b></font>
  </pre>
</p>

<h3 align="center"><b>Automated CTF Return-to-Win Exploitation Toolkit & Interactive TUI</b></h3>

<p align="center">
  <i>Supercharge your binary exploitation workflow. Zero-guesswork crash analysis, checksec auditing, stack alignment hunting, colorized payload breakdowns, and instant remote flag captures.</i>
</p>

<p align="center">
  <a href="https://pypi.org/project/ret2win/"><img src="https://img.shields.io/pypi/v/ret2win.svg?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI Version" /></a>
  <a href="https://github.com/Vishal-07-R/Ret2Win/releases"><img src="https://img.shields.io/badge/version-1.3.4-blue.svg?style=for-the-badge&logo=git&logoColor=white" alt="Version 1.3.4" /></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8%2B-blueviolet.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+" /></a>
  <a href="https://github.com/Gallopsled/pwntools"><img src="https://img.shields.io/badge/Powered%20By-Pwntools%20%26%20Rich-ff69b4.svg?style=for-the-badge" alt="Pwntools & Rich" /></a>
  <a href="https://github.com/Vishal-07-R/Ret2Win/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License MIT" /></a>
  <a href="https://archlinux.org"><img src="https://img.shields.io/badge/Tested%20On-CachyOS%20%7C%20Arch%20%7C%20Kali%20%7C%20Ubuntu-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Linux Tested" /></a>
</p>

---

## ⚡ Overview

**Ret2Win** is a modern binary exploitation toolkit engineered specifically for CTF players, security researchers, and exploit developers. 

In traditional CTF competitions, solving a classic `ret2win` challenge typically involves repeated manual steps:
1. Running `checksec` on the binary.
2. Disassembling symbols with `objdump`, `readelf`, or Ghidra to spot target functions.
3. Launching GDB, generating cyclic patterns, crashing the binary, copying addresses, and running `cyclic -l`.
4. Calculating stack padding, hunting lone `ret` gadgets for 16-byte stack alignment (`movaps` crash prevention), and drafting an exploit script.

**Ret2Win completely automates this lifecycle.** It analyzes the ELF binary, detects checksec mitigations, locates win functions, fuzzes the exact offset using native core dumps (with automatic GDB fallback), crafts the payload, guarantees 16-byte stack alignment, and either drops you into an interactive shell or generates a standalone, clean `solve.py` script—**in under 3 seconds**.

Available both as a **rich, split-scrolling Cyberpunk Terminal User Interface (TUI)** and as a **fully scriptable CLI tool**.

---

## 🖥️ Interactive Terminal UI

Launch the interface with a single command:
```bash
ret2win
```

```text
            ██████╗ ███████╗████████╗██████╗ ██╗    ██╗██╗███╗   ██╗            
            ██╔══██╗██╔════╝╚══██╔══╝╚════██╗██║    ██║██║████╗  ██║            
            ██████╔╝█████╗     ██║    █████╔╝██║ █╗ ██║██║██╔██╗ ██║            
            ██╔══██╗██╔══╝     ██║   ██╔═══╝ ██║███╗██║██║██║╚██╗██║            
            ██║  ██║███████╗   ██║   ███████╗╚███╔███╔╝██║██║ ╚████║            
            ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝            
                                                                                
  ─── Automated CTF Return-to-Win Exploitation Toolkit  •  made by -Casper ───  

╭── [ TARGET BINARY & MITIGATIONS ] ──────────╮╭── [ EXPLOIT CONFIGURATION ] ───────────────╮
│  Binary:        ./vuln                      ││  Win Target:   0x401196 (win)              │
│  Architecture:  amd64 (64-bit, little)      ││  Offset:       88 bytes ✓ Validated        │
│  Checksec:      Partial RELRO │ No Canary   ││  Stack Align:  Enabled (lone ret 0x40101a) │
│  Mitigations:   NX Enabled    │ No PIE      ││  Delivery:     stdin (Standard Input)      │
│  Win Candidate: win (0x401196)              ││  Destination:  Local Process (vuln)        │
│  Ret Gadget:    0x40101a (x86_64 16B align) ││  Payload Size: 104 bytes (payload.bin)     │
╰─────────────────────────────────────────────╯╰────────────────────────────────────────────╯
 Status: Offset verified (88 bytes). Exploit payload compiled and armed.

╭───────────────────────────────────────────────────────────────────────────────────────────╮
│                                [ MISSION CONTROL ACTIONS ]                                │
│   [1] Select/Scan Binary        [2] Auto-Detect Offset        [3] Validate Offset         │
│   [4] Set Win Address/Symbol    [5] Toggle 16B Alignment      [6] Toggle Delivery (stdin) │
│   [7] Set Exploit Destination   [8] Inspect Payload & Hexdump [9] ELF Symbol Browser      │
│   [f] Fire Exploit & solve.py   [h] Help & CTF Guide          [q] Quit Ret2Win            │
╰───────────────────────────────────────────────────────────────────────────────────────────╯

ret2win ➜
```

### Colorized Payload Inspection
Ret2Win visually dissects and displays the structure of the generated buffer:

```text
  00000000:  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
  ...
  00000050:  41 41 41 41 41 41 41 41  1a 10 40 00 00 00 00 00   AAAAAAAA..@.....
  00000060:  96 11 40 00 00 00 00 00                            ..@.....

  Breakdown:
  • 0x00 - 0x57 [88 bytes] : Cyclic Padding ('A' * 88)
  • 0x58 - 0x5F [ 8 bytes] : Lone `ret` Gadget (0x40101a) [16-Byte Stack Alignment]
  • 0x60 - 0x67 [ 8 bytes] : Target `win()` Address (0x401196)
```

---

## 🚀 Installation

Ret2Win can be installed via **PyPI**, the **universal installer script**, or directly from source.

### Method 1: Install from PyPI (Simplest)

Ret2Win is officially published on PyPI: **[https://pypi.org/project/ret2win/](https://pypi.org/project/ret2win/)**

Install globally via `pipx` or inside a virtual environment:

```bash
# Recommended for CLI tools on modern Linux (PEP 668)
pipx install ret2win

# Or via standard pip in your active environment
pip install ret2win
```

---

### Method 2: Universal Automated Installer (Recommended for Local Git Repo)

Clone the repository and run the installer:

```bash
git clone https://github.com/Vishal-07-R/Ret2Win.git
cd Ret2Win
./install.sh
```

#### Installer Options:
```bash
./install.sh                # User-space install (~/.local/share/ret2win and ~/.local/bin/ret2win)
./install.sh -y             # Silent, non-interactive automated install
sudo ./install.sh --system  # System-wide install for all users (/usr/local/bin/ret2win)
./install.sh --dev          # Developer symlink mode (links directly to active repo)
./install.sh --check        # Audit system dependencies and coredump configuration
./install.sh --uninstall    # Clean uninstallation of Ret2Win and launcher links
```

---

### Method 3: From Source (`git`)

#### Using `pipx` (Isolated user application):
```bash
pipx install .
```

#### Using `pip` with Virtual Environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

### Distribution Prerequisites

Ret2Win utilizes standard Linux tools for binary inspection and crash capturing. The `install.sh` script will automatically offer to install these for you:

#### Arch Linux / CachyOS / Manjaro
```bash
sudo pacman -S python python-pip gdb wl-clipboard xclip qemu-user qemu-user-binfmt
```

#### Debian / Ubuntu / Kali / Parrot OS
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv gdb wl-clipboard xclip qemu-user qemu-user-static
```

#### Fedora / RHEL
```bash
sudo dnf install python3 python3-pip python3-virtualenv gdb wl-clipboard xclip qemu-user-static
```

#### Termux (Android)
On Android/Termux, upstream `psutil` rejects Android during PyPI source builds, and `unicorn` (required by `pwntools`) compiles native C-extensions requiring `cmake` and `clang`. Install Termux's pre-compiled and native build dependencies first:
```bash
pkg update && pkg install -y clang cmake make pkg-config libffi openssl binutils python-psutil python-cryptography
pip install ret2win
```
*(Tip: Run `ret2win --diagnostics` after installation to audit your environment).*

---

## ⚡ Core Dump Optimization (Zero-Guesswork Offset Finding)

To let Ret2Win automatically calculate buffer overflow offsets using native Linux core dumps without GDB delay:

1. Enable unlimited core dumps in your shell:
   ```bash
   ulimit -c unlimited
   ```
   *(Add `ulimit -c unlimited` to your `~/.bashrc` or `~/.zshrc` so it is always active).*

2. (Optional) If running on Ubuntu/Debian with Apport or systemd-coredump:
   ```bash
   sudo sysctl -w fs.suid_dumpable=1
   ```
   *Note: Even if core dumping is restricted by your kernel, Ret2Win automatically falls back to an integrated GDB crash tracing engine seamlessly.*

---

## 📖 CLI Usage & Command Reference

Ret2Win can be driven completely headless in automation pipelines, CTF scripts, or CI/CD testing.

### Command-Line Arguments

| Argument | Type | Default | Description |
|:---|:---:|:---:|:---|
| `--binary` | `PATH` | *None* | Path to target ELF binary executable |
| `--win-addr` | `HEX/SYM` | *None* | Target win function address (e.g. `0x401196`) or symbol name (`win`) |
| `--offset` | `INT` | *Auto* | Manually specify buffer overflow offset (skips auto-detection) |
| `--max-len` | `INT` | `2048` | Maximum De Bruijn pattern length for crash auto-detection |
| `--align` | `FLAG` | `False` | Add 16-byte stack alignment padding (lone `ret`) before jumping to win |
| `--ret-gadget` | `HEX/SYM` | *Auto* | Address or symbol of a lone `ret` instruction |
| `--input-mode` | `stdin\|argv`| `stdin` | How input is delivered to vulnerable program buffer |
| `--output` | `PATH` | `payload.bin` | File path to write raw binary payload bytes |
| `--run` | `FLAG` | `False` | Spawn target binary locally, transmit payload, and open interactive shell |
| `--remote` | `HOST PORT`| *None* | Connect to remote network socket, transmit payload, and open interactive shell |
| `--script` | `PATH` | *None* | Generate a standalone, documented `solve.py` script and exit |
| `--validate-offset` | `FLAG` | `False` | Validate computed offset with a controlled marker crash |
| `--diagnostics`, `--check` | `FLAG` | `False` | Audit environment, compilers, Termux status, and dependencies |
| `--tui` | `FLAG` | `False` | Launch the interactive Terminal User Interface |
| `--no-color` | `FLAG` | `False` | Strip Rich ANSI color codes and formatting |
| `--version` | `FLAG` | *None* | Display version information and exit |

---

## 🎯 Practical CTF Cookbooks

### 1. Zero-Config Local Exploit & Shell
Automatically find the offset, target the `win` function, and drop into an interactive shell:
```bash
ret2win --binary ./vuln --win-addr win --run
```

### 2. 64-bit Stack Alignment (`movaps` crash prevention)
When targeting 64-bit binaries on modern Linux distributions (Ubuntu 18.04+, Debian, Arch) where libc functions crash at `movaps`:
```bash
ret2win --binary ./vuln --win-addr win --align --run
```

### 3. Generate a Standalone `solve.py` for CTF Submission
Generate a modular, production-ready exploit script configured for the competition's remote server:
```bash
ret2win --binary ./chall --win-addr 0x401176 --align --remote 10.10.10.42 1337 --script solve.py
```

### 4. Argv-Based Vulnerability
When the target program reads input from command line arguments (`argv[1]`):
```bash
ret2win --binary ./cli_vuln --win-addr win --input-mode argv --run
```

### 5. Validate Offset Before Exploitation
Test and confirm the offset via canary crash marker verification before executing:
```bash
ret2win --binary ./vuln --win-addr win --validate-offset --run
```

---

## 💡 Troubleshooting & CTF Deep-Dive

<details>
<summary><b>1. Why does my payload crash inside <code>system()</code> or <code>puts()</code>? (Stack Alignment)</b></summary>

### The 16-Byte Stack Alignment Rule (x86_64)
The AMD64 System V ABI mandates that before a `call` instruction is executed, the stack pointer (`rsp`) must be **16-byte aligned** (`rsp % 16 == 0`). When a function is called, the CPU pushes the 8-byte return address onto the stack, leaving `rsp` aligned to `8 (mod 16)`.

Modern glibc implementations make extensive use of SSE instructions (such as `movaps` or `movdqa`), which require memory operands to be strictly 16-byte aligned. If the stack is misaligned when entering `system()`, `do_system()`, or `puts()`, the program triggers a `SIGSEGV` at the `movaps` instruction.

**The Fix:**
Ret2Win's `--align` switch automatically prepends a lone `ret` gadget address to the payload before `win()`. Executing `ret` pops 8 bytes off the stack, re-aligning `rsp` to 16 bytes and allowing SSE instructions to execute without crashing.
</details>

<details>
<summary><b>2. Why does <code>argv</code> mode reject my payload? (NUL Byte Termination)</b></summary>

### The C String Terminator Limitation
Under Linux and POSIX systems, `argv[]` strings passed via `execve()` are null-terminated C strings. If an address contains a null byte (`0x00`) anywhere prior to its final byte (which is standard for 64-bit addresses like `0x0000000000401196`), the kernel truncates the argument at the first `0x00`.

**The Solution:**
If the binary supports reading from standard input, switch to `--input-mode stdin`. If `argv` is mandatory, choose an address or gadget free of embedded null bytes.
</details>

<details>
<summary><b>3. How does Ret2Win handle Position Independent Executables (PIE)?</b></summary>

### PIE / ASLR Handling
When a binary is compiled with PIE enabled, code addresses are randomized on each execution. Static addresses shown in `objdump` or `readelf` are relative offsets (e.g. `0x1196`), not runtime addresses.

**The Solution:**
When Ret2Win detects PIE, it warns the user. In the interactive TUI, you can supply either the runtime base address or compute `base + offset` after leaking a pointer.
</details>

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to check the [Issues page](https://github.com/Vishal-07-R/Ret2Win/issues).

1. Fork the Project (`https://github.com/Vishal-07-R/Ret2Win/fork`)
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for more information.

---

## 👤 Author

**Casper (Vishal-07-R)**
- GitHub: [@Vishal-07-R](https://github.com/Vishal-07-R)
- Focus: CTF Competitions, Binary Exploitation, Reverse Engineering, Cybersecurity

<p align="center">
  <b>Happy Hacking! May your return addresses always land true. 🚩</b>
</p>
