#!/usr/bin/env python3
"""
tui.py - Ret2Win Pure Rich Terminal User Interface
Modern, full-fledged CTF Ret2Win exploitation toolkit built completely with Rich.
Features truecolor 2D RGB gradient banners, interactive mission control,
checksec audits, offset auto-detection, symbol browsing, and exploit execution.
Designed for Casper (CachyOS / Arch Linux).
"""

import builtins
import os
import re
import shlex
import shutil
import signal
import sys
import subprocess
import tempfile
from typing import Optional, Dict, Any, List, Tuple

_orig_input = getattr(builtins, "_orig_input", builtins.input)

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
console = Console()
ESC = chr(27)


# ---------------------------------------------------------------------------
# Pinned-header support.
#
# The dashboard (banner + panels + menu) is kept visually fixed at the top
# of the screen via a VT100/xterm "scrolling region" (DECSTBM, `ESC[t;br`):
# everything printed while the cursor sits inside that region scrolls
# normally, but rows above the region's top margin are left untouched by
# that scrolling. This is a real terminal feature (supported by basically
# every modern emulator, including inside tmux/screen panes) rather than an
# app-managed redraw, so normal terminal scrollback/selection/copy for the
# command output still works exactly as it does today.
#
# It only makes sense -- and is only safe -- on a genuine interactive
# terminal that will actually interpret the escape sequences instead of
# echoing them as literal text (see clear_screen()'s note below on why
# isatty() alone isn't a reliable enough signal).
# ---------------------------------------------------------------------------

def _is_real_tty() -> bool:
    """True only when stdout is a real terminal capable of honoring cursor
    and scroll-region escapes, so the pinned-header feature degrades to the
    old plain-scrolling behavior anywhere that would otherwise show garbage
    (piped output, captured transcripts, dumb/unknown TERM values, etc.)."""
    if not sys.stdout.isatty():
        return False
    if console.is_dumb_terminal:
        return False
    term = os.environ.get("TERM", "")
    if not term or term == "dumb":
        return False
    return True


def _term_size() -> Tuple[int, int]:
    size = shutil.get_terminal_size(fallback=(80, 24))
    return size.columns, size.lines


def _term_rows() -> int:
    return _term_size()[1]


def _raw(seq: str) -> None:
    """Write a raw ANSI escape sequence straight to the terminal, bypassing
    Rich and any stream hooks (like pwntools term wrapper)."""
    try:
        sys.stdout.flush()
    except Exception:
        pass
    try:
        os.write(sys.stdout.fileno(), seq.encode("utf-8"))
    except (OSError, AttributeError):
        target = getattr(sys, "__stdout__", sys.stdout)
        target.write(seq)
        target.flush()


def _set_scroll_region(top: int, bottom: int, target_row: Optional[int] = None) -> None:
    _raw(f"{ESC}[{top};{bottom}r")
    # DECSTBM automatically resets the cursor to row 1, col 1.
    # Always reposition the cursor inside the scrolling region so subsequent
    # writes never overwrite the fixed header.
    row = target_row if target_row is not None else top
    row = max(top, min(bottom, row))
    _goto(row, 1)


def _reset_scroll_region() -> None:
    """Restores the full-screen scroll region. Always call this before the
    process exits, or the user's terminal is left with a stuck scroll
    region after Ret2Win closes."""
    _raw(f"{ESC}[r")


def _goto(row: int, col: int = 1) -> None:
    _raw(f"{ESC}[{row};{col}H")


def _clear_all() -> None:
    _raw(f"{ESC}[2J{ESC}[1;1H")


def ask(prompt_markup: str, default: str = "") -> str:
    """Read user input with genuine GNU readline, properly escaping ANSI codes
    with \001 and \002 so readline accurately tracks cursor position and
    never erases or misplaces the prompt on submit."""
    if default:
        formatted = f"{prompt_markup} [dim]({default})[/dim]: "
    else:
        formatted = f"{prompt_markup}: " if not any(prompt_markup.endswith(x) for x in (": ", "➜", "➜ ")) else f"{prompt_markup} "
    with console.capture() as cap:
        console.print(formatted, end="")
    raw_prompt = cap.get()
    rl_prompt = re.sub(r'(\x1b\[[0-9;?]*[a-zA-Z])', lambda m: f"\x01{m.group(1)}\x02", raw_prompt)

    # Ensure streams and builtins.input are restored from pwntools' hijacking
    if hasattr(sys, "__stdin__") and sys.__stdin__ is not None:
        sys.stdin = sys.__stdin__
    if hasattr(sys, "__stdout__") and sys.__stdout__ is not None:
        sys.stdout = sys.__stdout__
    if hasattr(sys, "__stderr__") and sys.__stderr__ is not None:
        sys.stderr = sys.__stderr__
    real_input = getattr(builtins, "_orig_input", _orig_input)
    builtins.input = real_input

    try:
        val = real_input(rl_prompt).strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        raise


def confirm(prompt_markup: str, default: bool = True) -> bool:
    """Prompt for a yes/no confirmation with GNU readline."""
    hint = "Y/n" if default else "y/N"
    with console.capture() as cap:
        console.print(f"{prompt_markup} [dim]({hint})[/dim]: ", end="")
    raw_prompt = cap.get()
    rl_prompt = re.sub(r'(\x1b\[[0-9;?]*[a-zA-Z])', lambda m: f"\x01{m.group(1)}\x02", raw_prompt)

    # Ensure streams and builtins.input are restored from pwntools' hijacking
    if hasattr(sys, "__stdin__") and sys.__stdin__ is not None:
        sys.stdin = sys.__stdin__
    if hasattr(sys, "__stdout__") and sys.__stdout__ is not None:
        sys.stdout = sys.__stdout__
    if hasattr(sys, "__stderr__") and sys.__stderr__ is not None:
        sys.stderr = sys.__stderr__
    real_input = getattr(builtins, "_orig_input", _orig_input)
    builtins.input = real_input

    try:
        resp = real_input(rl_prompt).strip().lower()
        if not resp:
            return default
        return resp in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        raise

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

        # Pinned-header state (see module-level comment above _is_real_tty).
        self.pinned_header: bool = False
        self.header_height: int = 0
        self.body_top: int = 1
        self._pin_rows: int = 0
        self._pin_cols: int = 0
        self._resize_pending: bool = False

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

    def _render_dashboard_lines(self, width: int, rows: int) -> List[str]:
        """Renders the complete rich UI dashboard (banner, panels, menu) to a
        list of formatted ANSI lines, ensuring a rock-solid, fixed height."""
        dash_console = Console(width=min(width, _MAX_SANE_WIDTH))
        with dash_console.capture() as cap:
            # 1. Gradient Title Banner or Compact Header based on terminal height
            if rows >= 34:
                banner_text, sub_text = create_gradient_banner()
                dash_console.print(Align.center(banner_text))
                dash_console.print(Align.center(sub_text))
                dash_console.print()
            else:
                compact_banner = Text.assemble(
                    (" [RET2WIN] ", "bold black on bright_cyan"),
                    ("  Automated CTF Return-to-Win Exploitation Toolkit  •  made by -Casper", "bold cyan")
                )
                dash_console.print(Align.center(compact_banner))

            # 2. Left Panel: Target Binary & Mitigations (fixed 6 data rows)
            t_left = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            t_left.add_column("Field", style="bold cyan", width=16, no_wrap=True)
            t_left.add_column("Value", no_wrap=True)

            if not self.binary_info:
                bin_display = self.binary_path if self.binary_path else "[dim]No binary selected[/dim]"
                t_left.add_row("Binary:", bin_display)
                t_left.add_row("Architecture:", "[dim]Unknown[/dim]")
                t_left.add_row("Checksec:", "[dim]Run 'Select/Scan Binary' to inspect[/dim]")
                t_left.add_row("Mitigations:", "[dim]None inspected[/dim]")
                t_left.add_row("Win Candidates:", "[dim]None[/dim]")
                t_left.add_row("Ret Gadget:", "[dim]None[/dim]")
            else:
                info = self.binary_info
                bin_name = os.path.basename(info["path"])
                bin_dir = os.path.dirname(info["path"]) or "."
                short_dir = bin_dir if len(bin_dir) <= 20 else "..." + bin_dir[-17:]
                t_left.add_row("Binary:", f"[bold white]{bin_name}[/bold white] [dim]({short_dir})[/dim]")
                t_left.add_row("Architecture:", f"[bold bright_cyan]{info['arch']}[/bold bright_cyan] [dim]({info['bits']}-bit, {info['endian']})[/dim]")

                relro_tag = f"[cyan]{info['relro']}[/cyan]"
                canary_tag = "[bold red]Canary Present[/bold red]" if info["canary"] else "[bold green]No Canary[/bold green]"
                nx_tag = "[bold yellow]NX Enabled[/bold yellow]" if info["nx"] else "[bold green]NX Disabled[/bold green]"
                pie_tag = "[bold yellow]PIE Enabled[/bold yellow]" if info["pie"] else "[bold green]No PIE[/bold green]"
                t_left.add_row("Checksec:", f"{relro_tag} │ {canary_tag}")
                t_left.add_row("Mitigations:", f"{nx_tag} │ {pie_tag}")

                candidates = info.get("candidates", [])
                if candidates:
                    cand_str = f"[bold green]{candidates[0]['name']}[/bold green] ([dim]{candidates[0]['addr']}[/dim])"
                    if len(candidates) > 1:
                        cand_str += f" [dim]+{len(candidates)-1} more[/dim]"
                    t_left.add_row("Win Candidates:", cand_str)
                else:
                    t_left.add_row("Win Candidates:", "[dim]None detected (check Symbol Browser)[/dim]")

                ret_g = self.ret_gadget_str if self.ret_gadget_str else "[dim]None[/dim]"
                t_left.add_row("Ret Gadget:", f"[yellow]{ret_g}[/yellow] [dim](x86_64 16B align)[/dim]")

            p_left = Panel(t_left, title="[bold cyan][ TARGET BINARY & MITIGATIONS ][/bold cyan]", border_style="cyan")

            # 3. Right Panel: Exploit Configuration (fixed 6 data rows)
            t_right = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            t_right.add_column("Field", style="bold magenta", width=16, no_wrap=True)
            t_right.add_column("Value", no_wrap=True)

            win_parsed = self._get_parsed_win_addr()
            if win_parsed is not None:
                win_display = f"[bold green]{hex(win_parsed)}[/bold green] [dim]({self.win_addr_str})[/dim]"
            else:
                win_display = f"[bold red]{self.win_addr_str or 'Not Set'}[/bold red]"
            t_right.add_row("Win Target:", win_display)

            if self.offset is not None:
                valid_tag = " [bold green]✓ Validated[/bold green]" if self.offset_validated else " [dim](unverified)[/dim]"
                offset_display = f"[bold yellow]{self.offset} bytes[/bold yellow]{valid_tag}"
            else:
                offset_display = "[bold red]Not Found[/bold red] [dim](run Auto-Detect)[/dim]"
            t_right.add_row("Offset:", offset_display)

            if self.align:
                align_display = f"[bold green]Enabled[/bold green] [dim](lone ret {self.ret_gadget_str or 'needed'})[/dim]"
            else:
                align_display = "[dim]Disabled[/dim]"
            t_right.add_row("Stack Align:", align_display)

            input_display = "[bold cyan]stdin (Standard Input)[/bold cyan]" if self.input_mode == "stdin" else "[bold yellow]argv[1] (Command Line Arg)[/bold yellow]"
            t_right.add_row("Delivery:", input_display)

            if self.target_mode == "local":
                dest_display = f"[bold green]Local Process[/bold green] [dim]({os.path.basename(self.binary_path) if self.binary_path else 'none'})[/dim]"
            elif self.target_mode == "remote":
                dest_display = f"[bold yellow]Remote Service[/bold yellow] [dim]({self.remote_host}:{self.remote_port})[/dim]"
            else:
                dest_display = f"[bold cyan]File Only[/bold cyan] [dim]({self.output_path})[/dim]"
            t_right.add_row("Destination:", dest_display)

            if self.offset is not None and win_parsed is not None:
                bits = self.binary_info["bits"] if self.binary_info else 64
                ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None
                payload_len = self.offset + (8 if (self.align and bits == 64 and ret_g_parsed) else 0) + (8 if bits == 64 else 4)
                size_display = f"[bold white]{payload_len} bytes[/bold white] [dim]({self.output_path})[/dim]"
            else:
                size_display = "[dim]Configure offset & win to compute[/dim]"
            t_right.add_row("Payload Size:", size_display)

            p_right = Panel(t_right, title="[bold magenta][ EXPLOIT CONFIGURATION ][/bold magenta]", border_style="magenta")

            # Guaranteed side-by-side single row grid
            panel_grid = Table.grid(expand=True)
            panel_grid.add_column(ratio=1)
            panel_grid.add_column(ratio=1)
            panel_grid.add_row(p_left, p_right)
            dash_console.print(panel_grid, end="")

            # 4. Status Bar
            dash_console.print(f" Status: [{self.last_status_style}]{self.last_status_msg}[/{self.last_status_style}]")

            # 5. Interactive Action Menu (3 columns, 4 rows)
            menu_table = Table(title="[bold bright_cyan][ MISSION CONTROL ACTIONS ][/bold bright_cyan]", box=None, padding=(0, 2), expand=True, show_header=False)
            menu_table.add_column("Col1", no_wrap=True)
            menu_table.add_column("Col2", no_wrap=True)
            menu_table.add_column("Col3", no_wrap=True)

            menu_table.add_row(
                f"{kbadge('1')} Select/Scan Binary",
                f"{kbadge('2')} Auto-Detect Offset",
                f"{kbadge('3')} Validate Offset"
            )
            menu_table.add_row(
                f"{kbadge('4')} Set Win Address/Symbol",
                f"{kbadge('5')} Toggle 16B Alignment",
                f"{kbadge('6')} Toggle Delivery (stdin/argv)"
            )
            menu_table.add_row(
                f"{kbadge('7')} Set Exploit Destination",
                f"{kbadge('8')} Inspect Payload & Hexdump",
                f"{kbadge('9')} ELF Symbol Browser"
            )
            menu_table.add_row(
                f"{kbadge('f', 'bold red')} Fire Exploit & solve.py",
                f"{kbadge('h')} Help & CTF Guide",
                f"{kbadge('q', 'bold bright_black')} Quit Ret2Win"
            )

            p_menu = Panel(menu_table, border_style="bright_blue", padding=(0, 1))
            dash_console.print(p_menu, end="")

        return cap.get().splitlines()

    def _setup_pinned_header(self) -> bool:
        """(Re)establishes the pinned header: clears the screen, draws the
        dashboard at rows 1..header_height, and sets the terminal scroll region
        to confine all scrolling to the bottom area (body_top..rows)."""
        if not _is_real_tty():
            self.pinned_header = False
            return False

        cols, rows = _term_size()
        lines = self._render_dashboard_lines(cols, rows)
        h = len(lines)
        if h + 4 > rows:
            # Terminal height too small for fixed header + scroll region
            self.pinned_header = False
            _reset_scroll_region()
            return False

        self.pinned_header = True
        self.header_height = h
        self.body_top = h + 1
        self._pin_rows = rows
        self._pin_cols = cols

        _reset_scroll_region()
        _clear_all()
        for r, line in enumerate(lines, start=1):
            _raw(f"{ESC}[{r};1H{line}{ESC}[K")
        _set_scroll_region(self.body_top, rows)
        _goto(self.body_top, 1)
        sys.stdout.flush()
        return True

    def _refresh_pinned_header(self) -> None:
        """Redraws the pinned header in-place to reflect current state
        without disturbing or scrolling the bottom active area."""
        if not self.pinned_header:
            return

        cols, rows = _term_size()
        if rows != self._pin_rows or cols != self._pin_cols:
            self._setup_pinned_header()
            return

        lines = self._render_dashboard_lines(cols, rows)
        if len(lines) != self.header_height:
            self._setup_pinned_header()
            return

        _raw(f"{ESC}7")  # Save cursor position
        for r, line in enumerate(lines, start=1):
            _raw(f"{ESC}[{r};1H{line}{ESC}[K")
        _raw(f"{ESC}8")  # Restore cursor position
        sys.stdout.flush()

    def render_dashboard(self, pin: bool = True) -> None:
        """Draws the dashboard. With pin=True on a real terminal, it is
        pinned to the top of the screen via a VT100 scroll region. Otherwise,
        prints inline."""
        if pin and _is_real_tty():
            if self._setup_pinned_header():
                return
        self.pinned_header = False
        cols, rows = _term_size()
        lines = self._render_dashboard_lines(cols, rows)
        for line in lines:
            console.print(line)
        console.print()

    def clear_body(self) -> None:
        """Clears the scrollable bottom area below the pinned header."""
        if self.pinned_header:
            _raw(f"{ESC}[{self.body_top};1H{ESC}[J")
            _goto(self.body_top, 1)
            sys.stdout.flush()
        else:
            self.clear_screen()

    def _on_resize(self, signum, frame) -> None:
        # Signal handlers should do minimal work; just flag it and let the
        # main loop redraw once it's safe to do so.
        self._resize_pending = True

    # --- Interactive Action Implementations ---

    def action_select_binary(self):
        """Browse local ELFs or type custom binary path."""
        console.print()
        console.print(Rule("[bold cyan][ Select Target Binary ][/bold cyan]"))
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

        choice = ask("[bold cyan]Select an option[/bold cyan]", default="1" if local_elfs else "c")
        if choice.lower() == "b":
            return
        elif choice.lower() == "c":
            path = ask("[bold cyan]Enter path to target ELF binary[/bold cyan]")
            if not path:
                return
            if not os.path.isfile(path):
                self.set_status(f"File not found: {path}", "bold red")
                console.print(f"[bold red]✗ File not found: {path}[/bold red]")
                return
            self.analyze_binary_silent(path)
        elif choice.isdigit() and 1 <= int(choice) <= len(local_elfs):
            selected = local_elfs[int(choice) - 1]["path"]
            self.analyze_binary_silent(selected)
        else:
            self.set_status(f"Invalid selection: {choice}", "yellow")
            console.print(f"[yellow][!] Invalid selection: {choice}[/yellow]")

    def action_detect_offset(self):
        """Auto-detect offset via De Bruijn cyclic crash."""
        if not self.binary_path or not os.path.isfile(self.binary_path):
            self.set_status("Please select a target binary first.", "bold red")
            console.print("[bold red]✗ Please select a target binary first.[/bold red]")
            return

        console.print()
        console.print(Rule("[bold cyan][ Buffer Overflow Offset Auto-Detection ][/bold cyan]"))
        console.print()
        console.print(f"Target: [bold white]{self.binary_path}[/bold white]  │  Delivery: [bold cyan]{self.input_mode}[/bold cyan]")
        console.print()

        max_len_str = ask("Max cyclic pattern length", default="2048")
        try:
            max_len = int(max_len_str)
        except ValueError:
            max_len = 2048

        console.print("[cyan][*] Crashing target with De Bruijn cyclic pattern & inspecting core dump...[/cyan]")
        try:
            offset = core.find_offset(self.binary_path, max_len=max_len, input_mode=self.input_mode)
            self.offset = offset
            self.offset_validated = False
            self.set_status(f"Offset found: {offset} bytes (via core dump crash analysis)", "bold green")
            console.print(f"[bold green]✓ Offset successfully detected: {self.offset} bytes![/bold green]")
        except Exception as e:
            self.set_status(f"Offset detection failed: {e}", "bold red")
            console.print(f"[bold red]✗ Offset detection failed: {e}[/bold red]")
            return

        if confirm("Validate this offset now with marker crash test?", default=True):
            self.action_validate_offset()

    def action_validate_offset(self):
        """Sanity check proposed offset with marker bytes."""
        if not self.binary_path or self.offset is None:
            self.set_status("Target binary and offset must be set before validation.", "bold red")
            console.print("[bold red]✗ Target binary and offset must be set before validation.[/bold red]")
            return

        console.print(f"[cyan][*] Validating offset {self.offset} with test marker crash...[/cyan]")
        try:
            is_valid = core.validate_offset(self.binary_path, self.offset, input_mode=self.input_mode)
            if is_valid:
                self.offset_validated = True
                self.set_status(f"Offset {self.offset} verified and validated successfully! (RIP/EIP precisely controlled)", "bold green")
                console.print(f"[bold green]✓ Offset {self.offset} verified: instruction pointer precisely controlled![/bold green]")
            else:
                self.offset_validated = False
                self.set_status(f"Offset {self.offset} validation failed (marker did not match instruction pointer)", "bold yellow")
                console.print(f"[bold yellow]✗ Offset {self.offset} validation failed: marker did not match instruction pointer.[/bold yellow]")
        except Exception as e:
            self.set_status(f"Validation error: {e}", "bold red")
            console.print(f"[bold red]✗ Validation error: {e}[/bold red]")

    def action_set_win_addr(self):
        """Configure win function address or symbol."""
        console.print()
        console.print(Rule("[bold magenta][ Configure Win Function ][/bold magenta]"))
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

        choice = ask("[bold magenta]Select win target[/bold magenta]", default="1" if candidates else "c")
        if choice.lower() == "b":
            return
        elif choice.lower() == "c":
            val = ask("[bold magenta]Enter address or symbol[/bold magenta]")
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
                custom_ret = ask(
                    "Enter lone ret gadget address (hex, no gadget auto-detected)",
                    default=""
                )
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
        console.print(Rule("[bold cyan][ Configure Exploit Destination ][/bold cyan]"))
        console.print()
        console.print("  [bold cyan][1][/bold cyan] Launch Local Process (interactive tty session)")
        console.print("  [bold cyan][2][/bold cyan] Connect Remote CTF Service (host:port)")
        console.print("  [bold cyan][3][/bold cyan] Generate Payload File Only (save to disk)")
        console.print(f"  {kbadge('b', 'bold yellow')} Back")
        console.print()

        choice = ask("Select destination", default="1")
        if choice == "1":
            self.target_mode = "local"
            self.set_status("Destination set to Local Process", "bold green")
        elif choice == "2":
            self.target_mode = "remote"
            host = ask("Remote Host / IP", default=self.remote_host or "127.0.0.1")
            port = ask("Remote Port", default=self.remote_port or "1337")
            self.remote_host = host
            self.remote_port = port
            self.set_status(f"Destination set to Remote Service: {host}:{port}", "bold green")
        elif choice == "3":
            self.target_mode = "file"
            self.output_path = ask("Output file path", default=self.output_path)
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
        console.print(Rule("[bold cyan][ Payload Inspector & Colorized Hexdump ][/bold cyan]"))
        console.print()
        console.print(table)
        console.print()
        console.print(Panel(hexdump_text, title="[bold green]Colorized Hexdump (Red=Junk, Yellow=Ret Align, Green=Win Address)[/bold green]", border_style="green"))
        console.print(f"  {kbadge('c')} Copy raw hex to clipboard")
        console.print(f"  {kbadge('b')} Copy Python bytes literal to clipboard")
        console.print(f"  {kbadge('s')} Save to file")
        console.print(f"  {kbadge('Enter', 'bold yellow')} Back to main menu")
        console.print()

        sub_choice = ask("Action", default="").lower()
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
        console.print(Rule("[bold cyan][ ELF Symbol Browser ][/bold cyan]"))
        console.print()

        filter_query = ask("Filter symbols by name/address (leave empty for all)", default="").lower()

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
            tag = "[bold green][CANDIDATE][/bold green]" if is_cand else "[dim]Function[/dim]"
            name_disp = f"[bold green]{sym['name']}[/bold green]" if is_cand else sym["name"]
            sym_table.add_row(str(i + 1), name_disp, sym["addr"], tag)

        console.print(sym_table)
        if len(matched) > 40:
            console.print(f"[dim]...showing 40 of {len(matched)} matching symbols. Refine filter to narrow down.[/dim]")

        console.print("\nPick a number to set as win target, or press [bold yellow]Enter[/bold yellow] to go back.")
        pick = ask("Selection", default="")
        if pick.isdigit() and 1 <= int(pick) <= min(40, len(matched)):
            selected = matched[int(pick) - 1]
            self.win_addr_str = selected["addr"]
            self.set_status(f"Win target set to {selected['name']} ({selected['addr']})", "bold green")

    def action_generate_payload(self):
        """Write raw payload to disk."""
        win_parsed = self._get_parsed_win_addr()
        if self.offset is None or win_parsed is None:
            self.set_status("Offset and win address required to build payload.", "bold red")
            console.print("[bold red]✗ Offset and win address required to build payload.[/bold red]")
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
            console.print(f"[bold green]✓ Payload written to {self.output_path} ({len(payload)} bytes)[/bold green]")
        except Exception as e:
            self.set_status(f"Failed to write payload: {e}", "bold red")
            console.print(f"[bold red]✗ Failed to write payload: {e}[/bold red]")

    def action_fire_exploit(self):
        """Unified exploit control: review parameters, inspect/save solve.py, and fire exploit."""
        bits = self.binary_info["bits"] if self.binary_info else 64
        ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None
        remote_target = (self.remote_host, int(self.remote_port)) if (self.target_mode == "remote" and self.remote_host and self.remote_port.isdigit()) else None

        win_parsed = self._get_parsed_win_addr()
        bin_p = self.binary_path or "./vuln"
        off_val = self.offset if self.offset is not None else 0
        win_val = win_parsed if win_parsed is not None else 0x0

        script_code = core.generate_solve_script(
            binary_path=bin_p,
            offset=off_val,
            win_addr=win_val,
            bits=bits,
            align=self.align,
            ret_gadget=ret_g_parsed,
            remote_target=remote_target,
            input_mode=self.input_mode
        )
        user_edited = False

        while True:
            win_parsed = self._get_parsed_win_addr()
            bits = self.binary_info["bits"] if self.binary_info else 64
            ret_g_parsed = self._get_parsed_ret_gadget() if self.align else None
            remote_target = (self.remote_host, int(self.remote_port)) if (self.target_mode == "remote" and self.remote_host and self.remote_port.isdigit()) else None
            dest_desc = f"Local Process ({self.binary_path})" if self.target_mode == "local" else f"Remote Service ({self.remote_host}:{self.remote_port})"

            # Build payload preview if parameters are ready
            payload = None
            if self.offset is not None and win_parsed is not None:
                try:
                    payload = core.build_payload(
                        offset=self.offset,
                        win_addr=win_parsed,
                        bits=bits,
                        align=self.align,
                        ret_gadget=ret_g_parsed
                    )
                except Exception:
                    payload = None

            console.print()
            console.print(Rule("[bold cyan][ Exploit & solve.py Control ][/bold cyan]"))
            console.print()

            tgt_display = dest_desc if self.binary_path else "[yellow]No binary selected[/yellow]"
            off_display = f"[bold yellow]{self.offset} bytes[/bold yellow]" if self.offset is not None else "[yellow]Not detected (press [o] or [2])[/yellow]"
            win_display = f"[bold green]{hex(win_parsed)}[/bold green]" if win_parsed is not None else "[yellow]Not set (press [w] or [4])[/yellow]"
            pay_display = f"[bold green]{len(payload)} bytes[/bold green]" if payload else "[dim]Not ready[/dim]"

            save_fmt_display = "solve.py" if getattr(self, "_save_format", "py") == "py" else "payload.bin"
            console.print(f"Target:       [bold cyan]{tgt_display}[/bold cyan]")
            console.print(f"Payload Size: {pay_display}")
            console.print(f"Win Address:  {win_display}")
            console.print(f"Offset:       {off_display}")
            console.print(f"Delivery:     [bold cyan]{self.input_mode}[/bold cyan]")
            console.print()
            console.print(Syntax(script_code, "python", theme="monokai", line_numbers=True))
            console.print()
            console.print("  [bold cyan][1][/bold cyan] Edit script code ($EDITOR)")
            console.print(f"  [bold cyan][2][/bold cyan] Save exploit file [dim](format: [bold green]{save_fmt_display}[/bold green] | {kbadge('t', 'bold cyan')} to toggle)[/dim]")
            console.print("  [bold cyan][3][/bold cyan] Run py code directly in ret2win")
            console.print("  [bold cyan][4][/bold cyan] Copy script code to clipboard")
            win_curr = hex(win_parsed) if win_parsed is not None else "not set"
            off_curr = f"{self.offset}B" if self.offset is not None else "not set"
            console.print(f"  {kbadge('w', 'bold cyan')} Set/Change Win Target [dim]({win_curr})[/dim]")
            console.print(f"  {kbadge('o', 'bold cyan')} Set/Change Offset [dim]({off_curr})[/dim]")
            console.print(f"  {kbadge('b', 'bold yellow')} Back to main menu")
            console.print()

            try:
                choice = ask("Action", default="3").lower()
            except (KeyboardInterrupt, EOFError):
                break

            if choice in ("1", "e", "edit"):
                with open("solve.py", "w") as f:
                    f.write(script_code)

                editor_env = os.environ.get("VISUAL") or os.environ.get("EDITOR")
                editor_cmd = []
                if editor_env:
                    editor_cmd = shlex.split(editor_env)
                else:
                    for candidate in ["nvim", "vim", "nano", "micro", "vi"]:
                        if shutil.which(candidate):
                            editor_cmd = [candidate]
                            break

                if not editor_cmd:
                    custom_ed = ask("No default editor found. Enter editor command (e.g. nano, vim)", default="nano").strip()
                    if custom_ed and shutil.which(custom_ed.split()[0]):
                        editor_cmd = shlex.split(custom_ed)
                    else:
                        self.set_status("No valid editor available.", "bold red")
                        console.print("[bold red][!] No valid editor found on system.[/bold red]")
                        continue

                # Reset scroll region so full-screen editor has the full terminal window
                if self.pinned_header:
                    _reset_scroll_region()
                    _clear_all()

                try:
                    subprocess.run(editor_cmd + ["solve.py"], check=False)
                except Exception as e:
                    console.print(f"[bold red][!] Editor launch error: {e}[/bold red]")
                finally:
                    if hasattr(sys, "__stdin__") and sys.__stdin__ is not None:
                        sys.stdin = sys.__stdin__
                    if hasattr(sys, "__stdout__") and sys.__stdout__ is not None:
                        sys.stdout = sys.__stdout__
                    if hasattr(sys, "__stderr__") and sys.__stderr__ is not None:
                        sys.stderr = sys.__stderr__
                    builtins.input = getattr(builtins, "_orig_input", _orig_input)
                    if self.pinned_header:
                        self._setup_pinned_header()

                try:
                    with open("solve.py", "r") as f:
                        script_code = f.read()
                    user_edited = True
                    self.set_status("solve.py updated from editor.", "bold green")
                    console.print("[bold green]✓ solve.py successfully updated from editor![/bold green]")
                except Exception as e:
                    console.print(f"[bold red][!] Could not read updated solve.py: {e}[/bold red]")

            elif choice in ("2", "s", "save"):
                console.print()
                console.print(Rule("[bold cyan][ Save Exploit File ][/bold cyan]"))
                console.print()
                cur_fmt = getattr(self, "_save_format", "py")
                console.print(f"  Current Save Format: [bold green]{'solve.py (Python script)' if cur_fmt == 'py' else 'payload.bin (Raw binary)'}[/bold green]")
                console.print("  [bold cyan][1][/bold cyan] Save as Python script ([bold green]solve.py[/bold green])")
                console.print("  [bold cyan][2][/bold cyan] Save as Raw binary payload ([bold green]payload.bin[/bold green])")
                console.print(f"  {kbadge('t', 'bold cyan')} Toggle default format [dim]({cur_fmt} ➜ {'bin' if cur_fmt == 'py' else 'py'})[/dim]")
                console.print(f"  {kbadge('b', 'bold yellow')} Cancel")
                console.print()

                def_opt = "1" if cur_fmt == "py" else "2"
                save_sub = ask("Select save option", default=def_opt).lower()

                if save_sub in ("1", "py", "p", "script"):
                    self._save_format = "py"
                    with open("solve.py", "w") as f:
                        f.write(script_code)
                    self.set_status("solve.py successfully saved to current directory!", "bold green")
                    console.print("[bold green]✓ solve.py saved to current directory![/bold green]")

                elif save_sub in ("2", "bin", "b", "raw", "payload"):
                    self._save_format = "bin"
                    win_parsed = self._get_parsed_win_addr()
                    if self.offset is None or win_parsed is None:
                        console.print("[yellow][!] Offset and win address are required to generate raw payload.bin.[/yellow]")
                        if self.offset is None:
                            o = ask("Enter offset in bytes").strip()
                            if o.isdigit() and int(o) >= 0:
                                self.offset = int(o)
                        if win_parsed is None:
                            w = ask("Enter win address or symbol").strip()
                            if w:
                                try:
                                    self.win_addr_str = w
                                    win_parsed = self._get_parsed_win_addr()
                                except Exception:
                                    pass

                    if self.offset is not None and win_parsed is not None:
                        bin_payload = core.build_payload(
                            offset=self.offset,
                            win_addr=win_parsed,
                            bits=bits,
                            align=self.align,
                            ret_gadget=ret_g_parsed
                        )
                        out_path = self.output_path or "payload.bin"
                        with open(out_path, "wb") as f:
                            f.write(bin_payload)
                        self.set_status(f"Raw payload saved to {out_path} ({len(bin_payload)} bytes)!", "bold green")
                        console.print(f"[bold green]✓ Raw binary payload saved to {out_path} ({len(bin_payload)} bytes)![/bold green]")
                    else:
                        console.print("[bold red]✗ Cannot generate payload.bin without offset and win address.[/bold red]")

                elif save_sub in ("t", "toggle"):
                    self._save_format = "bin" if cur_fmt == "py" else "py"
                    new_label = "solve.py" if self._save_format == "py" else "payload.bin"
                    self.set_status(f"Default save format toggled to {new_label}", "bold green")
                    console.print(f"[bold green]✓ Default save format toggled to: {new_label}[/bold green]")

            elif choice in ("3", "r", "run", "fire", "x"):
                # Interactively check & ask for binary if missing
                if not self.binary_path or not os.path.isfile(self.binary_path):
                    console.print("[yellow][!] No target binary selected.[/yellow]")
                    p = ask("Enter path to target ELF binary").strip()
                    if p and os.path.isfile(p):
                        self.analyze_binary_silent(p)
                    else:
                        console.print("[bold red]✗ Valid target binary required to run exploit.[/bold red]")
                        continue

                # Interactively check & ask for offset if missing
                if self.offset is None:
                    console.print("[yellow][!] Buffer overflow offset is not set.[/yellow]")
                    o = ask("Enter offset in bytes (or press Enter to run Auto-Detect)").strip()
                    if o.isdigit() and int(o) >= 0:
                        self.offset = int(o)
                    elif not o:
                        self.action_detect_offset()
                        if self.offset is None:
                            continue
                    else:
                        console.print("[bold red]✗ Offset required to run exploit.[/bold red]")
                        continue

                # Interactively check & ask for win address if missing
                win_parsed = self._get_parsed_win_addr()
                if win_parsed is None:
                    console.print("[yellow][!] Win function address is not set.[/yellow]")
                    w = ask("Enter win address or symbol (e.g. 0x401156 or 'win')").strip()
                    if w:
                        symbols = self.binary_info.get("symbols") if self.binary_info else None
                        try:
                            parsed = core.parse_address(w, symbols=symbols)
                            self.win_addr_str = w
                            win_parsed = parsed
                        except Exception as e:
                            console.print(f"[bold red]✗ Could not resolve win address '{w}': {e}[/bold red]")
                            continue
                    else:
                        console.print("[bold red]✗ Win address required to run exploit.[/bold red]")
                        continue

                # Refresh script from updated parameters if not manually modified in editor
                if not user_edited:
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

                payload = core.build_payload(
                    offset=self.offset,
                    win_addr=win_parsed,
                    bits=bits,
                    align=self.align,
                    ret_gadget=ret_g_parsed
                )

                if self.target_mode == "local" and self.input_mode == "argv" and b"\x00" in payload[:-1]:
                    console.print(
                        "\n[bold red][!] This payload contains a null byte before its "
                        "final byte, so it cannot be passed whole as an argv[] "
                        "argument (argv strings are NUL-terminated). Switch delivery "
                        "to stdin (if supported by the target) or pick a win "
                        "address/gadget without embedded null bytes.[/bold red]"
                    )
                    ask("[dim]Press Enter to continue...[/dim]", default="")
                    self.set_status("Exploit aborted: argv payload contains null bytes.", "bold red")
                    continue

                with open("solve.py", "w") as f:
                    f.write(script_code)

                dest_desc = f"Local Process ({self.binary_path})" if self.target_mode == "local" else f"Remote Service ({self.remote_host}:{self.remote_port})"
                console.print("\n" + "=" * 65)
                console.print(f"[+] Ret2Win: Launching exploit against {dest_desc} via solve.py...")
                console.print(f"[+] Sending payload ({len(payload)} bytes)...")
                console.print("=" * 65 + "\n")

                try:
                    subprocess.run([sys.executable, "solve.py"], check=False)
                except Exception as e:
                    console.print(f"\n[bold red][!] Execution error: {e}[/bold red]")
                finally:
                    if hasattr(sys, "__stdin__") and sys.__stdin__ is not None:
                        sys.stdin = sys.__stdin__
                    if hasattr(sys, "__stdout__") and sys.__stdout__ is not None:
                        sys.stdout = sys.__stdout__
                    if hasattr(sys, "__stderr__") and sys.__stderr__ is not None:
                        sys.stderr = sys.__stderr__
                    builtins.input = getattr(builtins, "_orig_input", _orig_input)
                    if self.pinned_header:
                        cols, rows = _term_size()
                        self._pin_rows = rows
                        self._pin_cols = cols
                        _set_scroll_region(self.body_top, rows, target_row=rows)
                        _raw("\n")
                        self._refresh_pinned_header()

                console.print("\n" + "=" * 65)
                console.print("[*] Exploit execution complete.")
                ask("[dim]Press Enter to return to exploit menu...[/dim]", default="")
                self.set_status("Returned from exploit execution session.", "bold green")

            elif choice in ("t", "toggle"):
                cur_fmt = getattr(self, "_save_format", "py")
                self._save_format = "bin" if cur_fmt == "py" else "py"
                new_label = "solve.py" if self._save_format == "py" else "payload.bin"
                self.set_status(f"Default save format toggled to {new_label}", "bold green")
                console.print(f"[bold green]✓ Default save format toggled to: {new_label}[/bold green]")

            elif choice in ("w", "win"):
                w = ask("Enter win function address or symbol name (e.g. 0x401156 or 'win')").strip()
                if w:
                    symbols = self.binary_info.get("symbols") if self.binary_info else None
                    try:
                        parsed = core.parse_address(w, symbols=symbols)
                        self.win_addr_str = w
                        win_parsed = parsed
                        if not user_edited:
                            script_code = core.generate_solve_script(
                                binary_path=self.binary_path or "./vuln",
                                offset=self.offset if self.offset is not None else 0,
                                win_addr=win_parsed,
                                bits=bits,
                                align=self.align,
                                ret_gadget=ret_g_parsed,
                                remote_target=remote_target,
                                input_mode=self.input_mode
                            )
                        self.set_status(f"Win target set to {w}", "bold green")
                        console.print(f"[bold green]✓ Win target updated: {w} ({hex(win_parsed)})[/bold green]")
                    except Exception as e:
                        console.print(f"[bold red]✗ Failed to resolve '{w}': {e}[/bold red]")

            elif choice in ("o", "offset"):
                o = ask("Enter buffer overflow offset in bytes").strip()
                if o.isdigit() and int(o) >= 0:
                    self.offset = int(o)
                    win_parsed = self._get_parsed_win_addr()
                    if not user_edited:
                        script_code = core.generate_solve_script(
                            binary_path=self.binary_path or "./vuln",
                            offset=self.offset,
                            win_addr=win_parsed if win_parsed is not None else 0x0,
                            bits=bits,
                            align=self.align,
                            ret_gadget=ret_g_parsed,
                            remote_target=remote_target,
                            input_mode=self.input_mode
                        )
                    self.set_status(f"Offset set to {self.offset} bytes", "bold green")
                    console.print(f"[bold green]✓ Offset updated: {self.offset} bytes[/bold green]")
                else:
                    console.print("[bold red]✗ Invalid offset. Please enter a non-negative integer.[/bold red]")

            elif choice in ("4", "c", "copy"):
                if copy_to_clipboard(script_code):
                    self.set_status("solve.py script copied to clipboard!", "bold green")
                    console.print("[bold green]✓ solve.py copied to clipboard![/bold green]")
                else:
                    self.set_status("Clipboard tool not found. Use option [2] to save to solve.py.", "yellow")
                    console.print("[yellow][!] Clipboard tool not found (wl-copy/xclip).[/yellow]")

            elif choice in ("b", "back", "q", "exit"):
                break
            else:
                console.print(f"[yellow][!] Invalid option '{choice}'. Choose 1 (edit), 2 (save), 3 (run), 4 (copy), or b (back).[/yellow]")

    # Aliases for unified exploit action
    action_solve_script = action_fire_exploit
    action_run_solve_script = action_fire_exploit

    def _render_help_index(self) -> Panel:
        index_text = f"""[bold bright_white]Select a topic below, step through sequentially, or open the continuous guide in pager:[/bold bright_white]

  {kbadge("1")} [bold white]Quick-Start CTF Solve Workflow[/bold white]     [dim]4-step fast path to pop a shell[/dim]
  {kbadge("2")} [bold white]Mission Control Actions Reference[/bold white]  [dim]Complete breakdown of [1]-[9], {kbadge('f', 'bold red')}, {kbadge('h')}, {kbadge('q')}[/dim]
  {kbadge("3")} [bold white]Exploit Workshop Guide ({kbadge('f')})[/bold white]       [dim]In-TUI editor, py/bin toggling, run & copy[/dim]
  {kbadge("4")} [bold white]CTF Binary Exploitation Cheatsheet[/bold white] [dim]movaps 16B alignment, argv[1] nulls, #GP, PIE[/dim]
  {kbadge("5")} [bold white]CLI & Headless Scripting Reference[/bold white] [dim]Automation flags, batch solves, remote exploitation[/dim]

  {kbadge("a", "bold green")} [bold green]Step through all topics sequentially (1 ➜ 5)[/bold green]
  {kbadge("p", "bold yellow")} [bold yellow]Open entire guide in full pager (less -R / scrollable)[/bold yellow]
  {kbadge("b", "bold bright_black")} [dim white]Back to Main Dashboard[/dim white]"""
        return Panel(index_text, title="[bold bright_cyan][ Ret2Win Help & CTF Guide ][/bold bright_cyan]", border_style="cyan")

    def _render_help_topic_1(self) -> Panel:
        quickstart_text = f"""[bold bright_green][ Fast-Track 4-Step CTF Solve Workflow ][/bold bright_green]
  {kbadge("1")} [bold white]Select/Scan Target[/bold white]       Scan current directory or enter path to ELF. Automatically runs checksec and flags candidates.
  {kbadge("2")} [bold white]Auto-Detect Offset[/bold white]       Crashes binary with cyclic pattern via core dump analysis to find exact overwrite offset.
  {kbadge("4")} [bold white]Configure Win Target[/bold white]     Select discovered win function or enter custom hex address (0x401156) or symbol name.
  {kbadge("f", "bold red")} [bold white]Fire & solve.py Control[/bold white]  Open exploit workshop to edit [1], save [2], or execute directly in ret2win [3]!

[dim]Tip: Checksec warnings highlight whether NX, Canary, or PIE are present before you start.[/dim]"""
        return Panel(quickstart_text, title="[bold bright_cyan][ Help 1/5: Quick-Start CTF Solve Workflow ][/bold bright_cyan]", border_style="cyan")

    def _render_help_topic_2(self) -> Panel:
        menu_ref = Table(box=None, padding=(0, 1), expand=True, show_header=True)
        menu_ref.add_column("Key", style="bold cyan", width=7)
        menu_ref.add_column("Action", style="bold white", width=22)
        menu_ref.add_column("Capabilities & Notes", style="dim white")
        menu_ref.add_row(kbadge("1"), "Select/Scan Binary", "Checksec audit (NX, Canary, PIE, RELRO); candidate win functions.")
        menu_ref.add_row(kbadge("2"), "Auto-Detect Offset", "Cyclic crash pattern analysis; non-canonical 64-bit RIP handling.")
        menu_ref.add_row(kbadge("3"), "Validate Offset", "Marker pattern verification (0xdeadbeef) for instruction pointer control.")
        menu_ref.add_row(kbadge("4"), "Set Win Address", "Accepts function symbol (win, flag) or hex address (0x401156, 0x122d).")
        menu_ref.add_row(kbadge("5"), "16B Stack Alignment", "Prepends ret gadget on x86_64 before win() to fix movaps glibc crash.")
        menu_ref.add_row(kbadge("6"), "Toggle Delivery", "Switches stdin vs argv[1]. Alerts on null bytes in argument mode.")
        menu_ref.add_row(kbadge("7"), "Exploit Destination", "Toggles between Local Process and Remote Service (host:port).")
        menu_ref.add_row(kbadge("8"), "Inspect Payload", "Displays hexdump, ASCII view, and memory anatomy breakdown.")
        menu_ref.add_row(kbadge("9"), "Symbol Browser", "Searchable ELF function table with addresses and sizes.")
        menu_ref.add_row(kbadge("f", "bold red"), "Exploit Workshop", "Edit code in $EDITOR, save solve.py/payload.bin, or run exploit directly.")
        menu_ref.add_row(kbadge("h"), "Help & CTF Guide", "Interactive guide, CTF cheatsheet, and headless CLI reference.")
        menu_ref.add_row(kbadge("q", "bold bright_black"), "Quit", "Gracefully resets terminal scroll regions and exits.")
        return Panel(menu_ref, title="[bold bright_cyan][ Help 2/5: Mission Control Actions Reference ][/bold bright_cyan]", border_style="bright_blue", expand=True)

    def _render_help_topic_3(self) -> Panel:
        editor_display = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nvim/vim/nano"
        f_guide = f"""[bold bright_yellow][ Exploit Workshop Features ({kbadge('f')} / {kbadge('s')} / {kbadge('r')}) ][/bold bright_yellow]
  • {kbadge("1")} [bold white]Edit script code[/bold white]      : Opens solve.py in {editor_display}. Reads back changes on exit.
  • {kbadge("2")} [bold white]Save exploit file[/bold white]   : Saves either standalone solve.py or raw payload.bin. Toggle default format with {kbadge("t")}.
  • {kbadge("3")} [bold white]Run py code directly[/bold white]: Executes solve.py in an isolated subprocess with full interactive shell access (io.interactive()).
  • {kbadge("4")} [bold white]Copy code[/bold white]           : Copies python solve script to system clipboard via wl-copy (Wayland) or xclip (X11).
  • {kbadge("w")} / {kbadge("o")} [bold white]Inline Config[/bold white] : Change win address or overflow offset directly inside the submenu without leaving."""
        return Panel(f_guide, title=f"[bold bright_yellow][ Help 3/5: Exploit Workshop Features ({kbadge('f', 'bold bright_yellow')}) ][/bold bright_yellow]", border_style="yellow")

    def _render_help_topic_4(self) -> Panel:
        pwn_tips = f"""  {kbadge("1", "bold red")} [bold white]x86_64 SIMD (movaps) 16-Byte Stack Alignment Crash:[/bold white]
     Functions like system() and printf() require RSP to be 16-byte aligned before calling.
     A direct ret2win often lands with RSP % 16 != 0, triggering SIGSEGV inside glibc.
     [bold green]Fix:[/bold green] Toggle option {kbadge("5")} (16B Alignment). Ret2Win prepends a lone ret gadget to realign RSP.

  {kbadge("2", "bold red")} [bold white]Null Bytes in argv[1] Arguments:[/bold white]
     Command-line arguments in Linux (execve) are NUL-terminated strings. If addresses contain \\x00,
     the kernel truncates the payload at the first null byte.
     [bold green]Fix:[/bold green] Deliver via stdin ({kbadge("6")}) whenever possible, or find win addresses without interior nulls.

  {kbadge("3", "bold red")} [bold white]Non-Canonical RIP Fault on x86_64 (#GP vs SIGSEGV):[/bold white]
     Addresses > 0x00007fffffffffff trigger #GP *before* RIP updates, leaving RIP at ret opcode.
     [bold green]Fix:[/bold green] Ret2Win inspects core dump fault address and stack memory to find true offset.

  {kbadge("4", "bold red")} [bold white]PIE (Position Independent Executable):[/bold white]
     When PIE is enabled, addresses in the binary are relative offsets (e.g. 0x122d).
     [bold green]Fix:[/bold green] For remote CTFs, leak the binary base address or ASLR base to calculate absolute target."""
        return Panel(pwn_tips, title="[bold bright_magenta][ Help 4/5: CTF Binary Exploitation Cheatsheet ][/bold bright_magenta]", border_style="magenta")

    def _render_help_topic_5(self) -> Panel:
        cli_guide = """[bold bright_white]Ret2Win can be used completely headlessly in scripts or CTF solve pipelines without the TUI:[/bold bright_white]

  [dim]# Auto-detect offset and generate solve.py:[/dim]
  [bold white]$ python3 ret2win.py --binary ./vuln --win-addr 0x401156 --script solve.py[/bold white]

  [dim]# Auto-detect offset and fire exploit locally with interactive shell:[/dim]
  [bold white]$ python3 ret2win.py --binary ./vuln --win-addr win --run[/bold white]

  [dim]# Generate raw binary payload file with 16B stack alignment:[/dim]
  [bold white]$ python3 ret2win.py --binary ./vuln --offset 40 --win-addr 0x401176 --align --output payload.bin[/bold white]

  [dim]# Exploit a remote CTF challenge service:[/dim]
  [bold white]$ python3 ret2win.py --binary ./vuln --win-addr 0x401156 --remote ctf.challenge.org 1337 --run[/bold white]"""
        return Panel(cli_guide, title="[bold bright_cyan][ Help 5/5: CLI & Headless Reference ][/bold bright_cyan]", border_style="cyan")

    def _get_full_help_ansi(self) -> str:
        cols, _ = _term_size()
        c = Console(record=True, width=min(cols, _MAX_SANE_WIDTH))
        c.print()
        c.print(Rule("[bold cyan][ Ret2Win Exploitation & CTF Guide ][/bold cyan]"))
        c.print()
        c.print(self._render_help_topic_1())
        c.print()
        c.print(self._render_help_topic_2())
        c.print()
        c.print(self._render_help_topic_3())
        c.print()
        c.print(self._render_help_topic_4())
        c.print()
        c.print(self._render_help_topic_5())
        c.print()
        return c.export_text(clear=True, styles=True)

    def _open_help_in_pager(self):
        ansi_text = self._get_full_help_ansi()
        if self.pinned_header:
            _reset_scroll_region()
            _clear_all()
        try:
            if shutil.which("less"):
                with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tmp:
                    tmp.write(ansi_text)
                    tmp_name = tmp.name
                try:
                    subprocess.run(["less", "-R", tmp_name], check=False)
                finally:
                    if os.path.exists(tmp_name):
                        try:
                            os.unlink(tmp_name)
                        except OSError:
                            pass
            else:
                import pydoc
                pydoc.pager(ansi_text)
        except Exception as e:
            console.print(f"[bold red][!] Pager error: {e}[/bold red]")
        finally:
            if hasattr(sys, "__stdin__") and sys.__stdin__ is not None:
                sys.stdin = sys.__stdin__
            if hasattr(sys, "__stdout__") and sys.__stdout__ is not None:
                sys.stdout = sys.__stdout__
            if hasattr(sys, "__stderr__") and sys.__stderr__ is not None:
                sys.stderr = sys.__stderr__
            builtins.input = getattr(builtins, "_orig_input", _orig_input)
            if self.pinned_header:
                self._setup_pinned_header()

    def action_show_help(self):
        """Displays interactive, paginated help and CTF guide with topic selection and full pager."""
        curr_topic = 0  # 0 indicates Index / Table of Contents

        while True:
            self.clear_body()

            if curr_topic == 0:
                console.print()
                console.print(self._render_help_index())
                console.print()
                choice = ask("Help Option [1-5=Topic, Enter/a=Start from Topic 1, p=Pager, b=Back]", default="1").strip().lower()

                if choice in ("b", "back", "q", "exit"):
                    break
                elif choice in ("p", "pager"):
                    self._open_help_in_pager()
                    continue
                elif choice in ("1", "a", "all", ""):
                    curr_topic = 1
                elif choice in ("2", "3", "4", "5"):
                    curr_topic = int(choice)
                else:
                    console.print(f"[yellow][!] Invalid option '{choice}'. Choose 1-5, a (step through), p (pager), or b (back).[/yellow]")
                    ask("[dim]Press Enter to continue...[/dim]", default="")
            else:
                console.print()
                if curr_topic == 1:
                    console.print(self._render_help_topic_1())
                elif curr_topic == 2:
                    console.print(self._render_help_topic_2())
                elif curr_topic == 3:
                    console.print(self._render_help_topic_3())
                elif curr_topic == 4:
                    console.print(self._render_help_topic_4())
                elif curr_topic == 5:
                    console.print(self._render_help_topic_5())
                console.print()

                next_prompt = "Finish & Return" if curr_topic == 5 else f"Next ({curr_topic + 1}/5)"
                nav_choice = ask(
                    f"Topic {curr_topic}/5 [Enter/n={next_prompt}, 1-5=Jump, m=Index, p=Pager, b=Back]",
                    default="n"
                ).strip().lower()

                if nav_choice in ("b", "back", "q", "exit"):
                    break
                elif nav_choice in ("m", "menu", "index", "i", "toc"):
                    curr_topic = 0
                elif nav_choice in ("p", "pager"):
                    self._open_help_in_pager()
                elif nav_choice in ("n", "next", ""):
                    if curr_topic < 5:
                        curr_topic += 1
                    else:
                        break  # Finished last topic
                elif nav_choice in ("prev", "pr"):
                    if curr_topic > 1:
                        curr_topic -= 1
                    else:
                        curr_topic = 0
                elif nav_choice in ("1", "2", "3", "4", "5"):
                    curr_topic = int(nav_choice)
                else:
                    console.print(f"[yellow][!] Choose Enter/n (next), 1-5, m (index), p (pager), or b (back).[/yellow]")
                    ask("[dim]Press Enter to continue...[/dim]", default="")

        self.clear_body()
        self.set_status("Returned from help and CTF guide.", "bold green")

    def run(self):
        """Main interactive application loop.

        The banner/panels/menu dashboard is drawn once at the start and
        pinned to the top of the screen via a terminal scroll region (see
        the module-level comment above _is_real_tty): it stays fixed in
        place, refreshed in-place after each action so it always reflects
        current state, while everything below it (prompts, action output,
        status history) scrolls like a normal CLI session. On a terminal
        that can't support that (piped output, a captured transcript, a
        dumb TERM, or a window too small to fit the header), it falls back
        to the previous behavior of printing the dashboard inline, with
        [m] available to print it again if it's scrolled out of view.
        """
        use_pin = _is_real_tty()
        if use_pin:
            # SIGWINCH fires on terminal resize; the handler flags it,
            # and the loop below redraws and re-pins once safe.
            try:
                signal.signal(signal.SIGWINCH, self._on_resize)
                if hasattr(signal, "siginterrupt"):
                    signal.siginterrupt(signal.SIGWINCH, False)
            except (AttributeError, ValueError):
                pass
        else:
            self.clear_screen()
        self.render_dashboard(pin=use_pin)

        try:
            while True:
                if self._resize_pending:
                    self._resize_pending = False
                    if self.pinned_header:
                        self._setup_pinned_header()
                    else:
                        self.render_dashboard(pin=False)

                try:
                    cmd = ask("[bold bright_cyan]ret2win[/bold bright_cyan] [dim]➜[/dim]").lower()
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
                elif cmd in ("f", "fire", "exploit", "pwn", "s", "solve", "script", "r", "run"):
                    self.action_fire_exploit()
                elif cmd in ("g", "generate", "gen"):
                    self.action_generate_payload()
                elif cmd in ("h", "help", "?"):
                    self.action_show_help()
                elif cmd in ("clear", "cls"):
                    self.clear_body()
                    continue
                elif cmd in ("m", "menu", "dashboard"):
                    if self.pinned_header:
                        self._setup_pinned_header()
                    else:
                        self.render_dashboard(pin=False)
                    continue
                elif cmd == "":
                    continue
                else:
                    self.set_status(f"Unknown action '{cmd}'. Type [h] for help or select 1-9, f, h, q.", "yellow")
                    console.print(f"[yellow][!] Unknown action '{cmd}'. Type [h] for help or select 1-9, f, h, q.[/yellow]")

                # In pinned header mode, the status bar is updated in-place inside the
                # pinned dashboard at the top so it doesn't pollute the scrollable body.
                # In plain mode, display the status line inline.
                if not self.pinned_header:
                    console.print(f" [dim]Status:[/dim] [{self.last_status_style}]{self.last_status_msg}[/{self.last_status_style}]")
                else:
                    self._refresh_pinned_header()
        finally:
            if self.pinned_header:
                _reset_scroll_region()
                _, rows = _term_size()
                _goto(rows, 1)
                _raw("\n")
                sys.stdout.flush()
            if use_pin:
                try:
                    signal.signal(signal.SIGWINCH, signal.SIG_DFL)
                except (AttributeError, ValueError):
                    pass


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
