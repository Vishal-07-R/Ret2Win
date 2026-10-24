#!/usr/bin/env bash
# ==============================================================================
#  Ret2Win - Automated CTF Return-to-Win Exploitation Toolkit
#  Universal Installation & Setup Script
#  Author: Casper (Vishal-07-R)
#  Version: 1.3.1
# ==============================================================================

set -e

VERSION="1.3.1"
APP_NAME="ret2win"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ANSI Color & Style Palettes
BOLD="\033[1m"
DIM="\033[2m"
ITALIC="\033[3m"
RESET="\033[0m"

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
MAGENTA="\033[1;35m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"

# Status Badges
OK="${GREEN}[✔]${RESET}"
FAIL="${RED}[✖]${RESET}"
WARN="${YELLOW}[⚠]${RESET}"
INFO="${CYAN}[ℹ]${RESET}"
ARROW="${MAGENTA}[➜]${RESET}"
STAR="${YELLOW}[★]${RESET}"

# Default Settings
AUTO_CONFIRM=false
SKIP_DEPS=false
CHECK_ONLY=false
UNINSTALL=false
USE_PIPX=false
DEV_LINK=false

# Root check & default directories
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_MODE="system"
    DEFAULT_INSTALL_DIR="/opt/ret2win"
    DEFAULT_BIN_DIR="/usr/local/bin"
else
    INSTALL_MODE="user"
    DEFAULT_INSTALL_DIR="${HOME}/.local/share/ret2win"
    DEFAULT_BIN_DIR="${HOME}/.local/bin"
fi

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
BIN_DIR="${DEFAULT_BIN_DIR}"

# ------------------------------------------------------------------------------
# Banner Function
# ------------------------------------------------------------------------------
print_banner() {
    printf "${CYAN}"
    cat << "EOF"
 ██████╗ ███████╗████████╗██████╗ ██╗    ██╗██╗███╗   ██╗
 ██╔══██╗██╔════╝╚══██╔══╝╚════██╗██║    ██║██║████╗  ██║
 ██████╔╝█████╗     ██║    █████╔╝██║ █╗ ██║██║██╔██╗ ██║
 ██╔══██╗██╔══╝     ██║   ██╔═══╝ ██║███╗██║██║██║╚██╗██║
 ██║  ██║███████╗   ██║   ███████╗╚███╔███╔╝██║██║ ╚████║
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝
EOF
    printf "${RESET}"
    printf " ${BOLD}${WHITE}Automated CTF Return-to-Win Exploitation Toolkit${RESET} ${DIM}v${VERSION}${RESET}\n"
    printf " ${DIM}Created by -Casper • Architected for High-Speed CTF Binary Exploitation${RESET}\n\n"
}

# ------------------------------------------------------------------------------
# Help Function
# ------------------------------------------------------------------------------
print_help() {
    print_banner
    cat << EOF
Usage: ./install.sh [OPTIONS]

Installation Options:
  -y, --yes          Non-interactive mode (accept all default prompts)
  --user             Install for current user only (into ~/.local/share/ret2win and ~/.local/bin)
  --system           Install system-wide (requires sudo; into /opt/ret2win and /usr/local/bin)
  --dir <PATH>       Specify custom installation directory (default: ${DEFAULT_INSTALL_DIR})
  --bin-dir <PATH>   Specify custom executable link directory (default: ${DEFAULT_BIN_DIR})
  --dev, --link      Development mode: symlink current workspace directly instead of copying
  --pipx             Install via pipx instead of creating a private virtualenv
  --skip-deps        Skip detection and installation of system package manager dependencies
  --check            Run environment and dependency audit only without modifying files
  --uninstall        Completely remove Ret2Win, its virtual environment, and launcher binary
  -h, --help         Display this help menu and exit

Examples:
  ./install.sh                # Standard user installation (recommended)
  ./install.sh -y             # Automated silent user install
  sudo ./install.sh --system  # System-wide installation for all users
  ./install.sh --dev          # Link directly to active development repository
  ./install.sh --uninstall    # Remove Ret2Win from system
EOF
}

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)
            AUTO_CONFIRM=true
            shift
            ;;
        --user)
            INSTALL_MODE="user"
            INSTALL_DIR="${HOME}/.local/share/ret2win"
            BIN_DIR="${HOME}/.local/bin"
            shift
            ;;
        --system)
            INSTALL_MODE="system"
            INSTALL_DIR="/opt/ret2win"
            BIN_DIR="/usr/local/bin"
            shift
            ;;
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --bin-dir)
            BIN_DIR="$2"
            shift 2
            ;;
        --dev|--link)
            DEV_LINK=true
            shift
            ;;
        --pipx)
            USE_PIPX=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            printf "${FAIL} Unknown argument: %s\n" "$1"
            printf "Run './install.sh --help' for usage.\n"
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Prompt Helper
# ------------------------------------------------------------------------------
ask_prompt() {
    local prompt_msg="$1"
    local default_ans="${2:-Y}"
    if [ "$AUTO_CONFIRM" = true ]; then
        return 0
    fi

    local prompt_str=" [Y/n]: "
    [ "$default_ans" = "N" ] && prompt_str=" [y/N]: "

    printf "${CYAN}?${RESET} ${BOLD}%s${RESET}%s" "$prompt_msg" "$prompt_str"
    read -r response
    response="${response:-$default_ans}"
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------------------------------
# Uninstallation Routine
# ------------------------------------------------------------------------------
run_uninstall() {
    print_banner
    printf "${WARN} ${BOLD}Preparing to uninstall Ret2Win...${RESET}\n\n"

    local targets_found=0

    # Check executable wrapper
    local wrapper_path="${BIN_DIR}/${APP_NAME}"
    if [ -f "$wrapper_path" ] || [ -L "$wrapper_path" ]; then
        printf "${INFO} Found launcher binary at: ${WHITE}%s${RESET}\n" "$wrapper_path"
        targets_found=$((targets_found + 1))
    fi

    # Check installation directory
    if [ -d "$INSTALL_DIR" ]; then
        printf "${INFO} Found installation directory at: ${WHITE}%s${RESET}\n" "$INSTALL_DIR"
        targets_found=$((targets_found + 1))
    fi

    if [ "$targets_found" -eq 0 ]; then
        printf "${OK} No existing Ret2Win installation detected at %s or %s.\n" "$wrapper_path" "$INSTALL_DIR"
        exit 0
    fi

    if ask_prompt "Are you sure you want to remove Ret2Win and its components?" "Y"; then
        if [ -f "$wrapper_path" ] || [ -L "$wrapper_path" ]; then
            if [ -w "$(dirname "$wrapper_path")" ] || [ "$(id -u)" -eq 0 ]; then
                rm -f "$wrapper_path"
                printf "${OK} Removed launcher: ${WHITE}%s${RESET}\n" "$wrapper_path"
            else
                sudo rm -f "$wrapper_path"
                printf "${OK} Removed launcher (with sudo): ${WHITE}%s${RESET}\n" "$wrapper_path"
            fi
        fi

        if [ -d "$INSTALL_DIR" ]; then
            if [ -w "$(dirname "$INSTALL_DIR")" ] || [ "$(id -u)" -eq 0 ]; then
                rm -rf "$INSTALL_DIR"
                printf "${OK} Removed directory: ${WHITE}%s${RESET}\n" "$INSTALL_DIR"
            else
                sudo rm -rf "$INSTALL_DIR"
                printf "${OK} Removed directory (with sudo): ${WHITE}%s${RESET}\n" "$INSTALL_DIR"
            fi
        fi

        printf "\n${GREEN}${BOLD}✔ Ret2Win has been successfully uninstalled.${RESET}\n"
    else
        printf "${INFO} Uninstallation cancelled.\n"
    fi
    exit 0
}

[ "$UNINSTALL" = true ] && run_uninstall

# ------------------------------------------------------------------------------
# System & Package Manager Detection
# ------------------------------------------------------------------------------
detect_os() {
    OS_NAME="Unknown"
    PKG_MGR="none"
    DISTRO_ID=""

    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_NAME="${NAME:-Linux}"
        DISTRO_ID="${ID:-unknown}"
        DISTRO_LIKE="${ID_LIKE:-}"
    elif [ "$(uname -s)" = "Darwin" ]; then
        OS_NAME="macOS"
        DISTRO_ID="darwin"
    fi

    if command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    elif command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MGR="zypper"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MGR="apk"
    elif command -v brew >/dev/null 2>&1; then
        PKG_MGR="brew"
    fi
}

# ------------------------------------------------------------------------------
# Environment & Dependency Audit Function
# ------------------------------------------------------------------------------
check_environment() {
    detect_os
    printf "${BOLD}${WHITE}System Environment & Prerequisite Audit:${RESET}\n"
    printf "  ${ARROW} Operating System:    ${CYAN}%s${RESET} (%s)\n" "$OS_NAME" "$DISTRO_ID"
    printf "  ${ARROW} Package Manager:     ${CYAN}%s${RESET}\n" "$PKG_MGR"
    printf "  ${ARROW} Target Install Mode: ${CYAN}%s${RESET}\n" "$INSTALL_MODE"
    printf "  ${ARROW} Install Directory:   ${CYAN}%s${RESET}\n" "$INSTALL_DIR"
    printf "  ${ARROW} Executable Bin Path: ${CYAN}%s${RESET}\n" "${BIN_DIR}/${APP_NAME}"
    echo

    # Python Check
    PYTHON_CMD=""
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            local ver
            ver="$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || true)"
            local major
            major="$("$cmd" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || true)"
            local minor
            minor="$("$cmd" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || true)"
            if [ "$major" -eq 3 ] && [ "$minor" -ge 8 ]; then
                PYTHON_CMD="$cmd"
                PYTHON_VERSION="$ver"
                break
            fi
        fi
    done

    if [ -n "$PYTHON_CMD" ]; then
        printf "  ${OK} Python Runtime:       ${GREEN}%s (v%s)${RESET}\n" "$PYTHON_CMD" "$PYTHON_VERSION"
    else
        printf "  ${FAIL} Python Runtime:       ${RED}Python 3.8+ not found${RESET}\n"
    fi

    # venv module check
    if [ -n "$PYTHON_CMD" ] && "$PYTHON_CMD" -c "import venv" >/dev/null 2>&1; then
        printf "  ${OK} Python venv Module:   ${GREEN}Available${RESET}\n"
    else
        printf "  ${WARN} Python venv Module:   ${YELLOW}Missing (python3-venv / python-virtualenv needed)${RESET}\n"
    fi

    # GDB Check
    if command -v gdb >/dev/null 2>&1; then
        local gdb_ver
        gdb_ver="$(gdb --version | head -n1)"
        printf "  ${OK} GDB Debugger:         ${GREEN}%s${RESET}\n" "$gdb_ver"
    else
        printf "  ${WARN} GDB Debugger:         ${YELLOW}Not found (optional but strongly recommended for fallback offset detection & debugging)${RESET}\n"
    fi

    # QEMU User Check
    if command -v qemu-x86_64 >/dev/null 2>&1 || command -v qemu-arm >/dev/null 2>&1 || command -v qemu-aarch64 >/dev/null 2>&1; then
        printf "  ${OK} QEMU User Emulation:  ${GREEN}Detected (foreign architecture support ready)${RESET}\n"
    else
        printf "  ${INFO} QEMU User Emulation:  ${DIM}Not installed (only required for cross-architecture binaries like ARM/MIPS on x86)${RESET}\n"
    fi

    # Clipboard Utilities Check
    local clip_tool=""
    if command -v wl-copy >/dev/null 2>&1; then
        clip_tool="wl-copy (Wayland)"
    elif command -v xclip >/dev/null 2>&1; then
        clip_tool="xclip (X11)"
    elif command -v xsel >/dev/null 2>&1; then
        clip_tool="xsel (X11)"
    elif command -v pbcopy >/dev/null 2>&1; then
        clip_tool="pbcopy (macOS)"
    fi

    if [ -n "$clip_tool" ]; then
        printf "  ${OK} Clipboard Utility:    ${GREEN}%s${RESET}\n" "$clip_tool"
    else
        printf "  ${INFO} Clipboard Utility:    ${DIM}None found (install wl-clipboard or xclip for 1-click clipboard payload copy)${RESET}\n"
    fi

    # Terminal Pager Check
    if command -v less >/dev/null 2>&1; then
        printf "  ${OK} Terminal Pager:       ${GREEN}less (Available for in-TUI documentation & manual reading)${RESET}\n"
    else
        printf "  ${INFO} Terminal Pager:       ${DIM}less not found (fallback to standard terminal output)${RESET}\n"
    fi

    # Coredump Readiness Check
    echo
    printf "${BOLD}${WHITE}Linux Core Dump Configuration Audit:${RESET}\n"
    local ulimit_c
    ulimit_c="$(ulimit -c 2>/dev/null || echo "unknown")"
    if [ "$ulimit_c" = "unlimited" ]; then
        printf "  ${OK} Core Dump File Limit: ${GREEN}unlimited (Perfect for automatic crash offset detection)${RESET}\n"
    elif [ "$ulimit_c" = "0" ]; then
        printf "  ${WARN} Core Dump File Limit: ${YELLOW}0 (Core dumps disabled in current shell)${RESET}\n"
        printf "       ${DIM}Tip: Run 'ulimit -c unlimited' or add it to ~/.bashrc for seamless zero-config offset finding.${RESET}\n"
    else
        printf "  ${INFO} Core Dump File Limit: ${CYAN}%s blocks${RESET}\n" "$ulimit_c"
    fi

    if [ -f /proc/sys/fs/suid_dumpable ]; then
        local suid_d
        suid_d="$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo "1")"
        if [ "$suid_d" = "1" ] || [ "$suid_d" = "2" ]; then
            printf "  ${OK} SUID Dumpable:        ${GREEN}Enabled (%s)${RESET}\n" "$suid_d"
        else
            printf "  ${WARN} SUID Dumpable:        ${YELLOW}Disabled (fs.suid_dumpable=0)${RESET}\n"
            printf "       ${DIM}Tip: Set with 'sudo sysctl -w fs.suid_dumpable=1' if binaries don't generate dumps.${RESET}\n"
        fi
    fi

    if [ -f /proc/sys/kernel/core_pattern ]; then
        local pattern
        pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")"
        printf "  ${INFO} Core Pattern:         ${CYAN}%s${RESET}\n" "$pattern"
        if echo "$pattern" | grep -qi "systemd-coredump"; then
            printf "       ${DIM}systemd-coredump detected: Ret2Win interacts natively with coredumpctl and GDB fallbacks.${RESET}\n"
        elif echo "$pattern" | grep -qi "apport"; then
            printf "       ${DIM}Ubuntu Apport detected: Ret2Win automatically searches Apport crash directories and invokes GDB fallback.${RESET}\n"
        fi
    fi

    echo
}

# Run check only if requested
if [ "$CHECK_ONLY" = true ]; then
    print_banner
    check_environment
    exit 0
fi

# ------------------------------------------------------------------------------
# Install System Dependencies via Package Manager
# ------------------------------------------------------------------------------
install_system_deps() {
    if [ "$SKIP_DEPS" = true ]; then
        printf "${INFO} Skipping system package dependencies as requested (--skip-deps).\n\n"
        return 0
    fi

    detect_os
    local need_sudo=false
    [ "$(id -u)" -ne 0 ] && need_sudo=true

    # Check if essential requirements are already satisfied
    local has_python=false
    local has_venv=false
    if [ -n "$PYTHON_CMD" ]; then
        has_python=true
        if "$PYTHON_CMD" -c "import venv" >/dev/null 2>&1; then
            has_venv=true
        fi
    fi

    local has_clipboard=false
    if command -v wl-copy >/dev/null 2>&1 || command -v xclip >/dev/null 2>&1 || command -v xsel >/dev/null 2>&1 || command -v pbcopy >/dev/null 2>&1; then
        has_clipboard=true
    fi

    local has_gdb=false
    if command -v gdb >/dev/null 2>&1; then
        has_gdb=true
    fi

    local pkg_list=()

    case "$PKG_MGR" in
        pacman)
            [ "$has_python" = false ] && pkg_list+=("python")
            [ "$has_venv" = false ] && pkg_list+=("python-virtualenv")
            [ "$has_gdb" = false ] && pkg_list+=("gdb")
            [ "$has_clipboard" = false ] && pkg_list+=("wl-clipboard")
            ;;
        apt)
            [ "$has_python" = false ] && pkg_list+=("python3" "python3-dev" "build-essential")
            [ "$has_venv" = false ] && pkg_list+=("python3-venv")
            [ "$has_gdb" = false ] && pkg_list+=("gdb")
            [ "$has_clipboard" = false ] && pkg_list+=("wl-clipboard" "xclip")
            ;;
        dnf)
            [ "$has_python" = false ] && pkg_list+=("python3" "gcc")
            [ "$has_venv" = false ] && pkg_list+=("python3-virtualenv")
            [ "$has_gdb" = false ] && pkg_list+=("gdb")
            [ "$has_clipboard" = false ] && pkg_list+=("wl-clipboard" "xclip")
            ;;
        zypper)
            [ "$has_python" = false ] && pkg_list+=("python3" "gcc")
            [ "$has_venv" = false ] && pkg_list+=("python3-virtualenv")
            [ "$has_gdb" = false ] && pkg_list+=("gdb")
            [ "$has_clipboard" = false ] && pkg_list+=("wl-clipboard" "xclip")
            ;;
        apk)
            [ "$has_python" = false ] && pkg_list+=("python3" "gcc" "musl-dev")
            [ "$has_venv" = false ] && pkg_list+=("py3-virtualenv")
            [ "$has_gdb" = false ] && pkg_list+=("gdb")
            ;;
        brew)
            [ "$has_gdb" = false ] && pkg_list+=("gdb")
            ;;
        *)
            return 0
            ;;
    esac

    if [ ${#pkg_list[@]} -gt 0 ]; then
        printf "${INFO} Recommended system packages missing: ${YELLOW}%s${RESET}\n" "${pkg_list[*]}"
        
        # In non-interactive mode, check if passwordless sudo is available
        if [ "$need_sudo" = true ] && [ "$AUTO_CONFIRM" = true ]; then
            if ! sudo -n true 2>/dev/null; then
                printf "${WARN} Non-interactive mode: sudo requires password authentication. Skipping system package install.\n\n"
                return 0
            fi
        fi

        if ask_prompt "Would you like to install these prerequisite system packages now?" "Y"; then
            local SUDO=""
            if [ "$need_sudo" = true ]; then
                if command -v sudo >/dev/null 2>&1; then
                    SUDO="sudo"
                elif command -v doas >/dev/null 2>&1; then
                    SUDO="doas"
                fi
            fi

            printf "${INFO} Installing system dependencies via %s...\n" "$PKG_MGR"
            case "$PKG_MGR" in
                pacman)
                    $SUDO pacman -Sy --noconfirm --needed "${pkg_list[@]}"
                    ;;
                apt)
                    $SUDO apt-get update -qq
                    $SUDO apt-get install -y "${pkg_list[@]}"
                    ;;
                dnf)
                    $SUDO dnf install -y "${pkg_list[@]}"
                    ;;
                zypper)
                    $SUDO zypper --non-interactive install "${pkg_list[@]}"
                    ;;
                apk)
                    $SUDO apk add --no-cache "${pkg_list[@]}"
                    ;;
                brew)
                    brew install "${pkg_list[@]}"
                    ;;
            esac
            printf "${OK} System packages installed successfully.\n\n"
        else
            printf "${WARN} Skipping system package installation. Proceeding with user environment.\n\n"
        fi
    else
        printf "${OK} All essential system prerequisites are verified.\n\n"
    fi
}

# ------------------------------------------------------------------------------
# Install Ret2Win Application
# ------------------------------------------------------------------------------
install_application() {
    print_banner
    check_environment
    install_system_deps

    printf "${BOLD}${WHITE}Installing Ret2Win Toolkit...${RESET}\n"

    # Determine Python 3 binary
    local python_bin=""
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
                python_bin="$(command -v "$cmd")"
                break
            fi
        fi
    done

    if [ -z "$python_bin" ]; then
        printf "${FAIL} Python 3.8 or newer is required to install Ret2Win.\n"
        exit 1
    fi

    # Pipx Installation Path
    if [ "$USE_PIPX" = true ]; then
        if command -v pipx >/dev/null 2>&1; then
            printf "${INFO} Installing Ret2Win using pipx...\n"
            pipx install "${SCRIPT_DIR}" --force
            printf "${OK} Successfully installed via pipx!\n"
            verify_and_finish
            return 0
        else
            printf "${WARN} pipx not found on system. Falling back to isolated virtualenv installation.\n"
        fi
    fi

    # Create target directories
    mkdir -p "${BIN_DIR}"
    if [ "$DEV_LINK" = true ]; then
        printf "${INFO} Development link mode enabled. Ret2Win will run directly from: ${WHITE}%s${RESET}\n" "$SCRIPT_DIR"
        INSTALL_DIR="$SCRIPT_DIR"
    else
        mkdir -p "${INSTALL_DIR}"
        printf "${INFO} Deploying package files to: ${WHITE}%s${RESET}\n" "$INSTALL_DIR"
        cp -u "${SCRIPT_DIR}/ret2win.py" "${INSTALL_DIR}/"
        cp -u "${SCRIPT_DIR}/core.py" "${INSTALL_DIR}/"
        cp -u "${SCRIPT_DIR}/tui.py" "${INSTALL_DIR}/"
        cp -u "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/" 2>/dev/null || true
        cp -u "${SCRIPT_DIR}/pyproject.toml" "${INSTALL_DIR}/" 2>/dev/null || true
        cp -u "${SCRIPT_DIR}/LICENSE" "${INSTALL_DIR}/" 2>/dev/null || true
        cp -u "${SCRIPT_DIR}/README.md" "${INSTALL_DIR}/" 2>/dev/null || true
    fi

    # Create virtual environment (with system site-packages inheritance to reuse pre-installed distro packages)
    local venv_path="${INSTALL_DIR}/venv"
    if [ ! -d "$venv_path" ]; then
        printf "${INFO} Creating isolated Python virtual environment at: ${WHITE}%s${RESET}\n" "$venv_path"
        "$python_bin" -m venv --system-site-packages "$venv_path"
    else
        printf "${OK} Existing virtual environment detected at: ${WHITE}%s${RESET}\n" "$venv_path"
    fi

    local venv_python="${venv_path}/bin/python3"
    local venv_pip="${venv_path}/bin/pip"

    if [ ! -f "$venv_python" ]; then
        printf "${FAIL} Virtual environment creation failed: %s not found.\n" "$venv_python"
        exit 1
    fi

    # Check if pwntools and rich are already functional inside the virtual environment
    if "$venv_python" -c "import pwn, rich" >/dev/null 2>&1; then
        printf "${OK} Required Python packages (pwntools, rich) are already satisfied.\n"
    else
        printf "${INFO} Installing required Python packages (pwntools, rich) inside isolated venv...\n"
        "$venv_pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
        "$venv_pip" install --upgrade "pwntools>=4.11.0" "rich>=13.0.0"
    fi

    # Create Launcher Executable Wrapper Script
    local launcher_path="${BIN_DIR}/${APP_NAME}"
    printf "${INFO} Generating executable launcher at: ${WHITE}%s${RESET}\n" "$launcher_path"

    cat << EOF > "$launcher_path"
#!/usr/bin/env bash
# Ret2Win Executable Launcher Wrapper
# Generated automatically by install.sh (v${VERSION})
# Target runtime: ${venv_python}
set -e

APP_ROOT="${INSTALL_DIR}"
PYTHON_EXEC="${venv_python}"
ENTRYPOINT="\${APP_ROOT}/ret2win.py"

if [ ! -f "\$ENTRYPOINT" ]; then
    printf "\033[1;31m[!] Error: Ret2Win entrypoint not found at %s\033[0m\n" "\$ENTRYPOINT" >&2
    exit 1
fi

exec "\$PYTHON_EXEC" "\$ENTRYPOINT" "\$@"
EOF

    chmod +x "$launcher_path"
    printf "${OK} Executable wrapper created and made executable: %s\n\n" "$launcher_path"

    verify_and_finish
}

# ------------------------------------------------------------------------------
# Verification & PATH Instructions
# ------------------------------------------------------------------------------
verify_and_finish() {
    local launcher_path="${BIN_DIR}/${APP_NAME}"
    printf "${BOLD}${WHITE}Installation Verification:${RESET}\n"

    if [ -x "$launcher_path" ]; then
        local version_output
        version_output="$("$launcher_path" --version 2>/dev/null || echo "")"
        if echo "$version_output" | grep -qi "ret2win"; then
            printf "  ${OK} Functional test:    ${GREEN}PASSED (%s)${RESET}\n" "$version_output"
        else
            printf "  ${WARN} Functional test:    ${YELLOW}Executable responded, but version string was unexpected: '%s'${RESET}\n" "$version_output"
        fi
    else
        printf "  ${FAIL} Functional test:    ${RED}Launcher %s is not executable.${RESET}\n" "$launcher_path"
    fi

    # Check if BIN_DIR is in $PATH
    echo
    local in_path=false
    IFS=':' read -ra PATH_DIRS <<< "$PATH"
    for dir in "${PATH_DIRS[@]}"; do
        if [ "$dir" = "$BIN_DIR" ]; then
            in_path=true
            break
        fi
    done

    if [ "$in_path" = false ]; then
        printf "${WARN} ${BOLD}%s is not in your current PATH!${RESET}\n" "$BIN_DIR"
        printf "     To execute '${APP_NAME}' directly from any terminal, add this to your shell config:\n\n"
        if [ -n "$ZSH_VERSION" ] || [ -f "${HOME}/.zshrc" ]; then
            printf "     ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc${RESET}\n" "$BIN_DIR"
            printf "     ${CYAN}source ~/.zshrc${RESET}\n\n"
        elif [ -f "${HOME}/.config/fish/config.fish" ]; then
            printf "     ${CYAN}fish_add_path %s${RESET}\n\n" "$BIN_DIR"
        else
            printf "     ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc${RESET}\n" "$BIN_DIR"
            printf "     ${CYAN}source ~/.bashrc${RESET}\n\n"
        fi
    else
        printf "  ${OK} PATH validation:    ${GREEN}%s is correctly in your PATH!${RESET}\n" "$BIN_DIR"
    fi

    # Core dump recommendation
    printf "\n${STAR} ${BOLD}${WHITE}CTF Pro-Tip for Instant Zero-Guesswork Crashes:${RESET}\n"
    printf "  Enable unlimited core dumps in your current terminal or shell RC file:\n"
    printf "  ${CYAN}ulimit -c unlimited${RESET}\n"
    printf "  This allows Ret2Win to instantly detect the exact buffer overflow offset via native core dumps!\n"

    printf "\n${GREEN}${BOLD}✔ Ret2Win v%s installation complete!${RESET}\n" "$VERSION"
    printf "${BOLD}Launch the interactive TUI anywhere:${RESET}   ${CYAN}ret2win${RESET}\n"
    printf "${BOLD}Or run headless via CLI:${RESET}               ${CYAN}ret2win --binary ./vuln --win-addr win --run${RESET}\n\n"
}

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
install_application
