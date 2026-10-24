#!/usr/bin/env bash
# ==============================================================================
#  Ret2Win - PyPI Build & Publish Automation Script
#  Author: Casper (Vishal-07-R)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ANSI Colors
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"

OK="${GREEN}[✔]${RESET}"
WARN="${YELLOW}[⚠]${RESET}"
INFO="${CYAN}[ℹ]${RESET}"
FAIL="${RED}[✖]${RESET}"

ACTION="build"
if [ "$1" = "--upload" ] || [ "$1" = "-u" ]; then
    ACTION="upload"
elif [ "$1" = "--test" ] || [ "$1" = "-t" ]; then
    ACTION="test-upload"
elif [ "$1" = "--clean" ]; then
    ACTION="clean"
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat << EOF
Usage: ./build.sh [OPTIONS]

Options:
  (no args)       Build sdist and wheel packages and run metadata validation
  --upload, -u    Build, validate, and publish package to official PyPI
  --test, -t      Build, validate, and publish package to TestPyPI
  --clean         Clean all build artifacts (dist/, build/, *.egg-info/)
  -h, --help      Show this help menu
EOF
    exit 0
fi

# ------------------------------------------------------------------------------
# Clean Function
# ------------------------------------------------------------------------------
clean_artifacts() {
    printf "${INFO} Cleaning previous build artifacts...\n"
    rm -rf build/ dist/ *.egg-info/
    printf "${OK} Clean complete.\n"
}

if [ "$ACTION" = "clean" ]; then
    clean_artifacts
    exit 0
fi

# ------------------------------------------------------------------------------
# Build Environment Resolution
# ------------------------------------------------------------------------------
BUILD_PYTHON=""
TWINE_CMD=""

if command -v python3 >/dev/null 2>&1 && python3 -c "import build, twine" >/dev/null 2>&1; then
    BUILD_PYTHON="python3"
    TWINE_CMD="twine"
elif [ -f "/tmp/pypi_build_env/bin/python3" ]; then
    BUILD_PYTHON="/tmp/pypi_build_env/bin/python3"
    TWINE_CMD="/tmp/pypi_build_env/bin/twine"
elif [ -f "${SCRIPT_DIR}/.venv-build/bin/python3" ]; then
    BUILD_PYTHON="${SCRIPT_DIR}/.venv-build/bin/python3"
    TWINE_CMD="${SCRIPT_DIR}/.venv-build/bin/twine"
else
    printf "${INFO} Setting up isolated build environment with 'build' and 'twine'...\n"
    python3 -m venv "${SCRIPT_DIR}/.venv-build"
    "${SCRIPT_DIR}/.venv-build/bin/pip" install --upgrade pip build twine >/dev/null 2>&1
    BUILD_PYTHON="${SCRIPT_DIR}/.venv-build/bin/python3"
    TWINE_CMD="${SCRIPT_DIR}/.venv-build/bin/twine"
fi

# ------------------------------------------------------------------------------
# Build Execution
# ------------------------------------------------------------------------------
clean_artifacts

printf "\n${BOLD}${CYAN}Building Ret2Win distributions (sdist & wheel)...${RESET}\n"
"$BUILD_PYTHON" -m build

printf "\n${BOLD}${CYAN}Validating distribution metadata with Twine...${RESET}\n"
"$TWINE_CMD" check dist/*

printf "\n${OK} ${GREEN}${BOLD}Build completed successfully!${RESET}\n"
printf "${BOLD}Generated Artifacts in dist/:${RESET}\n"
ls -lh dist/

# ------------------------------------------------------------------------------
# Upload Handling
# ------------------------------------------------------------------------------
if [ "$ACTION" = "test-upload" ]; then
    printf "\n${INFO} Uploading to ${YELLOW}TestPyPI${RESET} (https://test.pypi.org/)...\n"
    printf "${DIM}Username: __token__\nPassword: <your-test-pypi-api-token>${RESET}\n\n"
    "$TWINE_CMD" upload --repository testpypi dist/*
    printf "\n${OK} TestPyPI upload finished!\n"
    printf "Test install with: ${CYAN}pip install --index-url https://test.pypi.org/simple/ --no-deps ret2win${RESET}\n"
elif [ "$ACTION" = "upload" ]; then
    printf "\n${INFO} Uploading to ${GREEN}Production PyPI${RESET} (https://pypi.org/)...\n"
    printf "${DIM}Username: __token__\nPassword: <your-pypi-api-token>${RESET}\n\n"
    "$TWINE_CMD" upload dist/*
    printf "\n${OK} ${GREEN}${BOLD}Successfully published to PyPI!${RESET}\n"
    printf "Install anywhere via: ${CYAN}pip install ret2win${RESET}\n"
else
    printf "\n${INFO} Next step: To upload to PyPI, run:\n"
    printf "  ${CYAN}./build.sh --upload${RESET}   # for Official PyPI\n"
    printf "  ${CYAN}./build.sh --test${RESET}     # for TestPyPI sandbox\n\n"
fi
