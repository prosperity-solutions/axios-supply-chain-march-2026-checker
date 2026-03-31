#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# axios supply-chain checker — OS dispatcher
#
# Detects the operating system and runs the appropriate checker script.
# Supports macOS and Linux.
#
# Usage (remote):
#   bash <(curl -fsSL -H 'Cache-Control: no-cache' URL/check.sh)
#
# Usage (local):
#   ./check.sh [options]
# ──────────────────────────────────────────────────────────────────────────────

RED='\033[1;31m'
BOLD='\033[1m'
RESET='\033[0m'

REPO_BASE="https://raw.githubusercontent.com/prosperity-solutions/axios-supply-chain-march-2026-checker/main"

bail() {
  echo ""
  echo ""
  echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}║   ⚠️  THIS CHECK COULD NOT BE COMPLETED ON YOUR SYSTEM ⚠️             ║${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}║   $1$(printf '%*s' $((67 - ${#1})) '')║${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}║   👉 Please reach out to your security team lead IMMEDIATELY.         ║${RESET}"
  echo -e "${RED}${BOLD}║      They will help you run the check manually.                       ║${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  exit 1
}

os="$(uname -s)"

case "$os" in
  Darwin)
    script="check-macos.sh"
    ;;
  Linux)
    script="check-linux.sh"
    ;;
  *)
    bail "Your OS (${os}) is not supported by the automated checker."
    ;;
esac

# Determine how to run: local file (sibling script) or remote download
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${script_dir}/${script}" ]; then
  # Local: run the sibling script directly
  exec bash "${script_dir}/${script}" "$@"
else
  # Remote: download to temp file and verify before executing
  if ! command -v curl &>/dev/null; then
    bail "curl is required but not found."
    exit 1
  fi

  local_tmp=$(mktemp "${TMPDIR:-/tmp}/axios-check.XXXXXX") || bail "Failed to create temp file."
  trap 'rm -f "$local_tmp"' EXIT

  if ! curl -fsSL -H 'Cache-Control: no-cache' "${REPO_BASE}/${script}" -o "$local_tmp" 2>/dev/null; then
    bail "Failed to download ${script}. Check your internet."
  fi

  if [ ! -s "$local_tmp" ]; then
    bail "Downloaded script is empty. Check your internet."
  fi

  exec bash "$local_tmp" "$@"
fi
