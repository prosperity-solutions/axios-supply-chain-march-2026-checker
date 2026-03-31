#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# axios supply-chain checker (macOS)
#
# Checks for indicators of compromise from the March 2026 axios npm
# supply-chain attack (axios@1.14.1 / axios@0.30.4 / plain-crypto-js@4.2.1).
#
# Reference: https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat
#
# Usage:
#   ./check.sh              – guided mode (system check + mandatory project scan)
#   ./check.sh /path/to/repo – scan a specific git repo (+ all worktrees)
#   ./check.sh --system     – full-system scan only (no repo)
# ──────────────────────────────────────────────────────────────────────────────

# ── colours & symbols ─────────────────────────────────────────────────────────
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

TICK="${GREEN}✔${RESET}"
CROSS="${RED}✘${RESET}"
WARN="${YELLOW}⚠${RESET}"
INFO="${BLUE}ℹ${RESET}"

# ── state ─────────────────────────────────────────────────────────────────────
FOUND_ISSUES=0
SCANNED_DIRS=0
SCANNED_LOCKFILES=0
CHECKED_PROJECT_DIRS=()
GIT_AVAILABLE=1

# ── known bad SHA-1 sums (from npm registry) ─────────────────────────────────
BAD_SHA_AXIOS_1141="2553649f2322049666871cea80a5d0d6adc700ca"
BAD_SHA_AXIOS_0304="d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71"
BAD_SHA_PLAIN_CRYPTO="07d889e2dadce6f3910dcbc253317d28ca61c766"

# ── safety escape — unrecoverable failure ─────────────────────────────────────
bail() {
  echo ""
  echo ""
  echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}║   ⚠️  THIS CHECK COULD NOT BE COMPLETED ON YOUR SYSTEM ⚠️             ║${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}║   Reason: $1$(printf '%*s' $((52 - ${#1})) '')║${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}║   👉 Please reach out to Peter IMMEDIATELY via Slack huddle.          ║${RESET}"
  echo -e "${RED}${BOLD}║      He will help you run the check manually.                         ║${RESET}"
  echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
  echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  exit 1
}

# ── helpers ───────────────────────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  axios supply-chain attack checker (March 2026)${RESET}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${DIM}  Reference: aikido.dev/blog/axios-npm-compromised${RESET}"
  echo -e "${DIM}  Compromised: axios@1.14.1 · axios@0.30.4 · plain-crypto-js@4.2.1${RESET}"
  echo ""
}

section() {
  echo ""
  echo -e "${BOLD}── $1 ──${RESET}"
}

trace() {
  echo -e "  ${DIM}$1${RESET}"
}

found() {
  echo -e "  ${CROSS} ${RED}$1${RESET}"
  FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

ok() {
  echo -e "  ${TICK} $1"
}

info() {
  echo -e "  ${INFO} $1"
}

warn() {
  echo -e "  ${WARN} ${YELLOW}$1${RESET}"
}

plural() {
  local count="$1" singular="$2" plural_form="$3"
  if [ "$count" -eq 1 ]; then echo "$singular"; else echo "$plural_form"; fi
}

# ── preflight: verify required tools ──────────────────────────────────────────
preflight() {
  section "Preflight checks"

  # Raise file descriptor limit — macOS defaults to 256 which is too low
  # for deep directory scans with many process substitutions
  ulimit -n 10240 2>/dev/null || ulimit -n 4096 2>/dev/null || true

  # Hard requirements
  if [[ "$(uname)" != "Darwin" ]]; then
    bail "This script requires macOS"
  fi
  ok "Running on macOS ($(sw_vers -productVersion 2>/dev/null || echo 'unknown version'))"

  if ! command -v bash &>/dev/null; then
    bail "bash not found"
  fi
  ok "bash $(bash --version | head -1 | sed 's/.*version //' | sed 's/(.*//')"

  # Soft requirements — warn but continue
  local missing_tools=()
  for cmd in git npm shasum pgrep lsof; do
    if command -v "$cmd" &>/dev/null; then
      # Special case: macOS git shim triggers a modal dialog if Xcode CLT
      # is not installed. Detect this and treat git as unavailable.
      if [ "$cmd" = "git" ] && ! xcode-select -p &>/dev/null; then
        GIT_AVAILABLE=0
        missing_tools+=("$cmd")
        warn "git is a stub (Xcode Command Line Tools not installed) — git features will be skipped"
        continue
      fi
      trace "$cmd found: $(command -v "$cmd")"
    else
      missing_tools+=("$cmd")
      warn "$cmd not found — some checks will be skipped"
    fi
  done

  if [ ${#missing_tools[@]} -gt 3 ]; then
    bail "Too many missing tools (${missing_tools[*]})"
  fi
}

# ── system-level checks (RAT artefacts, network, processes) ──────────────────
check_system() {
  section "System-level checks (RAT artefacts)"

  # macOS RAT binary — system level
  trace "Checking /Library/Caches/com.apple.act.mond ..."
  if [ -f "/Library/Caches/com.apple.act.mond" ]; then
    found "RAT binary found: /Library/Caches/com.apple.act.mond"
  elif [ ! -r "/Library/Caches" ]; then
    warn "Cannot read /Library/Caches (permission denied) — run with sudo for full check"
  else
    ok "No RAT binary at /Library/Caches/com.apple.act.mond"
  fi

  # macOS RAT binary — user level
  trace "Checking ~/Library/Caches/com.apple.act.mond ..."
  if [ -f "$HOME/Library/Caches/com.apple.act.mond" ]; then
    found "RAT binary found: $HOME/Library/Caches/com.apple.act.mond"
  else
    ok "No RAT binary at ~/Library/Caches/com.apple.act.mond"
  fi

  # Linux artefact (in case running in a mixed env)
  trace "Checking /tmp/ld.py ..."
  if [ -f "/tmp/ld.py" ]; then
    found "Suspicious dropper found: /tmp/ld.py"
  else
    ok "No dropper at /tmp/ld.py"
  fi

  section "LaunchDaemon / LaunchAgent persistence check"

  local launch_dirs=(
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
    "$HOME/Library/LaunchAgents"
  )
  for ld in "${launch_dirs[@]}"; do
    trace "Scanning ${ld} ..."
    if [ -d "$ld" ] && [ -r "$ld" ]; then
      local hits=""
      # Convert each plist to XML first (handles binary plists with UTF-16 strings)
      while IFS= read -r plist; do
        [ -z "$plist" ] && continue
        if plutil -convert xml1 -o - "$plist" 2>/dev/null | grep -q "com.apple.act.mond\|sfrclak\|142\.11\.206\.73"; then
          hits="${hits}${plist} "
        fi
      done < <(find "$ld" -name "*.plist" 2>/dev/null || true)
      if [ -n "$hits" ]; then
        found "Suspicious LaunchAgent/Daemon referencing IOC: ${hits}"
      else
        ok "No suspicious entries in ${ld}"
      fi
    elif [ -d "$ld" ]; then
      warn "Cannot read ${ld} (permission denied)"
    else
      trace "${ld} does not exist — skipping"
    fi
  done

  section "Process checks"

  if command -v pgrep &>/dev/null; then
    trace "Looking for running com.apple.act.mond process ..."
    if pgrep -f "com.apple.act.mond" > /dev/null 2>&1; then
      found "Process 'com.apple.act.mond' is RUNNING"
    else
      ok "No com.apple.act.mond process running"
    fi
  else
    warn "pgrep not available — skipping process check"
  fi

  section "Network / DNS checks"

  # DNS check — use dig with timeout (more reliable than nslookup on macOS)
  trace "Checking if C2 domain sfrclak.com resolves ..."
  if command -v dig &>/dev/null; then
    local dig_result
    dig_result=$(dig +short +time=3 +tries=1 sfrclak.com 2>/dev/null || true)
    if [ -n "$dig_result" ]; then
      warn "DNS resolution for sfrclak.com succeeded (${dig_result}) — C2 may still be active"
    else
      ok "C2 domain sfrclak.com does not resolve"
    fi
  else
    trace "dig not available — skipping DNS check"
  fi

  # Active connections
  trace "Checking for connections to C2 IP 142.11.206.73 ..."
  if command -v lsof &>/dev/null; then
    if lsof -i 2>/dev/null | grep -qi "142.11.206.73\|sfrclak"; then
      found "Active connection to C2 infrastructure detected via lsof!"
    else
      ok "No active connections to C2 infrastructure (current user)"
    fi
    trace "(Note: run with sudo for system-wide connection check)"
  else
    warn "lsof not available — skipping connection check"
  fi
}

# ── check a single node_modules directory ─────────────────────────────────────
check_node_modules() {
  local nm_dir="$1"
  SCANNED_DIRS=$((SCANNED_DIRS + 1))

  trace "Scanning: ${nm_dir}"

  # 1. Check for plain-crypto-js (the actual malware package)
  if [ -d "${nm_dir}/plain-crypto-js" ] || [ -L "${nm_dir}/plain-crypto-js" ]; then
    found "MALICIOUS package 'plain-crypto-js' found in ${nm_dir}/plain-crypto-js"
    if [ -f "${nm_dir}/plain-crypto-js/package.json" ]; then
      local ver
      ver=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${nm_dir}/plain-crypto-js/package.json" 2>/dev/null | head -1 || true)
      [ -n "$ver" ] && found "  plain-crypto-js ${ver}"
    fi
  else
    # Show a readable label for the node_modules path
    local nm_label
    # For nvm/volta/fnm paths, show the node version
    if [[ "$nm_dir" == *"/.nvm/versions/node/"* ]]; then
      nm_label="nvm $(echo "$nm_dir" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')"
    elif [[ "$nm_dir" == *"/.volta/"* ]]; then
      nm_label="volta globals"
    elif [[ "$nm_dir" == *"/fnm/"* ]]; then
      nm_label="fnm globals"
    else
      # For project dirs, show the project folder name
      local project_dir
      project_dir=$(echo "$nm_dir" | sed 's|/node_modules$||')
      nm_label=$(basename "$project_dir")
    fi
    ok "No plain-crypto-js in ${nm_label}"
  fi

  # 2. Check axios version if present
  if [ -d "${nm_dir}/axios" ] || [ -L "${nm_dir}/axios" ]; then
    local axios_pkg="${nm_dir}/axios/package.json"
    if [ -f "$axios_pkg" ]; then
      local axios_ver
      axios_ver=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$axios_pkg" 2>/dev/null | sed 's/.*"\([^"]*\)"/\1/' | head -1 || true)
      if [ "$axios_ver" = "1.14.1" ] || [ "$axios_ver" = "0.30.4" ]; then
        found "Compromised axios@${axios_ver} installed in ${nm_dir}/axios"
        # Check if axios itself has plain-crypto-js as dependency
        if grep -q "plain-crypto-js" "$axios_pkg" 2>/dev/null; then
          found "  axios package.json references plain-crypto-js!"
        fi
      elif [ -n "$axios_ver" ]; then
        ok "axios@${axios_ver} (safe)"
      fi
    fi
  fi

  # 3. Check for setup.js dropper remnants in plain-crypto-js
  if [ -f "${nm_dir}/plain-crypto-js/setup.js" ]; then
    found "Dropper script found: ${nm_dir}/plain-crypto-js/setup.js"
  fi
}

# ── check lockfiles for compromised versions ─────────────────────────────────
check_lockfile() {
  local lockfile="$1"
  local basename
  basename=$(basename "$lockfile")

  # Skip binary lockfiles
  if [ "$basename" = "bun.lockb" ]; then
    trace "Skipping binary lockfile: ${lockfile}"
    return
  fi

  SCANNED_LOCKFILES=$((SCANNED_LOCKFILES + 1))
  trace "Scanning lockfile: ${lockfile}"

  # Check for plain-crypto-js in lockfile (universal — works for all formats)
  if grep -q "plain-crypto-js" "$lockfile" 2>/dev/null; then
    found "Lockfile references 'plain-crypto-js': ${lockfile}"
  fi

  # Check for known bad SHAs (universal)
  if grep -q "$BAD_SHA_AXIOS_1141" "$lockfile" 2>/dev/null; then
    found "Lockfile contains SHA for compromised axios@1.14.1: ${lockfile}"
  fi
  if grep -q "$BAD_SHA_AXIOS_0304" "$lockfile" 2>/dev/null; then
    found "Lockfile contains SHA for compromised axios@0.30.4: ${lockfile}"
  fi
  if grep -q "$BAD_SHA_PLAIN_CRYPTO" "$lockfile" 2>/dev/null; then
    found "Lockfile contains SHA for malicious plain-crypto-js@4.2.1: ${lockfile}"
  fi

  # Format-specific version checks
  case "$basename" in
    package-lock.json)
      # package-lock.json: "axios" and "version" are on separate lines
      if grep -A5 '"axios"' "$lockfile" 2>/dev/null | grep -qE '"version"[[:space:]]*:[[:space:]]*"(1\.14\.1|0\.30\.4)"'; then
        found "Lockfile pins compromised axios version: ${lockfile}"
      fi
      ;;
    yarn.lock)
      # Yarn v1: version "1.14.1"  /  Yarn Berry: version: 1.14.1
      if grep -A3 'axios@' "$lockfile" 2>/dev/null | grep -qE 'version:? "?(1\.14\.1|0\.30\.4)"?'; then
        found "Lockfile (yarn) pins compromised axios version: ${lockfile}"
      fi
      ;;
    pnpm-lock.yaml)
      # pnpm v6: /axios/1.14.1  /  pnpm v7+: /axios@1.14.1 or axios@1.14.1
      if grep -qE "axios[@/](1\.14\.1|0\.30\.4)" "$lockfile" 2>/dev/null; then
        found "Lockfile (pnpm) pins compromised axios version: ${lockfile}"
      fi
      ;;
    bun.lock)
      if grep -qE '"axios".*"(1\.14\.1|0\.30\.4)"' "$lockfile" 2>/dev/null; then
        found "Lockfile (bun) pins compromised axios version: ${lockfile}"
      fi
      ;;
  esac
}

# ── record a project directory for the summary ───────────────────────────────
record_project_dir() {
  local dir="$1"
  # Check if directory contains a package.json (it's a node project)
  if [ -f "${dir}/package.json" ]; then
    local name
    name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "${dir}/package.json" 2>/dev/null | sed 's/.*"\([^"]*\)"/\1/' | head -1 || true)
    if [ -n "$name" ]; then
      CHECKED_PROJECT_DIRS+=("${dir} (${name})")
    else
      CHECKED_PROJECT_DIRS+=("${dir} (unnamed)")
    fi
  fi
}

# ── scan a directory tree for node_modules and lockfiles ──────────────────────
scan_directory() {
  local dir="$1"
  local label="$2"

  section "Scanning: ${label}"
  trace "Path: ${dir}"

  if [ ! -d "$dir" ]; then
    warn "Directory does not exist: ${dir}"
    return
  fi

  # Record the top-level project
  record_project_dir "$dir"

  # Find all node_modules directories (including symlinks)
  local nm_count=0
  while IFS= read -r nm_dir; do
    [ -z "$nm_dir" ] && continue
    check_node_modules "$nm_dir"
    nm_count=$((nm_count + 1))
  done < <(find "$dir" \( -type d -o -type l \) -name "node_modules" -not -path "*/node_modules/*/node_modules" 2>/dev/null || true)

  if [ "$nm_count" -eq 0 ]; then
    info "No node_modules directories found in ${label}"
  else
    trace "Scanned ${nm_count} node_modules $(plural "$nm_count" "directory" "directories")"
  fi

  # Find all lockfiles (skip binary bun.lockb, skip inside node_modules)
  local lock_count=0
  while IFS= read -r lockfile; do
    [ -z "$lockfile" ] && continue
    check_lockfile "$lockfile"
    lock_count=$((lock_count + 1))
  done < <(find "$dir" \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "bun.lock" \) -not -path "*/node_modules/*" 2>/dev/null || true)

  if [ "$lock_count" -eq 0 ]; then
    info "No lockfiles found in ${label}"
  else
    trace "Scanned ${lock_count} $(plural "$lock_count" "lockfile" "lockfiles")"
  fi

  # Also record sub-projects (monorepos with workspaces)
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    record_project_dir "$(dirname "$pkg")"
  done < <(find "$dir" -maxdepth 4 -name "package.json" -not -path "*/node_modules/*" 2>/dev/null || true)
}

# ── scan a git repo + all its worktrees ───────────────────────────────────────
scan_git_repo() {
  local repo_dir="$1"

  if [ "$GIT_AVAILABLE" -eq 0 ] || ! command -v git &>/dev/null; then
    scan_directory "$repo_dir" "$repo_dir"
    return
  fi

  # Resolve to the repo root
  local git_root
  git_root=$(git -C "$repo_dir" rev-parse --show-toplevel 2>/dev/null || true)
  if [ -z "$git_root" ]; then
    warn "${repo_dir} is not a git repository — scanning as plain directory"
    scan_directory "$repo_dir" "$repo_dir"
    return
  fi

  section "Git repository detected"
  trace "Root: ${git_root}"

  # Scan the main worktree
  scan_directory "$git_root" "main worktree (${git_root})"

  # Discover and scan all additional worktrees using --porcelain for safe parsing
  trace "Discovering git worktrees ..."
  local wt_count=0
  while IFS= read -r wt_path; do
    [ -z "$wt_path" ] && continue
    # Strip "worktree " prefix
    wt_path="${wt_path#worktree }"
    # Skip the main worktree (already scanned)
    if [ "$wt_path" = "$git_root" ]; then
      continue
    fi
    if [ -d "$wt_path" ]; then
      wt_count=$((wt_count + 1))
      scan_directory "$wt_path" "worktree #${wt_count} (${wt_path})"
    fi
  done < <(git -C "$git_root" worktree list --porcelain 2>/dev/null | grep "^worktree " || true)

  if [ "$wt_count" -eq 0 ]; then
    info "No additional worktrees found"
  else
    trace "Scanned ${wt_count} additional $(plural "$wt_count" "worktree" "worktrees")"
  fi
}

# ── npm cache check ──────────────────────────────────────────────────────────
check_npm_cache() {
  section "npm cache check"

  if ! command -v npm &>/dev/null; then
    warn "npm not installed — skipping npm cache check"
    return
  fi

  local npm_cache
  npm_cache=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")
  trace "npm cache location: ${npm_cache}"

  if [ -d "$npm_cache" ]; then
    trace "Searching npm cache for plain-crypto-js ..."
    local cache_hit=0

    # Check file/directory names
    if find "$npm_cache" -path "*plain-crypto-js*" -print -quit 2>/dev/null | grep -q .; then
      found "plain-crypto-js found in npm cache (file path match)"
      cache_hit=1
    fi

    # Also check content-addressable index for the package name
    if [ -d "$npm_cache/_cacache/index-v5" ]; then
      if grep -rl "plain-crypto-js" "$npm_cache/_cacache/index-v5/" 2>/dev/null | head -1 | grep -q .; then
        found "plain-crypto-js found in npm cache index"
        cache_hit=1
      fi
    fi

    if [ "$cache_hit" -eq 0 ]; then
      ok "No plain-crypto-js in npm cache"
    fi

    trace "Searching npm cache for compromised axios tarballs ..."
    if command -v shasum &>/dev/null; then
      local found_bad_tarball=0
      while IFS= read -r tarball; do
        [ -z "$tarball" ] && continue
        local sha
        sha=$(shasum "$tarball" 2>/dev/null | awk '{print $1}' || true)
        if [ "$sha" = "$BAD_SHA_AXIOS_1141" ] || [ "$sha" = "$BAD_SHA_AXIOS_0304" ]; then
          found "Compromised axios tarball in cache: ${tarball} (sha1: ${sha})"
          found_bad_tarball=1
        fi
      done < <(find "$npm_cache" -path "*axios*" -name "*.tgz" 2>/dev/null || true)

      if [ "$found_bad_tarball" -eq 0 ]; then
        ok "No compromised axios tarballs in npm cache"
      fi
    else
      warn "shasum not available — skipping tarball hash verification"
    fi
  else
    info "npm cache directory not found at ${npm_cache}"
  fi
}

# ── global node_modules check (all nvm versions, volta, fnm) ─────────────────
check_global_node_modules() {
  section "Global node_modules check"

  local checked_any=0

  # nvm — check ALL installed node versions, not just active one
  if [ -d "$HOME/.nvm/versions/node" ]; then
    trace "nvm detected — checking all installed Node versions ..."
    while IFS= read -r ver_nm; do
      [ -z "$ver_nm" ] && continue
      if [ -d "$ver_nm" ]; then
        local ver_label
        ver_label=$(echo "$ver_nm" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
        trace "nvm Node ${ver_label}:"
        check_node_modules "$ver_nm"
        checked_any=1
      fi
    done < <(find "$HOME/.nvm/versions/node" -maxdepth 2 -type d -name "node_modules" -path "*/lib/node_modules" 2>/dev/null || true)
  fi

  # volta
  if [ -d "$HOME/.volta" ]; then
    trace "Volta detected ..."
    local volta_nm="$HOME/.volta/tools/image/node"
    if [ -d "$volta_nm" ]; then
      while IFS= read -r ver_nm; do
        [ -z "$ver_nm" ] && continue
        if [ -d "$ver_nm" ]; then
          trace "Volta $(basename "$(dirname "$(dirname "$ver_nm")")"):"
          check_node_modules "$ver_nm"
          checked_any=1
        fi
      done < <(find "$volta_nm" -maxdepth 3 -type d -name "node_modules" -path "*/lib/node_modules" 2>/dev/null || true)
    fi
  fi

  # fnm
  if [ -d "$HOME/Library/Application Support/fnm" ]; then
    trace "fnm detected ..."
    while IFS= read -r ver_nm; do
      [ -z "$ver_nm" ] && continue
      if [ -d "$ver_nm" ]; then
        trace "fnm $(basename "$(dirname "$(dirname "$ver_nm")")"):"
        check_node_modules "$ver_nm"
        checked_any=1
      fi
    done < <(find "$HOME/Library/Application Support/fnm" -maxdepth 4 -type d -name "node_modules" -path "*/lib/node_modules" 2>/dev/null || true)
  fi

  # Fallback: use npm prefix for current version if nothing else found
  if [ "$checked_any" -eq 0 ] && command -v npm &>/dev/null; then
    local global_prefix
    global_prefix=$(npm config get prefix 2>/dev/null || echo "/usr/local")
    local global_nm="${global_prefix}/lib/node_modules"
    trace "Global node_modules: ${global_nm}"
    if [ -d "$global_nm" ]; then
      check_node_modules "$global_nm"
    else
      info "Global node_modules directory not found"
    fi
  fi
}

# ── yarn cache check ─────────────────────────────────────────────────────────
check_yarn_cache() {
  section "Yarn cache check"

  local found_cache=0

  # Yarn v1 cache
  local yarn_v1_cache="$HOME/Library/Caches/Yarn"
  if [ -d "$yarn_v1_cache" ]; then
    found_cache=1
    trace "Yarn v1 cache: ${yarn_v1_cache}"
    if find "$yarn_v1_cache" -path "*plain-crypto-js*" -print -quit 2>/dev/null | grep -q .; then
      found "plain-crypto-js found in Yarn v1 cache"
    else
      ok "No plain-crypto-js in Yarn v1 cache"
    fi
  fi

  # Yarn Berry cache
  local yarn_berry_cache="$HOME/.yarn/berry/cache"
  if [ -d "$yarn_berry_cache" ]; then
    found_cache=1
    trace "Yarn Berry cache: ${yarn_berry_cache}"
    if find "$yarn_berry_cache" -path "*plain-crypto-js*" -print -quit 2>/dev/null | grep -q .; then
      found "plain-crypto-js found in Yarn Berry cache"
    else
      ok "No plain-crypto-js in Yarn Berry cache"
    fi
  fi

  if [ "$found_cache" -eq 0 ]; then
    info "No Yarn cache directories found — skipping"
  fi
}

# ── pnpm store check ─────────────────────────────────────────────────────────
check_pnpm_store() {
  section "pnpm store check"

  local pnpm_store=""

  # Try to get store path from pnpm itself
  if command -v pnpm &>/dev/null; then
    pnpm_store=$(pnpm store path 2>/dev/null || true)
  fi

  # Fallback to common macOS location
  if [ -z "$pnpm_store" ] || [ ! -d "$pnpm_store" ]; then
    pnpm_store="$HOME/Library/pnpm/store"
  fi

  if [ -d "$pnpm_store" ]; then
    trace "pnpm store: ${pnpm_store}"
    if find "$pnpm_store" -path "*plain-crypto-js*" -print -quit 2>/dev/null | grep -q .; then
      found "plain-crypto-js found in pnpm store"
    else
      ok "No plain-crypto-js in pnpm store"
    fi
  else
    info "No pnpm store found — skipping"
  fi
}

# ── bun cache check ──────────────────────────────────────────────────────────
check_bun_cache() {
  section "Bun cache check"

  local bun_cache="$HOME/.bun/install/cache"
  if [ -d "$bun_cache" ]; then
    trace "Bun cache: ${bun_cache}"
    if find "$bun_cache" -path "*plain-crypto-js*" -print -quit 2>/dev/null | grep -q .; then
      found "plain-crypto-js found in Bun cache"
    else
      ok "No plain-crypto-js in Bun cache"
    fi
  else
    info "No Bun cache found — skipping"
  fi
}

# ── interactive directory picker via macOS Finder ─────────────────────────────
pick_directory() {
  # Check if we have a GUI session
  if ! pgrep -q "WindowServer" 2>/dev/null; then
    warn "No GUI session detected (SSH or headless?) — Finder picker unavailable"
    echo ""
    return
  fi

  local chosen
  chosen=$(osascript -e 'tell application "Finder"
    activate
    set chosenFolder to choose folder with prompt "Select a git repository to scan for the axios supply-chain compromise:"
    return POSIX path of chosenFolder
  end tell' 2>/dev/null || true)

  if [ -z "$chosen" ]; then
    echo ""
    return
  fi

  # Remove trailing slash
  echo "${chosen%/}"
}

# ── paths to exclude from project discovery ──────────────────────────────────
# ONLY package manager caches and system directories that this script already
# checks via dedicated functions. Everything else (even hidden dirs like .next,
# .cursor, etc.) is still scanned — it just shows up in the "Internal / hidden
# directories" group in the final listing.
DISCOVERY_EXCLUDE_PATTERNS=(
  "*/.bun/install/cache/*"
  "*/.npm/*"
  "*/.nvm/*"
  "*/.yarn/berry/cache/*"
  "*/Library/Caches/Yarn/*"
  "*/.pnpm-store/*"
  "*/Library/pnpm/*"
  "*/.volta/*"
  "*/.fnm/*"
  "*/.cache/*"
  "*/.Trash/*"
  "*/Library/Caches/*"
  "*/node_modules/*"
)

# ── auto-discover projects (git repos + standalone node projects) ─────────────
discover_projects() {
  local search_root="$1"
  local max_depth="${2:-8}"

  info "Discovering git repositories and node/npm projects under ${search_root} ..."
  trace "This can take a while depending on directory size (depth ${max_depth}) ..."

  # Build find exclusion arguments as a proper array (no eval, no glob expansion)
  local find_excludes=()
  for pattern in "${DISCOVERY_EXCLUDE_PATTERNS[@]}"; do
    if [ ${#find_excludes[@]} -gt 0 ]; then
      find_excludes+=("-o")
    fi
    find_excludes+=("-path" "$pattern")
  done

  # Pass 1: fast discovery — just collect paths
  trace "Pass 1/2: Finding projects ..."

  local git_roots=()
  while IFS= read -r git_dir; do
    [ -z "$git_dir" ] && continue
    git_roots+=("$(dirname "$git_dir")")
  done < <(find "$search_root" -maxdepth "$max_depth" \( "${find_excludes[@]}" \) -prune -o -type d -name ".git" -print 2>/dev/null | sort || true)

  local standalone_roots=()
  local scanned_roots=""
  # Mark all git roots as covered
  for root in "${git_roots[@]+"${git_roots[@]}"}"; do
    scanned_roots="${scanned_roots}|||${root}|||"
  done

  while IFS= read -r pkg_json; do
    [ -z "$pkg_json" ] && continue
    local project_dir
    project_dir=$(dirname "$pkg_json")

    # Skip if inside an already-covered git repo
    local already_covered=0
    local check_dir="$project_dir"
    while [ "$check_dir" != "/" ] && [ "$check_dir" != "$search_root" ]; do
      if [[ "$scanned_roots" == *"|||${check_dir}|||"* ]]; then
        already_covered=1
        break
      fi
      check_dir=$(dirname "$check_dir")
    done
    # Also check the search root itself
    if [ "$already_covered" -eq 0 ] && [[ "$scanned_roots" == *"|||${search_root}|||"* ]]; then
      already_covered=1
    fi

    if [ "$already_covered" -eq 0 ]; then
      scanned_roots="${scanned_roots}|||${project_dir}|||"
      standalone_roots+=("$project_dir")
    fi
  done < <(find "$search_root" -maxdepth "$max_depth" \( "${find_excludes[@]}" \) -prune -o -name "package.json" -print 2>/dev/null | sort || true)

  local git_count=${#git_roots[@]}
  local standalone_count=${#standalone_roots[@]}
  local total=$((git_count + standalone_count))

  if [ "$total" -eq 0 ]; then
    info "No git repositories or node projects found under ${search_root}"
    return
  fi

  info "Found ${git_count} git $(plural "$git_count" "repository" "repositories") and ${standalone_count} standalone node $(plural "$standalone_count" "project" "projects")"
  echo ""

  # Pass 2: scan each project with progress counter
  trace "Pass 2/2: Scanning projects ..."
  local current=0

  for repo_root in "${git_roots[@]+"${git_roots[@]}"}"; do
    current=$((current + 1))
    echo -e "  ${CYAN}[${current}/${total}]${RESET} ${repo_root}"
    scan_git_repo "$repo_root"
  done

  for project_dir in "${standalone_roots[@]+"${standalone_roots[@]}"}"; do
    current=$((current + 1))
    echo -e "  ${CYAN}[${current}/${total}]${RESET} ${project_dir}"
    scan_directory "$project_dir" "$project_dir"
  done
}

# ── print the summary of checked project directories ─────────────────────────
print_checked_projects() {
  echo ""
  echo -e "${BOLD}── Checked node/npm project directories ──${RESET}"

  if [ ${#CHECKED_PROJECT_DIRS[@]} -eq 0 ]; then
    echo ""
    echo -e "  ${DIM}(no node/npm projects found during scan)${RESET}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}👆 Please review the list above.${RESET}"
    echo -e "  ${YELLOW}Does it include ALL your node/npm working directories?${RESET}"
    echo -e "  ${YELLOW}If any are missing, re-run the script and scan those directories too.${RESET}"
    return
  fi

  # Deduplicate entries
  local unique_entries=()
  local seen=""
  for entry in "${CHECKED_PROJECT_DIRS[@]}"; do
    if [[ "$seen" != *"|||${entry}|||"* ]]; then
      seen="${seen}|||${entry}|||"
      unique_entries+=("$entry")
    fi
  done

  # Split into two groups:
  #   normal  = path has no hidden folder (no /. in the directory portion)
  #   hidden  = path contains a hidden folder somewhere (e.g. .nvm, .cache, ...)
  local normal_entries=()
  local hidden_entries=()
  for entry in "${unique_entries[@]}"; do
    # Extract the path (everything before the last " (")
    local entry_path
    entry_path="${entry% (*}"
    # Check if any path component (directory) starts with a dot
    if echo "$entry_path" | grep -qE '(^|/)\.[^/]+(/|$)'; then
      hidden_entries+=("$entry")
    else
      normal_entries+=("$entry")
    fi
  done

  # Sort each group alphabetically by path (entries start with the path)
  local sorted_normal=()
  local sorted_hidden=()
  if [ ${#normal_entries[@]} -gt 0 ]; then
    while IFS= read -r line; do
      sorted_normal+=("$line")
    done < <(printf '%s\n' "${normal_entries[@]}" | sort)
  fi
  if [ ${#hidden_entries[@]} -gt 0 ]; then
    while IFS= read -r line; do
      sorted_hidden+=("$line")
    done < <(printf '%s\n' "${hidden_entries[@]}" | sort)
  fi

  # Print normal group first
  local counter=0
  if [ ${#sorted_normal[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${BOLD}Project directories:${RESET}"
    echo ""
    for entry in "${sorted_normal[@]}"; do
      counter=$((counter + 1))
      # Split into path and name for coloring
      local p="${entry% (*}"
      local n="${entry##* (}"
      n="${n%)}"
      echo -e "  ${CYAN}${counter}.${RESET}  ${p}  ${DIM}(${n})${RESET}"
    done
  fi

  # Print hidden group second
  if [ ${#sorted_hidden[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${BOLD}Internal / hidden directories:${RESET}"
    echo -e "  ${DIM}(paths inside hidden folders like .nvm, .cache, etc.)${RESET}"
    echo ""
    for entry in "${sorted_hidden[@]}"; do
      counter=$((counter + 1))
      local p="${entry% (*}"
      local n="${entry##* (}"
      n="${n%)}"
      echo -e "  ${CYAN}${counter}.${RESET}  ${DIM}${p}  (${n})${RESET}"
    done
  fi

  echo ""
  echo -e "  ${DIM}Total: ${counter} $(plural "$counter" "project" "projects")${RESET}"
  echo ""
  echo -e "  ${YELLOW}${BOLD}👆 Please review the list above.${RESET}"
  echo -e "  ${YELLOW}Does it include ALL your node/npm working directories?${RESET}"
  echo -e "  ${YELLOW}If any are missing, re-run the script and scan those directories too.${RESET}"
}

# ── final verdict banners ────────────────────────────────────────────────────
print_verdict() {
  echo ""

  if [ "$SCANNED_DIRS" -gt 0 ] || [ "$SCANNED_LOCKFILES" -gt 0 ]; then
    echo -e "${DIM}  Scanned: ${SCANNED_DIRS} node_modules $(plural "$SCANNED_DIRS" "directory" "directories"), ${SCANNED_LOCKFILES} $(plural "$SCANNED_LOCKFILES" "lockfile" "lockfiles")${RESET}"
  fi

  echo ""
  echo ""

  if [ "$FOUND_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║                                                                       ║${RESET}"
    echo -e "${GREEN}${BOLD}║     ✅✅✅   NOT INFECTED   ✅✅✅                                   ║${RESET}"
    echo -e "${GREEN}${BOLD}║                                                                       ║${RESET}"
    echo -e "${GREEN}${BOLD}║     No indicators of compromise were found on this system.            ║${RESET}"
    echo -e "${GREEN}${BOLD}║                                                                       ║${RESET}"
    echo -e "${GREEN}${BOLD}║     Your system appears safe from the axios supply-chain attack.      ║${RESET}"
    echo -e "${GREEN}${BOLD}║                                                                       ║${RESET}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════════════╝${RESET}"
  else
    echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
    echo -e "${RED}${BOLD}║     🚨🚨🚨   POTENTIALLY INFECTED   🚨🚨🚨                          ║${RESET}"
    echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
    echo -e "${RED}${BOLD}║     Found ${FOUND_ISSUES} indicator(s) of compromise!                            ║${RESET}"
    echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
    echo -e "${RED}${BOLD}║     ⚠️  REACH OUT TO PETER IMMEDIATELY  ⚠️                             ║${RESET}"
    echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
    echo -e "${RED}${BOLD}║     📞 Slack huddle or direct message — do this NOW                   ║${RESET}"
    echo -e "${RED}${BOLD}║                                                                       ║${RESET}"
    echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}While you wait:${RESET}"
    echo -e "    ${RED}1.${RESET} Do NOT run 'npm install' or any node/npm commands"
    echo -e "    ${RED}2.${RESET} Disconnect from Wi-Fi if RAT artefacts were found"
    echo -e "    ${RED}3.${RESET} Do NOT delete any files — preserve evidence"
    echo -e "    ${RED}4.${RESET} Do NOT restart your machine"
  fi

  echo ""
}

# ── guided project scanning (mandatory in default mode) ──────────────────────
guided_project_scan() {
  # All reads use /dev/tty so the script works when piped via curl | bash
  if [ ! -e /dev/tty ]; then
    info "Non-interactive mode detected — defaulting to home directory scan"
    section "Auto-discovery: ${HOME}"
    discover_projects "$HOME" 8
    return
  fi

  local keep_scanning=1

  while [ "$keep_scanning" -eq 1 ]; do
    echo ""
    echo -e "${BOLD}How would you like to scan for affected node/npm projects?${RESET}"
    echo ""
    echo -e "  ${CYAN}1${RESET})  Auto-discover all repos in your home directory ${GREEN}(recommended)${RESET}"
    echo -e "     ${DIM}Scans ${HOME} for all git repos & node projects${RESET}"
    echo -e "  ${CYAN}2${RESET})  Auto-discover all repos under a custom directory"
    echo -e "  ${CYAN}3${RESET})  Pick a directory using Finder (opens file chooser)"
    echo -e "  ${CYAN}4${RESET})  Type a path to a specific project"
    echo ""
    echo -n "  Choose [1-4] (press Enter for 1): "
    read -r choice < /dev/tty

    # Default to 1 on empty input (just pressing Enter)
    choice="${choice:-1}"

    case "$choice" in
      1)
        section "Auto-discovery: ${HOME}"
        discover_projects "$HOME" 8
        ;;
      2)
        echo ""
        echo -n "  Enter path to search: "
        read -r custom_path < /dev/tty
        custom_path="${custom_path/#\~/$HOME}"
        if [ -d "$custom_path" ]; then
          section "Auto-discovery: ${custom_path}"
          discover_projects "$custom_path"
        else
          warn "Directory not found: ${custom_path}"
        fi
        ;;
      3)
        info "Opening Finder … select a repository folder."
        local target_dir
        target_dir=$(pick_directory)
        if [ -z "$target_dir" ]; then
          warn "No directory selected."
        else
          scan_git_repo "$target_dir"
        fi
        ;;
      4)
        echo ""
        echo -n "  Enter path to project: "
        read -r project_path < /dev/tty
        project_path="${project_path/#\~/$HOME}"
        if [ -d "$project_path" ]; then
          scan_git_repo "$project_path"
        else
          warn "Directory not found: ${project_path}"
        fi
        ;;
      *)
        warn "Invalid choice. Please pick 1, 2, 3, or 4."
        continue
        ;;
    esac

    echo ""
    echo -e "  ${BOLD}Would you like to scan another directory?${RESET}"
    echo -n "  [y/N]: "
    read -r again < /dev/tty
    case "$again" in
      [yY]|[yY][eE][sS]) keep_scanning=1 ;;
      *) keep_scanning=0 ;;
    esac
  done
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
  banner

  local mode=""
  local target_dir=""

  # Parse arguments
  if [ $# -ge 1 ]; then
    case "$1" in
      --system)
        mode="system-only"
        ;;
      --help|-h)
        echo "Usage:"
        echo "  ./check.sh              Guided mode (system check + mandatory project scan)"
        echo "  ./check.sh /path/to/repo Scan a specific git repo + worktrees"
        echo "  ./check.sh --system     Full-system scan only"
        echo ""
        exit 0
        ;;
      *)
        mode="repo"
        target_dir="$1"
        ;;
    esac
  else
    mode="guided"
  fi

  # ── preflight ──
  preflight

  # ── always run system-level checks ──
  check_system
  check_npm_cache
  check_yarn_cache
  check_pnpm_store
  check_bun_cache
  check_global_node_modules

  # ── repo-level checks based on mode ──
  case "$mode" in
    repo)
      scan_git_repo "$target_dir"
      ;;
    guided)
      echo ""
      echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
      echo -e "${BOLD}  System checks complete. Now let's scan your projects.${RESET}"
      echo -e "${BOLD}═══════════════════════════════════════════════════════════════${RESET}"
      guided_project_scan
      ;;
    system-only)
      info "System-level checks only — no repo scan."
      ;;
  esac

  # ── print all checked project dirs ──
  print_checked_projects

  # ── final verdict ──
  print_verdict

  # Exit with non-zero code if issues were found (useful for CI/automation)
  if [ "$FOUND_ISSUES" -gt 0 ]; then
    exit 1
  fi
}

main "$@"
