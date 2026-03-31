# axios Supply Chain Attack Checker (March 2026)

In March 2026 the npm package `axios` was compromised via a maintainer account hijack. Two malicious versions (`axios@1.14.1` and `axios@0.30.4`) were published that install a hidden dependency (`plain-crypto-js`) which deploys a **Remote Access Trojan (RAT)** on your machine. The dropper self-deletes after execution.

This script checks your system and your node/npm projects for indicators of compromise. It runs interactively, guides you through scanning your working directories, and gives a clear pass/fail verdict at the end.

Full write-up: [aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat](https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat)

## Who can use this script?

| | Supported |
|---|---|
| **macOS** (Intel & Apple Silicon) | Yes |
| **Windows** | No |
| **Linux** | No |

This script is **macOS only**. It relies on macOS-specific paths (e.g. `/Library/Caches`), tools (`osascript`, `lsof`), and persistence locations (`LaunchAgents`/`LaunchDaemons`).

If you're on **Windows or Linux** and need to check your system, reach out to Peter via Slack huddle — he'll help you run the check manually.

## Run the checker

Open Terminal and paste:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/prosperity-solutions/axios-supply-chain-march-2026-checker/main/check.sh)
```

The script will:
1. Run all system-level checks automatically
2. Present a menu to scan your projects — the recommended option (press Enter) auto-discovers all git repos and node projects in your home directory
3. After each scan, ask if you want to scan additional directories
4. Show a list of all projects it checked so you can verify nothing was missed
5. Display a clear final verdict

## Details

### What happened?

| Package | Version | Status |
|---------|---------|--------|
| `axios` | `1.14.1` | Compromised |
| `axios` | `0.30.4` | Compromised |
| `plain-crypto-js` | `4.2.1` | Malicious dependency injected by the compromised axios versions |

The compromised versions introduced `plain-crypto-js` as a dependency, which executed a postinstall script (`setup.js`) that deployed a cross-platform RAT. The dropper self-deleted after execution to hide evidence.

**Safe versions:** axios `1.14.0` or earlier, `0.30.3` or earlier.

### Known indicators of compromise (IOCs)

- **macOS RAT binary:** `/Library/Caches/com.apple.act.mond`
- **Linux dropper:** `/tmp/ld.py`
- **Malicious package:** `node_modules/plain-crypto-js`
- **C2 domain:** `sfrclak.com`
- **C2 IP:** `142.11.206.73`
- **C2 endpoint:** `http://sfrclak.com:8000/6202033` (script checks domain/IP, not the full URL)
- **Known bad SHA-1 sums:**
  - axios@1.14.1: `2553649f2322049666871cea80a5d0d6adc700ca`
  - axios@0.30.4: `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`
  - plain-crypto-js@4.2.1: `07d889e2dadce6f3910dcbc253317d28ca61c766`

### What the script checks

**System-level (always runs)**
- RAT binary at `/Library/Caches/com.apple.act.mond` (system + user level)
- Linux dropper at `/tmp/ld.py` (for mixed environments)
- LaunchDaemons and LaunchAgents for persistence (including binary plists via `plutil`)
- Running `com.apple.act.mond` process
- DNS resolution of C2 domain (`sfrclak.com`)
- Active network connections to C2 IP/domain via `lsof`

**Package manager caches**
- npm cache (file paths + content-addressable index + tarball SHA verification)
- Yarn v1 cache, Yarn Berry cache
- pnpm content-addressable store
- Bun install cache

**Global installs**
- All nvm-managed Node versions (not just the active one)
- Volta and fnm global installs
- Fallback: current `npm prefix` global modules

**Per-project**
- `node_modules/plain-crypto-js` directory (including symlinks)
- Installed `axios` version (flags `1.14.1` and `0.30.4`)
- Dropper script remnants (`setup.js`)
- Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`) — format-aware checks for all package managers
- All git worktrees automatically included
- Monorepo sub-projects discovered and listed

### Output

At the end the script shows:

1. A list of all node/npm project directories it checked — split into regular projects and those in hidden/internal directories — so you can verify all your working directories were covered
2. A clear verdict:
   - **✅ NOT INFECTED** — no indicators of compromise found
   - **🚨 POTENTIALLY INFECTED** — reach out to Peter immediately

If the script can't run on your system (missing tools, wrong OS), it shows a prominent banner asking you to reach out to Peter via Slack huddle for manual help.

### Alternative usage

```bash
# Scan a specific git repo (including all worktrees)
./check.sh /path/to/your/repo

# System, cache, and global install checks only (no per-project scan)
./check.sh --system

# Show help
./check.sh --help
```

### No third-party dependencies

This script uses **only tools that ship with macOS** — it does not download, install, or depend on anything external:

| Tool | What it's used for | Ships with macOS |
|---|---|---|
| `bash` | Script runtime | Yes |
| `find` | Discover project directories | Yes |
| `grep` | Search lockfiles and caches for IOCs | Yes |
| `shasum` | Verify tarball hashes against known-bad SHA-1s | Yes |
| `lsof` | Check for active C2 network connections | Yes |
| `pgrep` | Check for running RAT process and GUI session detection | Yes |
| `dig` | DNS resolution check for C2 domain | Yes |
| `plutil` | Convert binary plists to XML for LaunchAgent/Daemon scanning | Yes |
| `osascript` | macOS Finder folder picker (interactive mode) | Yes |
| `xcode-select` | Detect whether git is a real install or an Xcode CLT stub | Yes |
| `git` | Worktree discovery | Yes (via Xcode CLT) |
| `npm` | Locate cache directory and global prefix | Needs Node.js install |
| `pnpm` | Locate pnpm store (optional, falls back to default path) | Only if installed |

If `git`, `npm`, or `pnpm` are not installed, the script warns and skips those specific checks — it never fails silently and never installs anything.

## License

MIT
