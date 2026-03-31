# axios Supply Chain Attack Checker (March 2026)

In March 2026 the npm package `axios` was compromised via a maintainer account hijack. Two malicious versions (`axios@1.14.1` and `axios@0.30.4`) were published that install a hidden dependency (`plain-crypto-js`) which deploys a **Remote Access Trojan (RAT)** on your machine. The dropper self-deletes after execution.

These scripts check your system and your node/npm projects for indicators of compromise. They run interactively, guide you through scanning your working directories, and give a clear pass/fail verdict at the end.

Full write-up: [aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat](https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat)

## Who can use this?

| | Supported |
|---|---|
| **macOS** (Intel & Apple Silicon) | Yes |
| **Linux** (Ubuntu, Debian, Fedora, etc.) | Yes |
| **Windows** | No |

The script automatically detects your OS and runs the appropriate checker (`check-macos.sh` or `check-linux.sh`).

If you're on **Windows** and need to check your system, reach out to your security team lead — they'll help you run the check manually.

## Run the checker

Open Terminal and paste:

```bash
bash <(curl -fsSL -H 'Cache-Control: no-cache' https://raw.githubusercontent.com/prosperity-solutions/axios-supply-chain-march-2026-checker/main/check.sh)
```

The script will:
1. Detect your OS and run the right checker
2. Run all system-level checks automatically
3. Present a menu to scan your projects — the recommended option (press Enter) auto-discovers all git repos and node projects in your home directory
4. After each scan, ask if you want to scan additional directories
5. Show a list of all projects it checked so you can verify nothing was missed
6. Display a clear final verdict

You can also pass flags via the one-liner:

```bash
# Scan a specific directory of repos via curl
bash <(curl -fsSL -H 'Cache-Control: no-cache' https://raw.githubusercontent.com/prosperity-solutions/axios-supply-chain-march-2026-checker/main/check.sh) --scan /path/to/repos
```

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

- **macOS RAT binary:** `/Library/Caches/com.apple.act.mond` (system + user level)
- **Linux dropper:** `/tmp/ld.py`
- **Windows artefacts:** `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
- **Malicious package:** `node_modules/plain-crypto-js`
- **C2 domain:** `sfrclak.com`
- **C2 IP:** `142.11.206.73`
- **C2 endpoint:** `http://sfrclak.com:8000/6202033` (script checks domain/IP, not the full URL)
- **Known bad SHA-1 sums:**
  - axios@1.14.1: `2553649f2322049666871cea80a5d0d6adc700ca`
  - axios@0.30.4: `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`
  - plain-crypto-js@4.2.1: `07d889e2dadce6f3910dcbc253317d28ca61c766`

### What the scripts check

**System-level (always runs)**

| Check | macOS | Linux |
|---|---|---|
| RAT artefacts | `/Library/Caches/com.apple.act.mond` (system + user), `/tmp/ld.py` | `/tmp/ld.py`, `/tmp/com.apple.act.mond` (shared FS) |
| Persistence | LaunchDaemons/LaunchAgents (binary plists via `plutil`) | systemd services, cron jobs, shell rc files (`.bashrc`, `.profile`, `.zshrc`) |
| Running processes | `com.apple.act.mond` | `ld.py`, `sfrclak` |
| DNS | C2 domain via `dig` | C2 domain via `dig` or `nslookup` |
| Network connections | `lsof -i` | `ss -tnp` (no root needed), fallback to `lsof` |

**Package manager caches (both OS)**
- npm cache (file paths + content-addressable index + tarball SHA verification)
- Yarn v1 cache, Yarn Berry cache
- pnpm content-addressable store
- Bun install cache

**Global installs (both OS)**
- All nvm-managed Node versions (not just the active one)
- Volta and fnm global installs
- Fallback: current `npm prefix` global modules

**Per-project (both OS)**
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
   - **🚨 POTENTIALLY INFECTED** — reach out to your security team lead immediately

If the script can't run on your system (missing tools, unsupported OS), it shows a prominent banner asking you to reach out to your security team lead for manual help.

### Scanning a directory of repos

If you have a directory containing multiple cloned repos (e.g. you pulled all repos you have access to), use `--scan` to discover and check all of them at once:

```bash
./check.sh --scan /path/to/directory-of-repos
```

This automatically finds all git repositories and node projects inside that directory, scans each one, and shows a progress counter (`[3/47]`) as it goes.

### Other options

```bash
# Scan a single git repo (including all its worktrees)
./check.sh /path/to/your/repo

# System, cache, and global install checks only (no per-project scan)
./check.sh --system

# Show help
./check.sh --help
```

### No third-party dependencies

These scripts use **only tools that ship with your OS** — they do not download, install, or depend on anything external.

**macOS** (`check-macos.sh`): `bash`, `find`, `grep`, `shasum`, `lsof`, `pgrep`, `dig`, `plutil`, `osascript`, `xcode-select`, `git`, `npm`/`pnpm` (if installed)

**Linux** (`check-linux.sh`): `bash`, `find`, `grep`, `sha1sum`, `ss` (fallback: `lsof`), `pgrep`, `dig`/`nslookup`, `crontab`, `git`, `npm`/`pnpm` (if installed)

If a tool is not installed, the script warns and skips that specific check — it never fails silently and never installs anything.

### Architecture

```
check.sh           <- OS dispatcher (detects macOS/Linux, runs the right script)
check-macos.sh     <- macOS-specific checker
check-linux.sh     <- Linux-specific checker
```

When run via `curl | bash`, the dispatcher downloads the OS-specific script from GitHub. When run locally, it finds the sibling script in the same directory.

## License

MIT
