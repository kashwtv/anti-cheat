# AntiCheat

**Antivirus _for_ gamers, not against them.**

A full-featured, context-aware antivirus designed for users who download cheat
software. Cheats use the same techniques as malware (DLL injection, memory
manipulation, packers, hooked Win32 APIs), so traditional AV flags them as
threats. AntiCheat is different — it tells a benign cheat targeting a game
process apart from real malware targeting browsers, wallets, or system
services. When something _is_ malicious — token stealers, miners, RATs,
droppers bundled inside cheat loaders — it catches it with high confidence.

> **AntiCheat is NOT an anti-cheat.** It does not report you, talk to game
> publishers, or interfere with cheats. It protects you from the malware that
> hides inside them.

---

## Download

| Platform | File | Notes |
|----------|------|-------|
| **Windows** | [`anticheat.exe`](../../tree/releases/v0.1.0) | Portable CLI — no installer needed |
| **Windows** | [`anticheat-service.exe`](../../tree/releases/v0.1.0) | Real-time background protection |
| **Linux** | Build from source (see below) | `cargo build --release` |

Switch to the **`releases`** branch on this repo to download the Windows `.exe` files directly.

---

## Features

### Scanner Engine
- **SHA-256 / MD5 / SHA-1 / TLSH** file hashing
- **PE parser** — sections, imports, exports, overlay detection, digital signature check (via `goblin`)
- **YARA-style pattern matching** — 13 built-in rule files covering stealers, RATs, miners, keyloggers, droppers, C2 indicators, packers, persistence, Discord exfil, token stealers, Lua malware, script downloaders, and cheat tools
- **Heuristic analysis** — classifies suspicious imports by category (process injection, crypto, networking, persistence, anti-debug)
- **Archive scanning** — ZIP and nested archive support
- **Network indicator extraction** — URLs, IPs, domains, Discord webhooks
- **5-tier threat classification** with confidence scores:
  - `CLEAN` — safe file
  - `CHEAT DETECTED` — game cheat, intentionally not flagged as malicious
  - `SUSPICIOUS` — some red flags but inconclusive
  - `LIKELY MALICIOUS` — high confidence this is harmful
  - `MALICIOUS` — confirmed malware (hash match or overwhelming heuristics)
- **Cheat-vs-malware classifier** — injection into a game process vs. a system/browser process
- **AES-256-GCM encrypted quarantine vault** — isolated threat storage with restore/delete
- **59-game database** + system process database
- **User whitelist** — trust files, import/export JSON whitelist, per-file trust management
- **False positive reduction** — context-aware scoring reduces FPs on game mods and tools

### Script Shield
- **Lua script parser** for the `loadstring + HttpGet` cheat-loader pattern used by Roblox exploits and similar
- **URL extraction** from obfuscated scripts, base64-encoded strings, and concatenated variables
- **Lua deobfuscator** — detects and partially unpacks Luraph, Ironbrew, Moonsec, and Prometheus obfuscation
- **Safe HTTP fetcher** that **never executes** downloaded content
- **Recursive download-chain resolver** — follows redirect chains and multi-stage loaders
- **Built-in domain reputation database** with TLD risk scoring, IP-as-host detection, shortener detection, CDN abuse patterns, and path-entropy analysis
- **Behavior detection** — classifies scripts as stealers, droppers, persistence installers, miners, keyloggers, cheat loaders, cheat injectors, or backdoors
- **API call classification** — maps Lua/Roblox API calls to risk categories

### Real-Time Protection Service
- **File-system watcher** — auto-scans new/modified files in watched directories
- **Process monitor** — detects new processes, flags those launched from suspicious locations (temp, AppData, Downloads)
- **Clipboard monitor** — detects crypto address hijacking (clipboard replacement attacks)
- **Scheduled scans** — configurable quick / full / idle scan schedules
- **Game-mode detection** — pauses background scans while a known game is running (reads `/proc` on Linux, extensible for Windows)
- **Network monitor** — watches for suspicious outbound connections
- **Threat notifications** — wired from file watcher to notify on detection
- **IPC server** — Unix-socket JSON-line protocol for CLI/GUI control (`status`, `scan`, `pause`, `resume`, `shutdown`)

### Anti-Cheat Compatibility (NEW)
Real game anti-cheats (EAC, BattlEye, Vanguard, etc.) treat any process that
opens handles into games, hooks graphics, or scans game memory as a cheat.
AntiCheat detects these and enters **safe mode** automatically:

| Anti-Cheat | Mode | What AntiCheat Does |
|---|---|---|
| Easy Anti-Cheat | user-mode | Pauses real-time scans on game folders |
| BattlEye | user-mode | Pauses real-time scans on game folders |
| Riot Vanguard | **kernel** | Full safe mode — on-demand only, no process handles |
| Ricochet (CoD) | **kernel** | Full safe mode — on-demand only, no process handles |
| miHoYo AC (Genshin/HSR) | **kernel** | Full safe mode — on-demand only, no process handles |
| XIGNCODE3 | **kernel** | Full safe mode — on-demand only, no process handles |
| FACEIT AC | **kernel** | Full safe mode — on-demand only, no process handles |
| ESEA | user-mode | Regular guardrails |
| PunkBuster | user-mode | Regular guardrails |
| VAC (Valve) | user-mode | Regular guardrails |
| Denuvo | user-mode | Regular guardrails |

In safe mode AntiCheat **never** opens a process handle into a game, **never**
loads a driver, and **never** reads memory of guarded processes. Downloads,
Discord attachments, and cheat loaders are still scanned freely.

Per-path policy decisions: `Allow` / `OnDemandOnly` / `Refuse` — the real-time watcher checks every filesystem event against the compat layer before touching it.

### Tune — PC Performance Optimizer (NEW)
Full PC tuning to maximize gaming performance. 10 categories:

| Category | What it does | Impact |
|---|---|---|
| Power Plan | Switch to Ultimate Performance | High |
| Game Mode | Enable Windows Game Mode | Medium |
| Startup Programs | Disable bloat (Cortana, Adobe updater, vendor assistants) | Medium |
| Background Services | Stop DiagTrack, dmwappushservice, WSearch | Medium |
| Visual Effects | Disable animations, translucency, shadows | Low |
| Memory Compression | Disable on 16GB+ systems (costs CPU, no benefit) | Low |
| Network Stack | Disable Nagle's algorithm, enable TCP_NODELAY | High |
| SSD Trim | Reclaim stale blocks on all SSDs | Low |
| Temp Files | Clear user temp dir (files older than 7 days) | Low |
| GPU Scheduling | Enable Hardware-Accelerated GPU Scheduling (HAGS) | Medium |

Two modes:
- `--plan` — inspect and report only, nothing changed
- `--apply` — execute the safe subset (temp clean on all platforms; registry/service tweaks on Windows with elevation)

Every suggestion includes a revert hint so you can undo it.

### Deep Clean — Reclaimable Storage Scanner (NEW)
CCleaner-style garbage finder and cleaner. Scans for:

| Category | Examples |
|---|---|
| Browser cache | Chrome, Chromium, Firefox, Edge (all platforms) |
| System temp | OS temp directory |
| User temp | `%TEMP%` / `/tmp` |
| Thumbnail cache | Windows Explorer / Nautilus thumbnails |
| Crash dumps | System crash dumps |
| Event logs | Windows event logs |
| Package cache | apt, dnf, winget download caches |
| Discord cache | Discord asset cache |
| Steam download cache | Steam appcache |
| Game shader cache | Mesa, Nvidia GL shader cache |
| Old installers | Leftover installer files |

Safety:
- Never touches `.ssh`, `.gnupg`, wallet, seed, save, savegame, credentials, or password files
- Never touches anti-cheat guarded directories
- Only deletes files older than 1 hour by default
- `--system-wide` required to touch anything outside HOME
- Dry run by default — must pass `--sweep` to actually delete

### Desktop GUI
- **Tauri v2** desktop application
- **Animated particle grid** background with mouse-repulsion physics
- **Glassmorphism** cards with backdrop-filter blur
- **Gradient glow** buttons with animated box-shadow halos
- **SVG protection ring** with linear gradient stroke and filter glow
- **Animated number counters** with ease-out cubic interpolation
- **Sidebar** with pulsing shield icon and live status indicator
- Dashboard with stat cards, quick actions, and AC compat status
- Scan view with drag-and-drop zone and concentric ring animations
- Tune view with score bar, impact tags, and apply status
- Deep Clean view with per-category size chips and selectable targets
- Script Shield analyzer with risk verdict badges
- Anti-cheat compatibility view with kernel/user-mode indicators
- Quarantine vault view
- Toast notification system
- Smooth page transitions, custom scrollbar, Inter + JetBrains Mono fonts
- No framework bloat — vanilla HTML/CSS/JS

### Cross-Compilation & Releases
- **`scripts/package-windows.sh`** — builds a portable Windows `.exe` from Linux using either `cargo-xwin` (LLVM, recommended) or `mingw-w64` (GCC). Produces a zip with `anticheat.exe`, `anticheat-service.exe`, signatures, and install notes.
- **`.cargo/config.toml`** — pre-configured linker for `x86_64-pc-windows-gnu` target
- **`.github/workflows/release.yml`** — full CI/CD release pipeline:
  - Linux-to-Windows CLI cross-compile job (cargo-xwin)
  - Windows-native Tauri GUI installer job (real Windows runner, MSI + NSIS)
  - Linux-native CLI + service job
  - Automatic GitHub Release with all artifacts on `v*` tag push
  - Manual trigger via `workflow_dispatch`
- **`releases` branch** — contains pre-built Windows `.exe` files for direct download

---

## Architecture

```
anti-cheat/
├── engine/                     Core scanning library (Rust)
│   ├── scanner/
│   │   ├── hash_scan.rs            SHA-256, MD5, SHA-1, TLSH hashing
│   │   ├── pe_analyzer.rs          PE parser (sections, imports, exports, overlay)
│   │   ├── yara_scan.rs            YARA-style pattern matching engine
│   │   ├── heuristics.rs           Heuristic import/string analysis
│   │   ├── archive_scan.rs         ZIP/archive scanning
│   │   └── network_scan.rs         URL/IP/domain extraction
│   ├── detection/
│   │   ├── confidence.rs           Multi-factor confidence scoring
│   │   ├── classifier.rs           Cheat-vs-malware classification
│   │   ├── threat_level.rs         5-tier threat levels
│   │   └── false_positive.rs       FP reduction logic
│   ├── database/
│   │   ├── game_db.rs              59-game process database
│   │   ├── hash_db.rs              Known malware hash database
│   │   ├── whitelist.rs            User trust / whitelist management
│   │   └── reputation.rs           Source reputation scoring
│   ├── quarantine/
│   │   ├── manager.rs              Quarantine lifecycle management
│   │   └── vault.rs                AES-256-GCM encrypted storage
│   ├── script_shield/
│   │   ├── parser/                 Lua parser, deobfuscator, URL extractor
│   │   ├── fetcher/                Safe HTTP fetcher, chain resolver, redirect tracker
│   │   ├── analyzer/               Script analysis, behavior detection, API classification
│   │   ├── reputation/             Domain DB, URL risk scoring
│   │   └── report.rs               Structured report output
│   ├── updater/
│   │   ├── signature_update.rs     Signature database updates
│   │   ├── delta_update.rs         Delta/incremental updates
│   │   └── self_update.rs          Application self-update
│   ├── anticheat_compat.rs         Game AC detection + safe-mode policy
│   ├── tune.rs                     PC performance tuning (10 categories)
│   ├── clean.rs                    Deep clean scanner + sweep
│   └── signatures/rules/           13 YARA rule files
│       ├── stealers.yar
│       ├── rats.yar
│       ├── miners.yar
│       ├── keyloggers.yar
│       ├── droppers.yar
│       ├── c2_indicators.yar
│       ├── packers.yar
│       ├── persistence.yar
│       ├── discord_exfil.yar
│       ├── token_stealers.yar
│       ├── lua_malware.yar
│       ├── script_downloaders.yar
│       └── cheat_tools.yar
├── cli/                        anticheat CLI
├── service/                    anticheat-service real-time daemon
│   ├── watcher.rs                  Filesystem watcher
│   ├── process_monitor.rs          Process monitor
│   ├── clipboard_monitor.rs        Clipboard hijack detection
│   ├── network_monitor.rs          Network monitor
│   ├── scheduler.rs                Scheduled scan manager
│   ├── game_mode.rs                Game-mode detector
│   ├── notifications.rs            Threat notifications
│   └── ipc.rs                      Unix-socket IPC server
├── ui/                         Tauri v2 desktop GUI
│   ├── dist/                       Frontend (HTML/CSS/JS)
│   └── src-tauri/                  Rust backend (Tauri commands)
├── scripts/
│   └── package-windows.sh          Cross-compile to Windows .exe
├── .cargo/config.toml              Linker config for mingw cross-compile
└── .github/workflows/
    └── release.yml                 CI/CD release pipeline
```

---

## CLI Usage

```bash
# ── Scanning ──
anticheat scan ~/Downloads                # full recursive scan
anticheat scan --quick suspicious.exe     # hash-only fast scan
anticheat scan --deep suspicious.exe      # deep heuristic scan
anticheat scan --system                   # full system scan
anticheat info suspicious.exe             # detailed file analysis

# ── Trust & Quarantine ──
anticheat trust ~/games/legit.exe         # add to whitelist
anticheat trust --folder ~/games/         # trust all files in folder
anticheat untrust <sha256>                # remove from whitelist
anticheat whitelist export                # export whitelist to JSON
anticheat whitelist import list.json      # import whitelist from JSON
anticheat quarantine list                 # view quarantined files
anticheat quarantine restore <id>         # restore a file
anticheat quarantine delete <id>          # permanently delete
anticheat quarantine clean                # remove entries >30 days old

# ── Signatures ──
anticheat update                          # update signature database
anticheat update --check                  # check for updates only
anticheat stats                           # show detection statistics

# ── Reports ──
anticheat report suspicious.exe --format json
anticheat report suspicious.exe --format html

# ── Script Shield ──
anticheat script analyze loader.lua       # analyze Lua cheat script
anticheat script analyze loader.lua --follow  # also fetch referenced URLs
anticheat script fetch https://example.com/payload.lua  # safe URL fetch

# ── Tune (NEW) ──
anticheat tune --plan                     # show performance recommendations
anticheat tune --apply                    # apply the safe subset of tweaks

# ── Deep Clean (NEW) ──
anticheat clean --scan                    # find reclaimable garbage (dry run)
anticheat clean --sweep                   # delete selected targets in HOME
anticheat clean --sweep --system-wide     # also delete outside HOME

# ── Anti-Cheat Compatibility (NEW) ──
anticheat compat                          # show which game ACs are running
```

## Real-Time Protection Service

```bash
anticheat-service                         # run in foreground
RUST_LOG=info anticheat-service           # verbose logging
```

The service runs all background monitors (filesystem, process, clipboard, network, scheduler, game-mode) and exposes a JSON-line IPC socket at `$XDG_RUNTIME_DIR/anticheat-service.sock` (Linux/macOS) or `\\.\pipe\anticheat-service` (Windows).

## Desktop GUI

```bash
cd ui && cargo tauri dev                  # development mode
cd ui && cargo tauri build                # production build
```

## Building from Source

### Prerequisites
- Rust 1.70+ (install via [rustup.rs](https://rustup.rs))
- For the desktop GUI: Tauri v2 prerequisites (WebView2 on Windows, webkit2gtk on Linux)

### Native build (Linux / macOS / Windows)

```bash
# CLI + service
cargo build --release

# Desktop GUI
cd ui && cargo tauri build
```

Outputs:
- `target/release/anticheat` (CLI)
- `target/release/anticheat-service` (service)

### Cross-compile to Windows `.exe` from Linux

```bash
# Option 1: mingw-w64 (easier setup)
sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p anticheat-cli
# or use the script:
scripts/package-windows.sh mingw

# Option 2: cargo-xwin (LLVM, no wine needed, cleaner output)
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc
scripts/package-windows.sh xwin
```

Output: `dist/AntiCheat-windows-x64-<version>.zip` containing portable `anticheat.exe` + `anticheat-service.exe`, signatures, and a README.

> The Tauri desktop GUI is not cross-compiled — WebView2 bindings require a real Windows environment. The GitHub Actions workflow builds the GUI installer on a Windows runner automatically.

### Running tests

```bash
cargo test --workspace
```

---

## Why does this exist?

When a player downloads a cheat from a forum or Discord server, the cheat
itself is usually a legitimate game-modification tool. Unfortunately, the
same channels are heavily used to distribute malware bundled with — or
disguised as — cheats: Discord token stealers, browser cookie grabbers,
crypto-clippers, RATs, and miners.

Mainstream AV either:
1. Flags every cheat as malicious → users disable AV entirely → unprotected
2. Misses the bundled malware → users get pwned

AntiCheat fills that gap. It understands game cheats, doesn't flag them, but catches the malware hiding inside them.

---

## License

MIT
