# AntiCheat

**AntiCheat is an antivirus _for_ gamers, not against them.**

It is a defensive security product designed for users who download cheat
software for video games. Cheats use the same techniques as malware (DLL
injection, memory manipulation, packers, hooked Win32 APIs), so traditional
antivirus engines flag them as malicious. AntiCheat is context-aware: it
distinguishes a benign cheat targeting a game process from real malware
targeting browsers, wallets, or system services. When something _is_
malicious — token stealers, miners, RATs, droppers bundled inside cheat
loaders — it catches it with high confidence.

> AntiCheat is **not** an anti-cheat. It does not report you, talk to game
> publishers, or interfere with cheats. It protects you from the malware that
> hides inside them.

## Why a separate antivirus for gamers?

When a player downloads a cheat from a forum or Discord server, the cheat
itself is usually a legitimate game-modification tool. Unfortunately, the
same channels are heavily used to distribute malware bundled with — or
disguised as — cheats: Discord token stealers, browser cookie grabbers,
crypto-clippers, RATs, and miners. Mainstream AV either flags every cheat
as malicious (forcing users to disable protection entirely) or fails to
detect the bundled malware. AntiCheat fills that gap.

## Highlights

- **Context-aware classification** — real stealers vs. harmless game-only cheats.
- **Script Shield** — unpacks Luraph / Ironbrew loaders, analyzes the payload chain, never executes it.
- **Real-time service** — filesystem, process, clipboard, and scheduled scans.
- **Anti-cheat compatibility** — detects EAC / BattlEye / Vanguard / Ricochet / FACEIT / miHoYo AC and enters a safe mode so your AV won't get you kernel-banned.
- **Tune** — CCleaner-grade PC tuning for competitive gaming (power plan, GPU scheduling, network stack, background services).
- **Deep Clean** — safe reclaimable-storage scanner (browser/shader/Discord caches, temp, package leftovers).
- **Desktop GUI** — Tauri v2 app with a polished, animated dashboard.
- **Cross-compile to Windows from Linux** — `scripts/package-windows.sh` plus a GitHub Actions release workflow.

## Architecture

```
anti-cheat/
├── engine/                 # Core scanning library (Rust)
│   ├── scanner/            Hash, PE, YARA, heuristic, archive, network scanners
│   ├── detection/          Confidence scoring, classification, threat levels
│   ├── database/           Game DB, hash DB, whitelist, source reputation
│   ├── quarantine/         AES-256-GCM encrypted vault
│   ├── script_shield/      Lua script parser, safe fetcher, payload analyzer
│   ├── updater/            Signature updates
│   ├── anticheat_compat.rs AC detection + safe-mode policy
│   ├── tune.rs             Performance-tune suggestions + safe apply
│   ├── clean.rs            Deep-clean scanner + sweep
│   └── signatures/         YARA rules
├── cli/                    # `anticheat` command-line interface
├── service/                # `anticheat-service` real-time daemon
├── ui/                     # Tauri v2 desktop GUI
├── scripts/
│   └── package-windows.sh  # Build a portable Windows .exe from Linux
└── .github/workflows/release.yml  # Full release pipeline
```

## Anti-cheat safety (so you don't get banned)

Being an antivirus that touches game processes would look, to EAC or Vanguard,
exactly like a cheat. AntiCheat's `anticheat_compat` module enumerates running
anti-cheat drivers and, when one is active, puts itself into **safe mode**:

| Anti-cheat                | Mode        | Safe-mode action                       |
| ------------------------- | ----------- | -------------------------------------- |
| Easy Anti-Cheat           | user-land   | pause real-time scans on game folders  |
| BattlEye                  | user-land   | pause real-time scans on game folders  |
| Riot Vanguard             | **kernel**  | full safe mode, on-demand only         |
| Ricochet (Call of Duty)   | **kernel**  | full safe mode, on-demand only         |
| miHoYo AC                 | **kernel**  | full safe mode, on-demand only         |
| XIGNCODE3                 | **kernel**  | full safe mode, on-demand only         |
| FACEIT AC                 | **kernel**  | full safe mode, on-demand only         |
| ESEA / PunkBuster / VAC   | user-land   | regular guardrails                     |

In safe mode AntiCheat **never** opens a process handle into a game, **never**
loads a driver, and **never** reads memory of guarded processes. Downloads,
Discord attachments, and cheat loaders are still scanned freely.

See it yourself:

```bash
anticheat compat
```

## Features

### Phase 1 - Scanner Engine
- SHA-256 / MD5 / SHA-1 / TLSH file hashing
- PE parser (sections, imports, exports, overlay, signature) via `goblin`
- YARA-style pattern matching
- Heuristic analysis classifying suspicious imports by category
- Archive scanning (ZIP, etc.)
- Network indicator extraction (URLs, IPs, webhooks)
- 5-tier threat classification with confidence scores:
  - 🟢 **CLEAN**
  - 🔵 **CHEAT DETECTED** (intentionally not flagged as malicious)
  - 🟡 **SUSPICIOUS**
  - 🟠 **LIKELY MALICIOUS**
  - 🔴 **MALICIOUS**
- AES-256-GCM encrypted quarantine vault
- User trust / whitelist management

### Phase 2 - Script Shield
- Lua script parser for `loadstring + HttpGet` cheat-loader patterns
- URL extraction from obfuscated and base64-encoded strings
- Lua deobfuscator with detection for Luraph, Ironbrew, Moonsec, Prometheus
- Safe HTTP fetcher that **never executes** downloaded content
- Recursive download-chain resolver
- Built-in domain reputation database
- URL risk scoring

### Phase 3 - Real-Time Service
- File-system watcher with auto-scan on create/modify
- Process monitor + clipboard monitor (crypto address hijacking)
- Game-mode detection that pauses scans while a known game is running
- Unix-socket IPC server for control by CLI / GUI

### Phase 4 - Desktop GUI
- Tauri v2 app under `ui/`
- Modern dark theme with gradient accents, animated score ring, toast notifications
- Views: Dashboard · Scan · Tune · Deep Clean · Script Shield · AC Compat · Quarantine

### Phase 5 - Performance & Cleanup (new)
- **Tune** — `anticheat tune --plan` generates safe performance recommendations,
  `--apply` executes the non-destructive subset (temp clear). Covers power plan,
  game mode, startup programs, telemetry services, visual effects, memory
  compression, TCP stack, SSD trim, GPU scheduling.
- **Deep Clean** — `anticheat clean --scan` finds reclaimable space across
  browser caches, system/user temp, thumbnails, crash dumps, Discord/Steam
  caches, shader caches, package caches and old installers. `--sweep` deletes
  selected targets (with age guard and refusal to touch `.ssh`, `save`, wallet,
  etc.). `--system-wide` opts into paths outside HOME.

### Phase 6 - Anti-Cheat Compatibility (new)
- `anticheat_compat` module recognises 10+ AC products and classifies them
  kernel vs user-land.
- Engine returns a `CompatStatus` with `safe_mode`, `guarded_paths`, and a
  human-readable explanation the GUI surfaces on the Dashboard and a dedicated
  view.
- Policy: real-time watchers consult `should_skip_realtime(path)` before
  touching anything inside a guarded game directory.

## Building

### Native (Linux / macOS)

```bash
cargo build --release        # CLI + service
cd ui && cargo tauri dev     # desktop GUI
```

### Windows `.exe` from Linux

```bash
# Using cargo-xwin (recommended, no wine needed)
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc
scripts/package-windows.sh xwin

# Or using mingw
sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu
scripts/package-windows.sh mingw
```

Output: `dist/AntiCheat-windows-x64-<version>.zip` containing a portable
`anticheat.exe` (and `anticheat-service.exe` when the service cross-compiles),
plus signatures and a README.

> The Tauri desktop **GUI** is intentionally *not* cross-compiled from Linux —
> WebView2 is too painful. The GitHub Actions workflow
> `.github/workflows/release.yml` builds the GUI installer on a real Windows
> runner whenever you push a `v*` tag.

## CLI Usage

```bash
# Scanning
anticheat scan ~/Downloads              # full scan
anticheat scan --quick suspicious.exe   # hash-only
anticheat info suspicious.exe           # detailed analysis

# Trust + quarantine
anticheat trust ~/games/legit.exe
anticheat quarantine list
anticheat quarantine restore <id>

# Signatures
anticheat update
anticheat stats

# Script Shield (Lua cheat loaders)
anticheat script analyze loader.lua --follow
anticheat script fetch https://example.com/payload.lua

# Tune
anticheat tune --plan                   # show recommendations
anticheat tune --apply                  # run the safe subset

# Deep Clean
anticheat clean --scan                  # dry run
anticheat clean --sweep                 # delete in HOME
anticheat clean --sweep --system-wide   # also outside HOME

# Anti-cheat compatibility
anticheat compat
```

## Real-Time Protection Service

```bash
anticheat-service                        # foreground
RUST_LOG=info anticheat-service          # verbose
```

Exposes a JSON-line IPC socket at `$XDG_RUNTIME_DIR/anticheat-service.sock`
(Linux/macOS) for client tools.

## Desktop GUI

```bash
cd ui && cargo tauri dev
```

The GUI now ships:

- Animated protection-score ring
- Dashboard with signature / whitelist / quarantine cards and quick actions
- Scan view with drag-and-drop
- **Tune** view with safe-apply button and score bar
- **Deep Clean** view with per-category size chips and selectable targets
- **Anti-cheat compatibility** view explaining safe mode
- Script Shield analyzer
- Quarantine view

## License

MIT
