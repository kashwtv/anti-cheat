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

## Architecture

```
anti-cheat/
├── engine/         # Core scanning library (Rust)
│   ├── scanner/        Hash, PE, YARA, heuristic, archive, network scanners
│   ├── detection/      Confidence scoring, classification, threat levels
│   ├── database/       Game DB, hash DB, whitelist, source reputation
│   ├── quarantine/     AES-256-GCM encrypted vault
│   ├── script_shield/  Lua script parser, safe fetcher, payload analyzer
│   ├── updater/        Signature updates
│   └── signatures/     YARA rules
├── cli/            # `anticheat` command-line interface
└── service/        # `anticheat-service` real-time protection daemon
```

## Features

### Phase 1 - Scanner Engine (complete)
- SHA-256 / MD5 / SHA-1 / TLSH file hashing
- PE parser (sections, imports, exports, overlay, signature) via `goblin`
- YARA-style pattern matching (custom rule engine)
- Heuristic analysis classifying suspicious imports by category
- Archive scanning (ZIP, etc.)
- Network indicator extraction (URLs, IPs, webhooks)
- 5-tier threat classification with confidence scores:
  - 🟢 **CLEAN**
  - 🔵 **CHEAT DETECTED** (intentionally not flagged as malicious)
  - 🟡 **SUSPICIOUS**
  - 🟠 **LIKELY MALICIOUS**
  - 🔴 **MALICIOUS**
- Cheat-vs-malware classifier based on injection target (game vs system process)
- AES-256-GCM encrypted quarantine vault
- 59-game database + system process database
- User trust / whitelist management

### Phase 2 - Script Shield (complete)
- Lua script parser for the "loadstring + HttpGet" cheat-loader pattern
- URL extraction from obfuscated and base64-encoded strings
- Lua deobfuscator with detection for Luraph, Ironbrew, Moonsec, Prometheus
- Safe HTTP fetcher that **never executes** downloaded content
- Recursive download-chain resolver
- Built-in domain reputation database
- URL risk scoring (TLD, IP-as-host, shortener, CDN abuse, path entropy)
- Behavior detection: stealers, droppers, persistence, miners, keyloggers,
  cheat loaders, cheat injectors, backdoors

### Phase 3 - Real-Time Protection Service (complete)
- File system watcher with auto-scan on create/modify
- Process monitor (new-process detection, suspicious-location alerts)
- Clipboard monitor (crypto address hijacking detection)
- Scheduled quick / full / idle scans
- Game-mode detection that pauses scans while a known game is running
- Unix-socket IPC server for control by CLI / GUI

### Phase 4 - Desktop GUI (complete)
- Tauri v2 desktop application in `ui/`
- Vanilla HTML/CSS/JS frontend (no framework bloat)
- Tauri commands wrapping the engine: `scan_file`, `quick_scan`,
  `scan_directory`, `get_stats`, `trust_file`, `analyze_script`
- Views: Dashboard, Scan, Script Shield, Quarantine

### Phase 5 - Polish (ongoing)
- Threat notifications wired from the file watcher
- Cleaned up unused imports and warnings
- Frontend-backend separation so the engine can be reused from CLI, service,
  and desktop GUI without duplication

## Building

```bash
# CLI + service (workspace)
cargo build --release
```

Outputs:
- `target/release/anticheat` (CLI)
- `target/release/anticheat-service` (background service)

The desktop GUI lives outside the workspace:

```bash
cd ui/src-tauri
cargo build --release
```

## CLI Usage

```bash
# Full scan of a directory
anticheat scan ~/Downloads

# Quick (hash-only) scan
anticheat scan --quick suspicious.exe

# Detailed file analysis
anticheat info suspicious.exe

# Trust a file (add to whitelist)
anticheat trust ~/games/legit.exe

# Quarantine management
anticheat quarantine list
anticheat quarantine restore <id>

# Update signatures
anticheat update

# Statistics
anticheat stats

# Script Shield: analyze a Lua cheat loader
anticheat script analyze loader.lua --follow

# Safely fetch a URL and report what it contains
anticheat script fetch https://example.com/payload.lua
```

## Real-Time Protection Service

```bash
# Run in foreground
anticheat-service

# Configure via env
RUST_LOG=info anticheat-service
```

The service exposes a JSON-line IPC socket at
`$XDG_RUNTIME_DIR/anticheat-service.sock` (Linux/macOS) for client tools.

## Desktop GUI

Launch the Tauri desktop app after building:

```bash
cd ui/src-tauri && cargo run
```

The GUI provides a dashboard with signature/whitelist/quarantine stats, a
scan view, and the Script Shield analyzer.

## Why a separate antivirus for gamers?

When a player downloads a cheat from a forum or Discord server, the cheat
itself is usually a legitimate game-modification tool. Unfortunately, the
same channels are heavily used to distribute malware bundled with — or
disguised as — cheats: Discord token stealers, browser cookie grabbers,
crypto-clippers, RATs, and miners. Mainstream AV either flags every cheat
as malicious (forcing users to disable protection entirely) or fails to
detect the bundled malware. AntiCheat fills that gap.

## License

MIT
