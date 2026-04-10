# AntiCheat v0.1.0 — Windows Portable

**anticheat.exe** — CLI scanner, tuner, deep clean, script shield, AC compat.
**anticheat-service.exe** — Real-time background protection service.

## Quick start

```
anticheat.exe scan C:\Users\you\Downloads
anticheat.exe tune --plan
anticheat.exe clean --scan
anticheat.exe compat
anticheat.exe script analyze loader.lua
```

No installer required — this is a portable build.
First run creates `%USERPROFILE%\.anticheat` for the signature DB and quarantine vault.

Built from Linux via mingw-w64 cross-compilation.
