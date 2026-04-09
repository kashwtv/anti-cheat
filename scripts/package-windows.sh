#!/usr/bin/env bash
# Build a Windows .exe for AntiCheat from a Linux host.
#
# Two backends are supported, in order of preference:
#
#   1. cargo-xwin (uses LLVM + the Microsoft build toolchain, no wine needed).
#      Install:  cargo install cargo-xwin
#                rustup target add x86_64-pc-windows-msvc
#
#   2. MinGW-w64 gcc cross-compiler (older, battle-tested).
#      Install on Debian/Ubuntu:
#                sudo apt install mingw-w64
#                rustup target add x86_64-pc-windows-gnu
#
# Usage:
#   scripts/package-windows.sh              # auto-detects a backend
#   scripts/package-windows.sh xwin         # force cargo-xwin
#   scripts/package-windows.sh mingw        # force mingw
#   BACKEND=xwin scripts/package-windows.sh # same via env var
#
# Output:
#   dist/AntiCheat-windows-x64/
#     anticheat.exe           (CLI)
#     anticheat-service.exe   (real-time service, if it builds)
#     README.txt
#     LICENSE
#   dist/AntiCheat-windows-x64.zip
#
# The Tauri desktop GUI (`anticheat-desktop`) is *not* cross-compiled here —
# Tauri apps require WebView2 bindings that are painful to cross-build. For
# the GUI, use the GitHub Actions workflow in `.github/workflows/release.yml`,
# which builds it on a Windows runner.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BACKEND="${BACKEND:-${1:-auto}}"
DIST="$ROOT/dist/AntiCheat-windows-x64"
VERSION="$(grep -m1 '^version' Cargo.toml 2>/dev/null | cut -d\" -f2 || true)"
VERSION="${VERSION:-dev}"

note() { printf "\033[1;36m==>\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m!!\033[0m  %s\n" "$*" >&2; }
die()  { printf "\033[1;31merr\033[0m %s\n" "$*" >&2; exit 1; }

detect_backend() {
  if command -v cargo-xwin >/dev/null 2>&1; then
    echo "xwin"
    return
  fi
  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "mingw"
    return
  fi
  echo "none"
}

if [[ "$BACKEND" == "auto" ]]; then
  BACKEND="$(detect_backend)"
fi

case "$BACKEND" in
  xwin)
    TARGET="x86_64-pc-windows-msvc"
    BUILD=(cargo xwin build --release --target "$TARGET")
    ;;
  mingw)
    TARGET="x86_64-pc-windows-gnu"
    BUILD=(cargo build --release --target "$TARGET")
    ;;
  none)
    die "No cross-compile backend found. Install cargo-xwin or mingw-w64 first. See this script's header."
    ;;
  *)
    die "Unknown backend '$BACKEND'. Use 'xwin' or 'mingw'."
    ;;
esac

note "Backend:  $BACKEND"
note "Target:   $TARGET"
note "Version:  $VERSION"

# Make sure the target is installed. `rustup` is a soft dependency — if the
# user installed rust via distro packages we just warn and hope for the best.
if command -v rustup >/dev/null 2>&1; then
  note "Ensuring rust target is installed"
  rustup target add "$TARGET" >/dev/null || warn "rustup target add $TARGET failed; continuing"
fi

note "Cleaning previous artifacts"
rm -rf "$DIST" "$DIST.zip"
mkdir -p "$DIST"

# --- CLI ---
note "Building anticheat CLI"
"${BUILD[@]}" -p anticheat-cli || die "CLI build failed"

CLI_EXE="target/$TARGET/release/anticheat.exe"
if [[ ! -f "$CLI_EXE" ]]; then
  die "Expected $CLI_EXE to exist"
fi
cp "$CLI_EXE" "$DIST/anticheat.exe"

# --- Service (optional, may fail on cross-compile with some deps) ---
note "Building anticheat-service (may be skipped on cross-compile)"
if "${BUILD[@]}" -p anticheat-service 2>/dev/null; then
  SVC_EXE="target/$TARGET/release/anticheat-service.exe"
  if [[ -f "$SVC_EXE" ]]; then
    cp "$SVC_EXE" "$DIST/anticheat-service.exe"
  fi
else
  warn "service did not cross-compile cleanly; shipping CLI only"
fi

# --- Bundle extras ---
note "Bundling docs and signatures"
if [[ -f LICENSE ]]; then cp LICENSE "$DIST/LICENSE"; fi
if [[ -f README.md ]]; then cp README.md "$DIST/README.txt"; fi
if [[ -d engine/signatures ]]; then
  cp -r engine/signatures "$DIST/signatures"
fi

cat > "$DIST/INSTALL.txt" <<'TXT'
AntiCheat Windows build

Quick start:
  1. Open a PowerShell or cmd window in this folder.
  2. Run:  anticheat.exe scan <path>
     or:    anticheat.exe tune --plan
     or:    anticheat.exe clean --scan
     or:    anticheat.exe compat

The first run creates %USERPROFILE%\.anticheat for the signature DB and quarantine vault.
No installer is required — this is a portable build. Drop the folder wherever you like.

For the desktop GUI (anticheat-desktop), use the Windows installer from the
GitHub Releases page. The GUI is built by the repo's CI on a real Windows
runner because Tauri + WebView2 is not cross-compile-friendly.
TXT

# --- Zip it up ---
if command -v zip >/dev/null 2>&1; then
  note "Creating zip"
  (cd dist && zip -qr "AntiCheat-windows-x64-$VERSION.zip" "AntiCheat-windows-x64")
  note "Done: dist/AntiCheat-windows-x64-$VERSION.zip"
else
  warn "'zip' not installed, skipping archive"
  note "Done: dist/AntiCheat-windows-x64/"
fi
