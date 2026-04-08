# AntiCheat Desktop

Tauri v2 desktop application for AntiCheat.

## Layout

```
ui/
├── src-tauri/          Rust backend (Tauri commands wrapping the engine)
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── build.rs
│   └── src/main.rs
└── dist/               Static frontend (vanilla HTML/CSS/JS)
    ├── index.html
    ├── main.js
    └── style.css
```

## Building

The Tauri project is **not** part of the root Cargo workspace (to avoid
Tauri's own dependency graph colliding with the engine). Build it from
inside `ui/src-tauri/`:

```bash
cd ui/src-tauri
cargo build --release
```

You will need Tauri v2 system prerequisites installed
(`webkit2gtk`, etc. on Linux).

Icons (`ui/src-tauri/icons/`) are not included in the repository; add your
own `icon.png` before building a distributable bundle.
