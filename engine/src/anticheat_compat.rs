//! Anti-cheat compatibility layer.
//!
//! Real competitive-game anti-cheats (EAC, BattlEye, Vanguard, FACEIT, ESEA,
//! PunkBuster) are *extremely* suspicious of any process that:
//!
//!   * opens handles into game processes,
//!   * hooks into graphics / input stacks,
//!   * loads kernel drivers while a game is running,
//!   * or does on-access scanning of the game's memory / files.
//!
//! We are an antivirus, not a cheat, but an AV that aggressively scans running
//! game binaries *looks* like a cheat to a kernel-level AC. The goal of this
//! module is simple: when a supported anti-cheat is running, we put ourselves
//! into a well-behaved "safe mode" where we:
//!
//!   1. never attach to, read, or enumerate threads of the guarded process,
//!   2. never touch files inside the guarded process's install directory
//!      unless the user explicitly asks for a scan,
//!   3. never inject, hook, or load drivers, and
//!   4. suspend real-time watchers on paths the AC might be hashing.
//!
//! The module is *detection only* — it tells the rest of the engine what
//! state to enter. It never talks to the anti-cheat process.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A game anti-cheat product we know about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiCheatProduct {
    EasyAntiCheat,
    BattlEye,
    RiotVanguard,
    FaceitAc,
    EsportsAc,
    PunkBuster,
    XignCode3,
    MiHoYoAc, // Genshin / HSR
    Ricochet,  // Call of Duty
    Denuvo,
    Steam,     // VAC - much lighter, but we still behave
}

impl AntiCheatProduct {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::EasyAntiCheat => "Easy Anti-Cheat",
            Self::BattlEye => "BattlEye",
            Self::RiotVanguard => "Riot Vanguard",
            Self::FaceitAc => "FACEIT Anti-Cheat",
            Self::EsportsAc => "ESEA Anti-Cheat",
            Self::PunkBuster => "PunkBuster",
            Self::XignCode3 => "XIGNCODE3",
            Self::MiHoYoAc => "miHoYo Anti-Cheat",
            Self::Ricochet => "Ricochet (Call of Duty)",
            Self::Denuvo => "Denuvo",
            Self::Steam => "VAC (Valve Anti-Cheat)",
        }
    }

    /// Is this AC kernel-mode? Kernel AC means we must be *extra* careful —
    /// no process handle opens, no driver loads, no memory scans.
    pub fn is_kernel_mode(&self) -> bool {
        matches!(
            self,
            Self::RiotVanguard | Self::Ricochet | Self::MiHoYoAc | Self::XignCode3 | Self::FaceitAc
        )
    }

    /// Process names (lowercased, without extension) that indicate this AC
    /// is running.
    pub fn process_names(&self) -> &'static [&'static str] {
        match self {
            Self::EasyAntiCheat => &["easyanticheat", "easyanticheat_eos", "eac-launcher"],
            Self::BattlEye => &["beservice", "bedaisy", "beclient"],
            Self::RiotVanguard => &["vgc", "vgtray", "vgk"],
            Self::FaceitAc => &["faceitclient", "faceitservice"],
            Self::EsportsAc => &["esea", "esea-client"],
            Self::PunkBuster => &["pnkbstra", "pnkbstrb"],
            Self::XignCode3 => &["xigncode3", "xigncode"],
            Self::MiHoYoAc => &["mhyprot2", "mhyprot3", "mhyprotectstub"],
            Self::Ricochet => &["ricochet", "ricochetservice", "ricochet_service"],
            Self::Denuvo => &["denuvo64"],
            Self::Steam => &[], // VAC is in-process, nothing to match on
        }
    }
}

/// Static list we iterate through when detecting what's running.
const ALL_PRODUCTS: &[AntiCheatProduct] = &[
    AntiCheatProduct::EasyAntiCheat,
    AntiCheatProduct::BattlEye,
    AntiCheatProduct::RiotVanguard,
    AntiCheatProduct::FaceitAc,
    AntiCheatProduct::EsportsAc,
    AntiCheatProduct::PunkBuster,
    AntiCheatProduct::XignCode3,
    AntiCheatProduct::MiHoYoAc,
    AntiCheatProduct::Ricochet,
    AntiCheatProduct::Denuvo,
];

/// Snapshot of what the compatibility layer thinks the system looks like.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatStatus {
    /// Anti-cheats detected running right now.
    pub active_products: Vec<AntiCheatProduct>,
    /// True if at least one active AC is kernel mode.
    pub kernel_mode_active: bool,
    /// Directories the AC is likely to hash/verify that we should not touch.
    pub guarded_paths: Vec<PathBuf>,
    /// Whether we should enter "safe mode" (no hooks, no process handle opens,
    /// no driver load, on-demand scans only for guarded paths).
    pub safe_mode: bool,
    /// Human readable explanation suitable for the UI.
    pub explanation: String,
}

impl CompatStatus {
    pub fn idle() -> Self {
        Self {
            active_products: vec![],
            kernel_mode_active: false,
            guarded_paths: vec![],
            safe_mode: false,
            explanation: "No game anti-cheat detected. Full protection enabled.".to_string(),
        }
    }
}

/// A single compatibility policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatAction {
    /// Path is fine to touch.
    Allow,
    /// Path is inside a guarded directory. Scan on-demand only, never in
    /// real time.
    OnDemandOnly,
    /// Path is a known AC process / driver. Do not open a handle at all.
    Refuse,
}

/// The compatibility layer itself.
pub struct AntiCheatCompat {
    /// Lowercased anti-cheat process names we watch for.
    known_names: HashSet<&'static str>,
    /// Directories that are "guarded" for on-demand-only scanning.
    guarded_prefixes: Vec<PathBuf>,
}

impl Default for AntiCheatCompat {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiCheatCompat {
    pub fn new() -> Self {
        let mut known = HashSet::new();
        for product in ALL_PRODUCTS {
            for name in product.process_names() {
                known.insert(*name);
            }
        }

        // Known install paths that are guarded by mainstream AC products.
        // We never auto-touch these — user has to scan them explicitly.
        let guarded = vec![
            PathBuf::from("C:\\Program Files\\Riot Vanguard"),
            PathBuf::from("C:\\Program Files (x86)\\Easy Anti-Cheat"),
            PathBuf::from("C:\\Program Files (x86)\\EasyAntiCheat"),
            PathBuf::from("C:\\Program Files (x86)\\Common Files\\BattlEye"),
            PathBuf::from("C:\\Program Files\\FACEIT AC"),
            PathBuf::from("C:\\Program Files\\FaceIT AC"),
            PathBuf::from("C:\\Program Files (x86)\\Genshin Impact"),
            PathBuf::from("C:\\Program Files\\Call of Duty"),
            PathBuf::from("C:\\Riot Games\\VALORANT"),
            PathBuf::from("C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Global Offensive"),
            PathBuf::from("C:\\Program Files (x86)\\Steam\\steamapps\\common\\Rust"),
            PathBuf::from("C:\\Program Files (x86)\\Steam\\steamapps\\common\\PUBG"),
        ];

        Self {
            known_names: known,
            guarded_prefixes: guarded,
        }
    }

    /// Quick test: is this process name a known anti-cheat process?
    pub fn is_known_ac_process(&self, process_name: &str) -> bool {
        let key = process_name_stem(process_name);
        self.known_names.contains(key.as_str())
    }

    /// Given a snapshot of process names, figure out which AC products
    /// are running.
    pub fn detect_from_process_list<I, S>(&self, processes: I) -> Vec<AntiCheatProduct>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let names: HashSet<String> = processes
            .into_iter()
            .map(|n| process_name_stem(n.as_ref()))
            .collect();

        let mut active = Vec::new();
        for product in ALL_PRODUCTS {
            for candidate in product.process_names() {
                if names.contains(*candidate) {
                    active.push(*product);
                    break;
                }
            }
        }
        active
    }

    /// Build a full status report from the current running-process snapshot.
    pub fn build_status<I, S>(&self, processes: I) -> CompatStatus
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let active_products = self.detect_from_process_list(processes);
        if active_products.is_empty() {
            return CompatStatus::idle();
        }

        let kernel_mode_active = active_products.iter().any(|p| p.is_kernel_mode());

        // Build explanation.
        let names: Vec<&'static str> =
            active_products.iter().map(|p| p.display_name()).collect();
        let listed = names.join(", ");
        let explanation = if kernel_mode_active {
            format!(
                "{} detected. Kernel-mode anti-cheat is active — AntiCheat is \
                running in safe mode: no process hooks, no driver loads, no \
                memory scans, on-demand scanning only for guarded game folders. \
                You can still scan downloads, Discord attachments, and cheat \
                loaders freely.",
                listed
            )
        } else {
            format!(
                "{} detected. AntiCheat is running in compatibility mode: \
                real-time scans on guarded game folders are paused. Manual \
                scans and downloads are still protected.",
                listed
            )
        };

        CompatStatus {
            active_products,
            kernel_mode_active,
            guarded_paths: self.guarded_prefixes.clone(),
            safe_mode: true,
            explanation,
        }
    }

    /// Policy decision for a given path given a status snapshot.
    pub fn policy_for_path(&self, path: &Path, status: &CompatStatus) -> CompatAction {
        // Never open a handle to an AC process binary. We match by stem.
        // On Linux, `\` is not a separator, so we split on both separators
        // manually to support cross-platform test paths.
        let as_str = path.to_string_lossy();
        let basename = as_str
            .rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(as_str.as_ref());
        let stem = basename.rsplit_once('.').map(|(l, _)| l).unwrap_or(basename);
        let stem_lower = stem.to_ascii_lowercase();
        if self.known_names.contains(stem_lower.as_str()) {
            return CompatAction::Refuse;
        }

        if !status.safe_mode {
            return CompatAction::Allow;
        }

        // If the path is inside a guarded prefix, it's on-demand-only.
        for prefix in &status.guarded_paths {
            if path_starts_with_insensitive(path, prefix) {
                return CompatAction::OnDemandOnly;
            }
        }

        CompatAction::Allow
    }

    /// True if our real-time file watcher should currently *skip* a path.
    /// Called on every filesystem event; must be cheap.
    pub fn should_skip_realtime(&self, path: &Path, status: &CompatStatus) -> bool {
        matches!(
            self.policy_for_path(path, status),
            CompatAction::OnDemandOnly | CompatAction::Refuse
        )
    }
}

/// Lowercased stem of a process name. `EasyAntiCheat.exe` -> `easyanticheat`.
fn process_name_stem(name: &str) -> String {
    let name = name.trim();
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let stem = base.rsplit_once('.').map(|(l, _)| l).unwrap_or(base);
    stem.to_ascii_lowercase()
}

fn path_starts_with_insensitive(path: &Path, prefix: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    let pref = prefix.to_string_lossy().to_ascii_lowercase();
    p.starts_with(&pref)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_vanguard() {
        let compat = AntiCheatCompat::new();
        let active = compat.detect_from_process_list(["vgc.exe", "chrome.exe", "svchost.exe"]);
        assert!(active.contains(&AntiCheatProduct::RiotVanguard));
    }

    #[test]
    fn kernel_mode_triggers_safe_mode() {
        let compat = AntiCheatCompat::new();
        let status = compat.build_status(["vgc.exe"]);
        assert!(status.kernel_mode_active);
        assert!(status.safe_mode);
    }

    #[test]
    fn idle_status_when_nothing_running() {
        let compat = AntiCheatCompat::new();
        let status = compat.build_status(["chrome.exe", "explorer.exe"]);
        assert!(!status.safe_mode);
        assert!(status.active_products.is_empty());
    }

    #[test]
    fn ac_process_path_is_refused() {
        let compat = AntiCheatCompat::new();
        let status = compat.build_status(["vgc.exe"]);
        let action = compat.policy_for_path(
            Path::new("C:\\Program Files\\Riot Vanguard\\vgc.exe"),
            &status,
        );
        assert_eq!(action, CompatAction::Refuse);
    }

    #[test]
    fn downloads_folder_stays_allowed() {
        let compat = AntiCheatCompat::new();
        let status = compat.build_status(["vgc.exe"]);
        let action =
            compat.policy_for_path(Path::new("C:\\Users\\me\\Downloads\\cheat.exe"), &status);
        assert_eq!(action, CompatAction::Allow);
    }
}
