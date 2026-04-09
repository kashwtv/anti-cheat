//! Deep Clean — CCleaner-style reclaimable storage scanner.
//!
//! This module walks the OS's "usual suspect" locations (browser caches,
//! temp dirs, crash dumps, log files, thumbnail caches, package caches,
//! Discord / Steam / game installer leftovers) and reports how much
//! space could be freed.
//!
//! Two stages:
//!   1. `scan`  — non-destructive. Enumerates targets, sizes them, and
//!                returns a `CleanReport`. The user sees the list and
//!                picks categories.
//!   2. `sweep` — destructive. Deletes the files in the selected
//!                categories. Files in `protected_paths` are *never*
//!                deleted, and we refuse to descend outside the HOME
//!                directory unless the caller passes `allow_system = true`.
//!
//! We never touch:
//!   - the Windows registry (that's for the Tune module),
//!   - game save directories,
//!   - Anti-cheat directories (see `anticheat_compat::guarded_paths`),
//!   - anything matched by `PROTECT_GLOBS` below.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// A category of cleanable garbage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CleanCategory {
    BrowserCache,
    BrowserCookies,
    SystemTemp,
    UserTemp,
    ThumbnailCache,
    CrashDumps,
    EventLogs,
    PackageCache,
    DiscordCache,
    SteamDownloadCache,
    GameShaderCache,
    RecycleBin,
    OldInstallers,
}

impl CleanCategory {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::BrowserCache => "Browser cache",
            Self::BrowserCookies => "Browser cookies",
            Self::SystemTemp => "System temp",
            Self::UserTemp => "User temp",
            Self::ThumbnailCache => "Thumbnail cache",
            Self::CrashDumps => "Crash dumps",
            Self::EventLogs => "Event logs",
            Self::PackageCache => "Package cache (apt / dnf / winget)",
            Self::DiscordCache => "Discord cache",
            Self::SteamDownloadCache => "Steam download cache",
            Self::GameShaderCache => "Game shader cache",
            Self::RecycleBin => "Recycle bin",
            Self::OldInstallers => "Old installer leftovers",
        }
    }

    /// Is this category safe to delete without confirmation?
    pub fn safe_default(&self) -> bool {
        matches!(
            self,
            Self::BrowserCache
                | Self::SystemTemp
                | Self::UserTemp
                | Self::ThumbnailCache
                | Self::CrashDumps
                | Self::EventLogs
                | Self::PackageCache
                | Self::DiscordCache
                | Self::SteamDownloadCache
                | Self::GameShaderCache
                | Self::OldInstallers
        )
    }
}

/// A single target path + how much it contains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanTarget {
    pub category: CleanCategory,
    pub path: PathBuf,
    pub description: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub last_modified: Option<String>,
    pub selected: bool,
}

/// Full report the scanner hands back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanReport {
    pub targets: Vec<CleanTarget>,
    pub total_bytes: u64,
    pub total_files: usize,
    pub scan_duration_ms: u64,
}

impl CleanReport {
    pub fn by_category(&self, category: CleanCategory) -> u64 {
        self.targets
            .iter()
            .filter(|t| t.category == category)
            .map(|t| t.size_bytes)
            .sum()
    }
}

/// Result of a destructive sweep run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepResult {
    pub bytes_freed: u64,
    pub files_deleted: usize,
    pub errors: Vec<String>,
}

/// Config for the cleaner.
#[derive(Debug, Clone)]
pub struct CleanConfig {
    /// Paths the cleaner must never touch, regardless of category.
    pub protected_paths: Vec<PathBuf>,
    /// Paths the cleaner is allowed to scan. Empty means "auto-detect".
    pub roots: Vec<(CleanCategory, PathBuf, String)>,
    /// Don't delete anything newer than this many hours.
    pub min_age_hours: u64,
    /// Required: refuse to delete files outside HOME unless this is true.
    pub allow_system_wide: bool,
}

impl Default for CleanConfig {
    fn default() -> Self {
        Self {
            protected_paths: Self::default_protected(),
            roots: Vec::new(), // auto-detect
            min_age_hours: 1,
            allow_system_wide: false,
        }
    }
}

impl CleanConfig {
    fn default_protected() -> Vec<PathBuf> {
        let mut v = vec![
            PathBuf::from("C:\\Program Files\\Riot Vanguard"),
            PathBuf::from("C:\\Program Files (x86)\\Easy Anti-Cheat"),
            PathBuf::from("C:\\Program Files (x86)\\Common Files\\BattlEye"),
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("C:\\Windows\\SysWOW64"),
        ];
        if let Some(home) = dirs_home() {
            // Don't sweep the user's own document roots.
            v.push(home.join("Documents"));
            v.push(home.join("Desktop"));
            v.push(home.join("Pictures"));
            v.push(home.join(".ssh"));
            v.push(home.join(".gnupg"));
        }
        v
    }
}

/// Glob-ish substrings that must never appear inside a path we delete.
const PROTECT_GLOBS: &[&str] = &[
    ".ssh",
    ".gnupg",
    "save",
    "saves",
    "savegame",
    "savedata",
    "wallet",
    "keystore",
    "seed",
    "password",
    "credentials",
    "cookies.sqlite",
];

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The cleaner itself.
pub struct DeepCleaner {
    config: CleanConfig,
}

impl DeepCleaner {
    pub fn new(config: CleanConfig) -> Self {
        Self { config }
    }

    /// Walk the default targets and return a sized report.
    pub fn scan(&self) -> CleanReport {
        let start = std::time::Instant::now();
        let roots = if self.config.roots.is_empty() {
            default_roots()
        } else {
            self.config.roots.clone()
        };

        let mut targets = Vec::new();
        let mut total_bytes = 0u64;
        let mut total_files = 0usize;

        for (category, path, description) in roots {
            if !path.exists() {
                continue;
            }
            if self.is_protected(&path) {
                continue;
            }

            let (size, count, mtime) = walk_dir_size(&path, &self.config.protected_paths);
            if size == 0 && count == 0 {
                continue;
            }
            total_bytes += size;
            total_files += count;

            targets.push(CleanTarget {
                category,
                path,
                description,
                size_bytes: size,
                file_count: count,
                last_modified: mtime.map(format_system_time),
                selected: category.safe_default(),
            });
        }

        CleanReport {
            targets,
            total_bytes,
            total_files,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Actually delete files in the selected targets. Files younger than
    /// `min_age_hours` are skipped.
    pub fn sweep(&self, report: &CleanReport) -> SweepResult {
        let mut result = SweepResult {
            bytes_freed: 0,
            files_deleted: 0,
            errors: Vec::new(),
        };
        let min_age = std::time::Duration::from_secs(self.config.min_age_hours * 3600);
        let home = dirs_home();

        for target in report.targets.iter().filter(|t| t.selected) {
            // System-wide sweeps are opt-in.
            if !self.config.allow_system_wide {
                if let Some(ref h) = home {
                    if !target.path.starts_with(h) {
                        result.errors.push(format!(
                            "{} is outside HOME, skipped (pass allow_system_wide to delete)",
                            target.path.display()
                        ));
                        continue;
                    }
                }
            }

            if self.is_protected(&target.path) {
                result
                    .errors
                    .push(format!("protected path: {}", target.path.display()));
                continue;
            }

            if let Err(e) = delete_dir_contents(
                &target.path,
                &self.config.protected_paths,
                min_age,
                &mut result,
            ) {
                result
                    .errors
                    .push(format!("{}: {}", target.path.display(), e));
            }
        }

        result
    }

    fn is_protected(&self, path: &Path) -> bool {
        let lower = path.to_string_lossy().to_ascii_lowercase();
        for protected in &self.config.protected_paths {
            let plower = protected.to_string_lossy().to_ascii_lowercase();
            if lower.starts_with(&plower) {
                return true;
            }
        }
        PROTECT_GLOBS.iter().any(|g| lower.contains(g))
    }
}

/// Default set of cleanup roots based on the current OS + user env.
fn default_roots() -> Vec<(CleanCategory, PathBuf, String)> {
    let mut out = Vec::new();
    let home = dirs_home();

    // Cross-platform temp.
    out.push((
        CleanCategory::UserTemp,
        std::env::temp_dir(),
        "Operating system temp directory".into(),
    ));

    if let Some(home) = home {
        // Browser caches.
        let browsers = [
            (
                ".cache/google-chrome/Default/Cache",
                "Google Chrome cache",
            ),
            (
                ".cache/chromium/Default/Cache",
                "Chromium cache",
            ),
            (
                ".cache/mozilla/firefox",
                "Firefox cache",
            ),
            (
                "AppData/Local/Google/Chrome/User Data/Default/Cache",
                "Google Chrome cache (Windows)",
            ),
            (
                "AppData/Local/Microsoft/Edge/User Data/Default/Cache",
                "Microsoft Edge cache",
            ),
            (
                "Library/Caches/Google/Chrome",
                "Google Chrome cache (macOS)",
            ),
        ];
        for (rel, desc) in browsers {
            let p = home.join(rel);
            if p.exists() {
                out.push((CleanCategory::BrowserCache, p, desc.into()));
            }
        }

        // Thumbnail cache.
        let thumbs = home.join(".cache/thumbnails");
        if thumbs.exists() {
            out.push((
                CleanCategory::ThumbnailCache,
                thumbs,
                "Nautilus / Linux thumbnail cache".into(),
            ));
        }
        let win_thumbs = home.join("AppData/Local/Microsoft/Windows/Explorer");
        if win_thumbs.exists() {
            out.push((
                CleanCategory::ThumbnailCache,
                win_thumbs,
                "Windows Explorer thumbnail cache".into(),
            ));
        }

        // Discord.
        let discord = home.join(".config/discord/Cache");
        if discord.exists() {
            out.push((
                CleanCategory::DiscordCache,
                discord,
                "Discord asset cache".into(),
            ));
        }
        let discord_win = home.join("AppData/Roaming/discord/Cache");
        if discord_win.exists() {
            out.push((
                CleanCategory::DiscordCache,
                discord_win,
                "Discord asset cache (Windows)".into(),
            ));
        }

        // Steam download cache + shader cache.
        let steam_dl = home.join(".steam/steam/appcache");
        if steam_dl.exists() {
            out.push((
                CleanCategory::SteamDownloadCache,
                steam_dl,
                "Steam appcache".into(),
            ));
        }
        let shader = home.join(".cache/mesa_shader_cache");
        if shader.exists() {
            out.push((
                CleanCategory::GameShaderCache,
                shader,
                "Mesa shader cache".into(),
            ));
        }
        let shader_nv = home.join(".nv/GLCache");
        if shader_nv.exists() {
            out.push((
                CleanCategory::GameShaderCache,
                shader_nv,
                "Nvidia GL shader cache".into(),
            ));
        }
    }

    // Package caches.
    #[cfg(target_os = "linux")]
    {
        let apt = PathBuf::from("/var/cache/apt/archives");
        if apt.exists() {
            out.push((
                CleanCategory::PackageCache,
                apt,
                "apt download cache".into(),
            ));
        }
        let dnf = PathBuf::from("/var/cache/dnf");
        if dnf.exists() {
            out.push((
                CleanCategory::PackageCache,
                dnf,
                "dnf download cache".into(),
            ));
        }
    }

    out
}

/// Recursively size a directory, skipping protected paths.
fn walk_dir_size(
    root: &Path,
    protected: &[PathBuf],
) -> (u64, usize, Option<SystemTime>) {
    let protected_set: HashSet<PathBuf> = protected.iter().cloned().collect();
    let mut bytes = 0u64;
    let mut files = 0usize;
    let mut newest: Option<SystemTime> = None;

    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !protected_set.contains(&e.path().to_path_buf()))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let lower = entry.path().to_string_lossy().to_ascii_lowercase();
        if PROTECT_GLOBS.iter().any(|g| lower.contains(g)) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            bytes += meta.len();
            files += 1;
            if let Ok(m) = meta.modified() {
                newest = Some(match newest {
                    Some(prev) if prev > m => prev,
                    _ => m,
                });
            }
        }
    }

    (bytes, files, newest)
}

/// Delete every regular file inside `root` older than `min_age`.
fn delete_dir_contents(
    root: &Path,
    protected: &[PathBuf],
    min_age: std::time::Duration,
    result: &mut SweepResult,
) -> std::io::Result<()> {
    let protected_set: HashSet<PathBuf> = protected.iter().cloned().collect();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .contents_first(true)
        .into_iter()
        .filter_entry(|e| !protected_set.contains(&e.path().to_path_buf()))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let lower = entry.path().to_string_lossy().to_ascii_lowercase();
        if PROTECT_GLOBS.iter().any(|g| lower.contains(g)) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let Ok(age) = SystemTime::now().duration_since(modified) else {
            continue;
        };
        if age < min_age {
            continue;
        }
        let size = meta.len();
        match std::fs::remove_file(entry.path()) {
            Ok(()) => {
                result.bytes_freed += size;
                result.files_deleted += 1;
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("{}: {}", entry.path().display(), e));
            }
        }
    }
    Ok(())
}

fn format_system_time(t: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = t.into();
    datetime.to_rfc3339()
}

/// Human-readable byte formatter.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}", value, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_does_not_panic() {
        let cleaner = DeepCleaner::new(CleanConfig::default());
        let report = cleaner.scan();
        // It's OK to find nothing in a CI sandbox.
        assert_eq!(
            report.total_bytes,
            report.targets.iter().map(|t| t.size_bytes).sum::<u64>()
        );
    }

    #[test]
    fn bytes_formatter_works() {
        assert_eq!(format_bytes(0), "0.00 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn protected_paths_never_selected() {
        let cleaner = DeepCleaner::new(CleanConfig::default());
        assert!(cleaner.is_protected(Path::new("/home/user/.ssh")));
        assert!(cleaner.is_protected(Path::new(
            "C:\\Program Files\\Riot Vanguard\\vgc.exe"
        )));
    }
}
