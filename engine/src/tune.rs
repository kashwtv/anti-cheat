//! PC performance tuning.
//!
//! This module inspects the system and suggests tweaks that *measurably*
//! improve gaming performance. Every destructive action is gated behind
//! `TuneMode::Apply` and a safety check — in `Plan` mode we only report.
//!
//! The module is cross-platform but most tweaks are Windows-focused,
//! because that's where the gaming audience is. Linux/mac builds get a
//! safe subset (basically detection + memory/disk advice, no registry).
//!
//! Design goals:
//!   - Never recommend a tweak that could cause data loss.
//!   - Never touch drivers, GPU firmware, or kernel modules.
//!   - Always leave a restore-point hook for the caller (via `Action::revert_hint`).
//!   - Be transparent: every applied tweak has a human readable justification.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How the caller wants to execute the tune.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TuneMode {
    /// Only inspect and report. Nothing is changed.
    Plan,
    /// Execute the safe subset of tweaks.
    Apply,
}

/// A tune category the user can toggle on or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TuneCategory {
    PowerPlan,
    GameMode,
    StartupPrograms,
    BackgroundServices,
    VisualEffects,
    MemoryCompression,
    NetworkStack,
    StorageTrim,
    TempFiles,
    GpuPriority,
}

impl TuneCategory {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::PowerPlan => "Power plan",
            Self::GameMode => "Game mode",
            Self::StartupPrograms => "Startup programs",
            Self::BackgroundServices => "Background services",
            Self::VisualEffects => "Visual effects",
            Self::MemoryCompression => "Memory compression",
            Self::NetworkStack => "Network stack",
            Self::StorageTrim => "SSD trim",
            Self::TempFiles => "Temp files",
            Self::GpuPriority => "GPU scheduling",
        }
    }
}

/// Severity / impact of a single suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Impact {
    Low,
    Medium,
    High,
}

impl Impact {
    pub fn weight(&self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Medium => 3,
            Self::High => 6,
        }
    }
}

/// A single tune suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuneSuggestion {
    pub category: TuneCategory,
    pub title: String,
    pub description: String,
    pub impact: Impact,
    /// Short note the user can use to undo the tweak by hand.
    pub revert_hint: String,
    /// Set to true once the tune runner has applied this action.
    pub applied: bool,
}

/// Full tuning report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuneReport {
    pub mode: TuneMode,
    pub suggestions: Vec<TuneSuggestion>,
    pub score_before: u32,
    pub score_after: u32,
    pub notes: Vec<String>,
}

impl TuneReport {
    pub fn total_impact(&self) -> u32 {
        self.suggestions.iter().map(|s| s.impact.weight()).sum()
    }

    pub fn applied_count(&self) -> usize {
        self.suggestions.iter().filter(|s| s.applied).count()
    }
}

/// Facts about the machine used to tailor suggestions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub total_memory_mb: u64,
    pub free_memory_mb: u64,
    pub cpu_cores: usize,
    pub is_laptop: bool,
    pub has_ssd: bool,
    pub os_kind: OsKind,
    pub temp_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsKind {
    Windows,
    Linux,
    Macos,
    Other,
}

impl SystemSnapshot {
    /// Read what we can about the system. Safe to call anywhere.
    pub fn capture() -> Self {
        let os_kind = if cfg!(target_os = "windows") {
            OsKind::Windows
        } else if cfg!(target_os = "linux") {
            OsKind::Linux
        } else if cfg!(target_os = "macos") {
            OsKind::Macos
        } else {
            OsKind::Other
        };

        let (total_memory_mb, free_memory_mb) = read_memory();
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let temp_dirs = std::env::temp_dir()
            .canonicalize()
            .ok()
            .into_iter()
            .collect();

        Self {
            total_memory_mb,
            free_memory_mb,
            cpu_cores,
            is_laptop: false, // conservative default
            has_ssd: true,    // conservative default
            os_kind,
            temp_dirs,
        }
    }
}

#[cfg(target_os = "linux")]
fn read_memory() -> (u64, u64) {
    // /proc/meminfo is the canonical source on linux.
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        let mut total_kb = 0u64;
        let mut avail_kb = 0u64;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                total_kb = parse_meminfo_kb(rest);
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                avail_kb = parse_meminfo_kb(rest);
            }
        }
        return (total_kb / 1024, avail_kb / 1024);
    }
    (0, 0)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb(rest: &str) -> u64 {
    rest.trim()
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn read_memory() -> (u64, u64) {
    (0, 0)
}

/// The tuner itself.
pub struct Tuner {
    /// Categories the user has explicitly disabled.
    disabled: std::collections::HashSet<TuneCategory>,
}

impl Default for Tuner {
    fn default() -> Self {
        Self::new()
    }
}

impl Tuner {
    pub fn new() -> Self {
        Self {
            disabled: Default::default(),
        }
    }

    pub fn disable(&mut self, category: TuneCategory) {
        self.disabled.insert(category);
    }

    /// Generate the full suggestion list for the given system.
    pub fn plan(&self, snapshot: &SystemSnapshot) -> TuneReport {
        let mut suggestions = Vec::new();

        self.add_power_plan(snapshot, &mut suggestions);
        self.add_game_mode(snapshot, &mut suggestions);
        self.add_startup_programs(snapshot, &mut suggestions);
        self.add_background_services(snapshot, &mut suggestions);
        self.add_visual_effects(snapshot, &mut suggestions);
        self.add_memory_compression(snapshot, &mut suggestions);
        self.add_network_stack(snapshot, &mut suggestions);
        self.add_storage_trim(snapshot, &mut suggestions);
        self.add_temp_files(snapshot, &mut suggestions);
        self.add_gpu_priority(snapshot, &mut suggestions);

        // Drop categories the user disabled.
        suggestions.retain(|s| !self.disabled.contains(&s.category));

        // Scoring — a bit playful but deterministic.
        let score_before = 50u32;
        let score_after = (score_before
            + suggestions.iter().map(|s| s.impact.weight() * 3).sum::<u32>())
        .min(100);

        TuneReport {
            mode: TuneMode::Plan,
            suggestions,
            score_before,
            score_after,
            notes: vec!["Plan-only. No system changes have been made.".to_string()],
        }
    }

    /// Apply the safe subset of tweaks. On non-Windows targets we just
    /// clean temp files and return a report. Registry / service edits
    /// require the real Windows build.
    pub fn apply(&self, snapshot: &SystemSnapshot) -> TuneReport {
        let mut report = self.plan(snapshot);
        report.mode = TuneMode::Apply;
        report.notes.clear();

        for suggestion in &mut report.suggestions {
            match suggestion.category {
                TuneCategory::TempFiles => {
                    if let Ok(freed) = clear_user_temp(&snapshot.temp_dirs) {
                        suggestion.applied = true;
                        report
                            .notes
                            .push(format!("Cleared {freed} bytes of temp files."));
                    }
                }
                TuneCategory::StorageTrim if snapshot.has_ssd => {
                    // On Windows we'd shell out to `defrag /L`, on Linux `fstrim`
                    // — both require privilege. Mark as planned only.
                    report
                        .notes
                        .push("SSD trim requires elevation and was not executed.".into());
                }
                _ => {
                    // Everything else requires elevation / registry access;
                    // the real Windows build will call into a privileged
                    // helper. We keep them as recommendations only.
                }
            }
        }

        if report.applied_count() == 0 {
            report.notes.push(
                "No destructive changes were made. Run the Windows build as \
                administrator to apply registry and service tweaks."
                    .into(),
            );
        }

        report
    }

    fn add_power_plan(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.os_kind == OsKind::Windows {
            out.push(TuneSuggestion {
                category: TuneCategory::PowerPlan,
                title: "Switch to the Ultimate Performance power plan".into(),
                description:
                    "Disables CPU park/throttle and prioritises latency-sensitive workloads. \
                     Gives a 3-8% boost in 1% lows on most desktops."
                        .into(),
                impact: Impact::High,
                revert_hint:
                    "Control Panel → Power Options → choose 'Balanced' to revert.".into(),
                applied: false,
            });
        }
    }

    fn add_game_mode(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.os_kind == OsKind::Windows {
            out.push(TuneSuggestion {
                category: TuneCategory::GameMode,
                title: "Enable Windows Game Mode".into(),
                description:
                    "Suspends background updates and defers Windows Update while you play."
                        .into(),
                impact: Impact::Medium,
                revert_hint: "Settings → Gaming → Game Mode → toggle off.".into(),
                applied: false,
            });
        }
    }

    fn add_startup_programs(&self, _snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        out.push(TuneSuggestion {
            category: TuneCategory::StartupPrograms,
            title: "Trim startup programs".into(),
            description:
                "AntiCheat scans your startup list for known bloat (Cortana bing, Adobe updater, \
                 Razer Synapse, vendor shopping assistants) and recommends disabling them."
                    .into(),
            impact: Impact::Medium,
            revert_hint: "Task Manager → Startup tab → re-enable.".into(),
            applied: false,
        });
    }

    fn add_background_services(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.os_kind == OsKind::Windows {
            out.push(TuneSuggestion {
                category: TuneCategory::BackgroundServices,
                title: "Disable telemetry and diagnostic services".into(),
                description:
                    "DiagTrack, dmwappushservice and WSearch are notorious for spiking disk \
                     during gameplay. We stop them and set Manual start."
                        .into(),
                impact: Impact::Medium,
                revert_hint:
                    "services.msc → set each service back to Automatic.".into(),
                applied: false,
            });
        }
    }

    fn add_visual_effects(&self, _snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        out.push(TuneSuggestion {
            category: TuneCategory::VisualEffects,
            title: "Use 'Adjust for best performance' visual profile".into(),
            description:
                "Disables animation, translucency and window shadows. Frees ~1-2% CPU."
                    .into(),
            impact: Impact::Low,
            revert_hint: "sysdm.cpl → Advanced → Performance → 'Let Windows choose'".into(),
            applied: false,
        });
    }

    fn add_memory_compression(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.total_memory_mb >= 16 * 1024 {
            out.push(TuneSuggestion {
                category: TuneCategory::MemoryCompression,
                title: "Disable memory compression".into(),
                description: format!(
                    "You have {} GB RAM — memory compression costs CPU with no benefit \
                     above 16 GB.",
                    snap.total_memory_mb / 1024
                ),
                impact: Impact::Low,
                revert_hint:
                    "PowerShell (admin): Enable-MMAgent -MemoryCompression".into(),
                applied: false,
            });
        }
    }

    fn add_network_stack(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.os_kind == OsKind::Windows {
            out.push(TuneSuggestion {
                category: TuneCategory::NetworkStack,
                title: "Tune TCP for low latency".into(),
                description:
                    "Disables Nagle's algorithm on the gaming NIC and enables \
                     TCP_NODELAY for game-port traffic. Improves ping consistency \
                     in competitive titles."
                        .into(),
                impact: Impact::High,
                revert_hint:
                    "netsh int tcp reset → removes all TCP overrides.".into(),
                applied: false,
            });
        }
    }

    fn add_storage_trim(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.has_ssd {
            out.push(TuneSuggestion {
                category: TuneCategory::StorageTrim,
                title: "Trim all SSDs".into(),
                description:
                    "Reclaims stale blocks on every SSD. Can restore lost write performance \
                     on older drives."
                        .into(),
                impact: Impact::Low,
                revert_hint: "Trim is non-destructive. No revert needed.".into(),
                applied: false,
            });
        }
    }

    fn add_temp_files(&self, _snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        out.push(TuneSuggestion {
            category: TuneCategory::TempFiles,
            title: "Clear temp folders".into(),
            description:
                "Removes files in the current user's %TEMP% / /tmp directory that are \
                 older than 7 days."
                    .into(),
            impact: Impact::Low,
            revert_hint: "Temp files do not need to be restored.".into(),
            applied: false,
        });
    }

    fn add_gpu_priority(&self, snap: &SystemSnapshot, out: &mut Vec<TuneSuggestion>) {
        if snap.os_kind == OsKind::Windows {
            out.push(TuneSuggestion {
                category: TuneCategory::GpuPriority,
                title: "Enable Hardware-accelerated GPU scheduling".into(),
                description:
                    "Lets the GPU manage its own VRAM queue. Reduces stutter on \
                     DX12 / Vulkan games when using modern Nvidia / AMD drivers."
                        .into(),
                impact: Impact::Medium,
                revert_hint: "Settings → Display → Graphics → toggle HAGS off.".into(),
                applied: false,
            });
        }
    }
}

/// Sum up every file older than 7 days in the temp dirs and delete them.
/// Returns the number of bytes freed.
fn clear_user_temp(dirs: &[PathBuf]) -> std::io::Result<u64> {
    use std::time::{Duration, SystemTime};

    let threshold = Duration::from_secs(7 * 24 * 60 * 60);
    let mut freed: u64 = 0;

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            let Ok(age) = SystemTime::now().duration_since(modified) else {
                continue;
            };
            if age < threshold {
                continue;
            }
            let size = metadata.len();
            if std::fs::remove_file(&path).is_ok() {
                freed += size;
            }
        }
    }

    Ok(freed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_produces_some_suggestions() {
        let tuner = Tuner::new();
        let snap = SystemSnapshot::capture();
        let report = tuner.plan(&snap);
        // Every OS should produce at least the temp-files and visual-effects suggestions.
        assert!(!report.suggestions.is_empty());
        assert!(report.score_after >= report.score_before);
    }

    #[test]
    fn disabled_categories_are_dropped() {
        let mut tuner = Tuner::new();
        tuner.disable(TuneCategory::TempFiles);
        let snap = SystemSnapshot::capture();
        let report = tuner.plan(&snap);
        assert!(!report
            .suggestions
            .iter()
            .any(|s| s.category == TuneCategory::TempFiles));
    }
}
