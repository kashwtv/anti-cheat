pub mod anticheat_compat;
pub mod clean;
pub mod database;
pub mod detection;
pub mod quarantine;
pub mod scanner;
pub mod script_shield;
pub mod tune;
pub mod updater;

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::anticheat_compat::{AntiCheatCompat, CompatStatus};
use crate::clean::{CleanConfig, CleanReport, DeepCleaner, SweepResult};
use crate::database::DatabaseManager;
use crate::detection::{Classification, DetectionEngine, ThreatInfo};
use crate::quarantine::{QuarantineEntry, QuarantineManager};
use crate::scanner::hash_scan::FileHashes;
use crate::scanner::heuristics::HeuristicResult;
use crate::scanner::network_scan::NetworkIndicators;
use crate::scanner::pe_analyzer::PeAnalysis;
use crate::scanner::Scanner;
use crate::tune::{SystemSnapshot, TuneReport, Tuner};
use crate::updater::{UpdateInfo, UpdateManager, UpdateResult};

// Re-export key types
pub use crate::detection::{ThreatLevel, RecommendedAction};
pub use crate::detection::confidence::ScanEvidence;
pub use crate::tune::{Impact as TuneImpact, TuneCategory, TuneSuggestion};
pub use crate::clean::{CleanCategory, CleanTarget, format_bytes};
pub use crate::anticheat_compat::{AntiCheatProduct, CompatAction};

/// Scan sensitivity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanSensitivity {
    Low,
    Medium,
    High,
    Paranoid,
}

impl std::fmt::Display for ScanSensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Paranoid => write!(f, "Paranoid"),
        }
    }
}

/// Configuration for the AntiCheat engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub data_dir: PathBuf,
    pub scan_sensitivity: ScanSensitivity,
    pub max_file_size: u64,
    pub enable_heuristics: bool,
    pub enable_network_analysis: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        let data_dir = dirs_default();
        Self {
            data_dir,
            scan_sensitivity: ScanSensitivity::Medium,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            enable_heuristics: true,
            enable_network_analysis: true,
        }
    }
}

fn dirs_default() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".anticheat")
    } else {
        PathBuf::from(".anticheat")
    }
}

/// Full scan result for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub hashes: FileHashes,
    pub threat_info: ThreatInfo,
    pub classification: Classification,
    pub scan_duration_ms: u64,
    pub timestamp: String,
}

/// Detailed file info (analysis without threat scoring).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub file_path: String,
    pub file_size: u64,
    pub hashes: FileHashes,
    pub pe_analysis: Option<PeAnalysis>,
    pub heuristic_result: Option<HeuristicResult>,
    pub network_indicators: Option<NetworkIndicators>,
}

/// The main AntiCheat engine.
pub struct AntiCheatEngine {
    scanner: Scanner,
    detection: DetectionEngine,
    pub database: DatabaseManager,
    pub quarantine: QuarantineManager,
    updater: UpdateManager,
    compat: AntiCheatCompat,
    config: EngineConfig,
}

impl AntiCheatEngine {
    /// Initialize the engine with the given configuration.
    pub fn init(config: EngineConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;

        let db_dir = config.data_dir.join("db");
        let database = DatabaseManager::init(&db_dir)?;

        let game_db = database::GameDatabase::init();
        let mut scanner = Scanner::new(game_db);

        // Load YARA rules if they exist
        let rules_dir = config.data_dir.join("signatures").join("rules");
        if rules_dir.is_dir() {
            let count = scanner.load_yara_rules(&rules_dir)?;
            info!(count, "loaded YARA rules");
        }

        let detection = DetectionEngine::new();

        let quarantine = QuarantineManager::init(
            config.data_dir.join("quarantine.db"),
            config.data_dir.join("vault"),
        )?;

        let updater = UpdateManager::new(
            &config.data_dir,
            "https://updates.anticheat.app/signatures",
            "https://updates.anticheat.app/app",
        );

        info!(data_dir = %config.data_dir.display(), "AntiCheat engine initialized");

        Ok(Self {
            scanner,
            detection,
            database,
            quarantine,
            updater,
            compat: AntiCheatCompat::new(),
            config,
        })
    }

    /// Build a compatibility status snapshot from a process-name iterator.
    /// The caller is expected to pass the current running-process list
    /// (the service already has one).
    pub fn compat_status<I, S>(&self, processes: I) -> CompatStatus
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.compat.build_status(processes)
    }

    /// Direct access to the compat layer for fine-grained policy checks.
    pub fn compat(&self) -> &AntiCheatCompat {
        &self.compat
    }

    /// Generate a tune plan based on the current system state.
    pub fn tune_plan(&self) -> TuneReport {
        Tuner::new().plan(&SystemSnapshot::capture())
    }

    /// Apply the safe subset of tune tweaks.
    pub fn tune_apply(&self) -> TuneReport {
        Tuner::new().apply(&SystemSnapshot::capture())
    }

    /// Scan for reclaimable garbage without deleting anything.
    pub fn clean_scan(&self) -> CleanReport {
        DeepCleaner::new(CleanConfig::default()).scan()
    }

    /// Sweep based on a previous scan report. Only selected targets are
    /// deleted. The caller is responsible for confirming with the user.
    pub fn clean_sweep(&self, report: &CleanReport) -> SweepResult {
        DeepCleaner::new(CleanConfig::default()).sweep(report)
    }

    /// Full scan of a single file.
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult> {
        let path = path.as_ref();
        let start = Instant::now();

        // Check file size
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > self.config.max_file_size {
            anyhow::bail!(
                "file exceeds max size ({} > {} bytes)",
                metadata.len(),
                self.config.max_file_size
            );
        }

        let (raw, evidence) = self.scanner.scan_file(path)?;

        // Check whitelist
        if let Some(wl) = self.database.whitelist_db.is_whitelisted(&raw.hashes.sha256) {
            info!(name = %wl.name, "file is whitelisted");
            return Ok(ScanResult {
                file_path: path.to_string_lossy().to_string(),
                file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                file_size: metadata.len(),
                hashes: raw.hashes,
                threat_info: ThreatInfo::clean(),
                classification: Classification::Benign,
                scan_duration_ms: start.elapsed().as_millis() as u64,
                timestamp: Utc::now().to_rfc3339(),
            });
        }

        // Check known malware hashes
        let mut evidence = evidence;
        if let Some(hash_match) = self.database.hash_db.lookup_sha256(&raw.hashes.sha256) {
            evidence.hash_match = Some(hash_match.threat_name.clone());
        }

        let threat_info = self.detection.evaluate(&evidence);
        let classification = self.detection_to_classification(&evidence);

        Ok(ScanResult {
            file_path: path.to_string_lossy().to_string(),
            file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            file_size: metadata.len(),
            hashes: raw.hashes,
            threat_info,
            classification,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: Utc::now().to_rfc3339(),
        })
    }

    /// Quick hash-only scan.
    pub fn quick_scan(&self, path: impl AsRef<Path>) -> Result<ScanResult> {
        let path = path.as_ref();
        let start = Instant::now();
        let metadata = std::fs::metadata(path)?;
        let hashes = self.scanner.quick_scan(path)?;

        // Check whitelist
        if self.database.whitelist_db.is_whitelisted(&hashes.sha256).is_some() {
            return Ok(ScanResult {
                file_path: path.to_string_lossy().to_string(),
                file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                file_size: metadata.len(),
                hashes,
                threat_info: ThreatInfo::clean(),
                classification: Classification::Benign,
                scan_duration_ms: start.elapsed().as_millis() as u64,
                timestamp: Utc::now().to_rfc3339(),
            });
        }

        // Check hash database
        let threat_info = if let Some(entry) = self.database.hash_db.lookup_sha256(&hashes.sha256) {
            ThreatInfo {
                threat_level: ThreatLevel::Malicious,
                threat_name: entry.threat_name,
                description: format!("Known malware (hash match). Type: {}", entry.threat_type),
                confidence_score: 95,
                factors: vec![],
                recommended_action: RecommendedAction::Quarantine,
            }
        } else {
            ThreatInfo::clean()
        };

        let classification = if threat_info.threat_level == ThreatLevel::Clean {
            Classification::Benign
        } else {
            Classification::Unknown
        };

        Ok(ScanResult {
            file_path: path.to_string_lossy().to_string(),
            file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            file_size: metadata.len(),
            hashes,
            threat_info,
            classification,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: Utc::now().to_rfc3339(),
        })
    }

    /// Scan a directory.
    pub fn scan_directory(&self, path: impl AsRef<Path>, recursive: bool) -> Result<Vec<ScanResult>> {
        let path = path.as_ref();
        let mut results = Vec::new();

        let walker = if recursive {
            walkdir::WalkDir::new(path)
        } else {
            walkdir::WalkDir::new(path).max_depth(1)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                match self.scan_file(entry.path()) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::warn!(
                            path = %entry.path().display(),
                            error = %e,
                            "failed to scan file"
                        );
                    }
                }
            }
        }

        Ok(results)
    }

    /// Quarantine a file.
    pub fn quarantine_file(
        &self,
        path: impl AsRef<Path>,
        threat_info: &ThreatInfo,
    ) -> Result<QuarantineEntry> {
        self.quarantine.quarantine_file(path, threat_info)
    }

    /// Add file to whitelist.
    pub fn trust_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let hashes = self.scanner.quick_scan(path.as_ref())?;
        let file_name = path
            .as_ref()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let entry = database::WhitelistEntry {
            sha256: hashes.sha256,
            name: file_name,
            description: "User-trusted file".into(),
            trust_level: database::TrustLevel::UserReported,
            category: database::WhitelistCategory::Utility,
            added_by: database::AddedBy::User,
            date_added: Utc::now().to_rfc3339(),
        };

        self.database.whitelist_db.add_entry(&entry)?;
        info!(name = %entry.name, "file added to whitelist");
        Ok(())
    }

    /// Remove from whitelist.
    pub fn untrust_file(&self, sha256: &str) -> Result<()> {
        self.database.whitelist_db.remove_entry(sha256)?;
        Ok(())
    }

    /// Check for signature updates.
    pub async fn check_updates(&self) -> Result<Option<UpdateInfo>> {
        self.updater.check_for_updates().await
    }

    /// Update signatures.
    pub async fn update_signatures(&self) -> Result<UpdateResult> {
        self.updater.update_signatures().await
    }

    /// Get detailed file info without threat scoring.
    pub fn get_file_info(&self, path: impl AsRef<Path>) -> Result<FileInfo> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)?;
        let (raw, _) = self.scanner.scan_file(path)?;

        Ok(FileInfo {
            file_path: path.to_string_lossy().to_string(),
            file_size: metadata.len(),
            hashes: raw.hashes,
            pe_analysis: raw.pe_analysis,
            heuristic_result: raw.heuristic_result,
            network_indicators: raw.network_indicators,
        })
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    fn detection_to_classification(&self, evidence: &ScanEvidence) -> Classification {
        let confidence = detection::ConfidenceScorer::new().calculate_confidence(evidence);
        detection::Classifier::new().classify(evidence, &confidence)
    }
}
