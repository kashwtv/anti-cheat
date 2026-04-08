pub mod hash_scan;
pub mod heuristics;
pub mod pe_analyzer;
pub mod yara_scan;
pub mod archive_scan;
pub mod network_scan;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::database::game_db::GameDatabase;
use crate::detection::confidence::ScanEvidence;

use self::hash_scan::{FileHashes, HashScanner};
use self::heuristics::{HeuristicAnalyzer, HeuristicResult, ImportCategory};
use self::pe_analyzer::{PeAnalysis, PeAnalyzer};
use self::yara_scan::{YaraMatch, YaraScanner};
use self::archive_scan::ArchiveScanner;
use self::network_scan::{NetworkAnalyzer, NetworkIndicators};

/// Unified result from all scan sub-systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawScanData {
    pub hashes: FileHashes,
    pub pe_analysis: Option<PeAnalysis>,
    pub yara_matches: Vec<YaraMatch>,
    pub heuristic_result: Option<HeuristicResult>,
    pub network_indicators: Option<NetworkIndicators>,
}

/// Orchestrates all scan sub-systems.
pub struct Scanner {
    hash_scanner: HashScanner,
    pe_analyzer: PeAnalyzer,
    yara_scanner: YaraScanner,
    heuristic_analyzer: HeuristicAnalyzer,
    network_analyzer: NetworkAnalyzer,
    archive_scanner: ArchiveScanner,
    game_db: GameDatabase,
}

impl Scanner {
    pub fn new(game_db: GameDatabase) -> Self {
        Self {
            hash_scanner: HashScanner::new(),
            pe_analyzer: PeAnalyzer::new(),
            yara_scanner: YaraScanner::new(),
            heuristic_analyzer: HeuristicAnalyzer::new(),
            network_analyzer: NetworkAnalyzer::new(),
            archive_scanner: ArchiveScanner::new(5, 100),
            game_db,
        }
    }

    /// Load YARA rules from a directory.
    pub fn load_yara_rules(&mut self, rules_dir: impl AsRef<Path>) -> Result<usize> {
        self.yara_scanner.load_rules_dir(rules_dir)
    }

    /// Full scan of a single file. Returns raw data and populated evidence.
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<(RawScanData, ScanEvidence)> {
        let path = path.as_ref();
        info!(path = %path.display(), "scanning file");

        let hashes = self.hash_scanner.compute_hashes(path)?;
        let yara_matches = self.yara_scanner.scan_file(path).unwrap_or_default();

        let pe_analysis = self.pe_analyzer.analyze(path).ok();
        let heuristic_result = self
            .heuristic_analyzer
            .analyze(path, pe_analysis.as_ref())
            .ok();
        let network_indicators = self.network_analyzer.analyze_file(path).ok();

        let evidence = self.build_evidence(
            &hashes,
            &pe_analysis,
            &yara_matches,
            &heuristic_result,
            &network_indicators,
        );

        let raw = RawScanData {
            hashes,
            pe_analysis,
            yara_matches,
            heuristic_result,
            network_indicators,
        };

        debug!("scan complete");
        Ok((raw, evidence))
    }

    /// Quick hash-only scan.
    pub fn quick_scan(&self, path: impl AsRef<Path>) -> Result<FileHashes> {
        self.hash_scanner.compute_hashes(path)
    }

    pub fn game_db(&self) -> &GameDatabase {
        &self.game_db
    }

    fn build_evidence(
        &self,
        _hashes: &FileHashes,
        pe_analysis: &Option<PeAnalysis>,
        yara_matches: &[YaraMatch],
        heuristic_result: &Option<HeuristicResult>,
        network_indicators: &Option<NetworkIndicators>,
    ) -> ScanEvidence {
        let mut evidence = ScanEvidence::default();

        // YARA matches
        evidence.yara_matches = yara_matches
            .iter()
            .map(|m| (m.rule_name.clone(), 7))
            .collect();

        if let Some(ref hr) = heuristic_result {
            evidence.suspicious_imports = hr
                .suspicious_imports
                .iter()
                .map(|i| i.function_name.clone())
                .collect();

            evidence.suspicious_strings = hr
                .suspicious_strings
                .iter()
                .map(|s| s.value.clone())
                .collect();

            evidence.entropy_score = hr.entropy_score;
            evidence.packer_info = hr.packer_detected.clone();

            // Check if any suspicious strings reference game or system processes
            for s in &hr.suspicious_strings {
                let lower = s.value.to_lowercase();
                if self.game_db.is_game_process(&lower).is_some() {
                    evidence.targets_game_processes = true;
                }
                if self.game_db.is_system_process(&lower) {
                    evidence.targets_system_processes = true;
                }
            }

            // Check injection targets from imports
            let has_injection = hr
                .suspicious_imports
                .iter()
                .any(|i| i.category == ImportCategory::Injection);
            let has_credential = hr
                .suspicious_imports
                .iter()
                .any(|i| i.category == ImportCategory::Credential);
            if has_injection && !has_credential {
                evidence.targets_game_processes = true;
            }
            if has_credential {
                evidence.targets_system_processes = true;
            }
        }

        if let Some(ref pe) = pe_analysis {
            evidence.has_signature = pe.is_signed;
        }

        if let Some(ref ni) = network_indicators {
            evidence.network_indicators = ni
                .urls
                .iter()
                .chain(ni.ip_addresses.iter())
                .chain(ni.domains.iter())
                .cloned()
                .collect();
        }

        evidence
    }
}
