use serde::{Deserialize, Serialize};

use super::confidence::{ConfidenceResult, ScanEvidence};

/// The type of cheat tool detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheatType {
    Injector,
    MemoryEditor,
    Trainer,
    Loader,
    Other(String),
}

/// Detailed information about a detected cheat tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheatInfo {
    pub cheat_type: CheatType,
    pub target_games: Vec<String>,
    pub uses_injection: bool,
    pub packer: Option<String>,
}

/// The type of malware detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MalwareType {
    RAT,
    Stealer,
    Miner,
    Keylogger,
    Trojan,
    Dropper,
    Ransomware,
    Other(String),
}

/// Detailed information about detected malware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareInfo {
    pub malware_type: MalwareType,
    /// Severity on a 1-10 scale.
    pub severity: u8,
    /// Observed capabilities (e.g. "credential_theft", "persistence").
    pub capabilities: Vec<String>,
}

/// Top-level classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Classification {
    Benign,
    CheatTool(CheatInfo),
    Malware(MalwareInfo),
    PotentiallyUnwanted,
    Unknown,
}

/// Stateless classifier that combines scan evidence and confidence scores to
/// produce a final [`Classification`].
#[derive(Debug, Clone)]
pub struct Classifier;

impl Classifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify a scanned file based on its evidence and pre-computed confidence.
    pub fn classify(
        &self,
        evidence: &ScanEvidence,
        confidence: &ConfidenceResult,
    ) -> Classification {
        // Shortcut: if overall confidence is very low, treat as benign.
        if confidence.overall_score < 10 {
            return Classification::Benign;
        }

        let has_injection_imports = evidence.suspicious_imports.iter().any(|i| {
            let lower = i.to_lowercase();
            lower.contains("writeprocessmemory")
                || lower.contains("createremotethread")
                || lower.contains("ntwritevirtualmemory")
                || lower.contains("virtualallocex")
        });

        let has_c2_indicators = !evidence.network_indicators.is_empty();

        let has_credential_access = evidence.suspicious_imports.iter().any(|i| {
            let lower = i.to_lowercase();
            lower.contains("credread")
                || lower.contains("lsaunprotectdata")
                || lower.contains("cryptunprotectdata")
        }) || evidence.suspicious_strings.iter().any(|s| {
            let lower = s.to_lowercase();
            lower.contains("password") || lower.contains("credential") || lower.contains("wallet")
        });

        let has_mining_indicators = evidence.suspicious_strings.iter().any(|s| {
            let lower = s.to_lowercase();
            lower.contains("stratum+tcp")
                || lower.contains("xmrig")
                || lower.contains("cryptonight")
                || lower.contains("monero")
        });

        let has_keylogger_indicators = evidence.suspicious_imports.iter().any(|i| {
            let lower = i.to_lowercase();
            lower.contains("getasynckeystate")
                || lower.contains("setwindowshookex")
                || lower.contains("rawinput")
        });

        let has_ransomware_indicators = evidence.suspicious_strings.iter().any(|s| {
            let lower = s.to_lowercase();
            lower.contains("your files have been encrypted")
                || lower.contains("bitcoin")
                    && (lower.contains("pay") || lower.contains("ransom"))
        });

        // --- Cheat heuristic ---
        // Targets game processes + uses injection + no C2 network traffic.
        let cheat_signal = evidence.targets_game_processes
            && has_injection_imports
            && !has_c2_indicators
            && !evidence.targets_system_processes;

        // --- Malware heuristic ---
        // Targets system processes + C2 indicators + credential access.
        let malware_signal = (evidence.targets_system_processes || has_c2_indicators)
            && (has_credential_access || has_mining_indicators || has_ransomware_indicators);

        // Decide based on scores and heuristics.
        if cheat_signal || (confidence.cheat_score > confidence.malware_score && confidence.cheat_score >= 20)
        {
            let cheat_type = self.infer_cheat_type(evidence);
            return Classification::CheatTool(CheatInfo {
                cheat_type,
                target_games: self.extract_game_names(evidence),
                uses_injection: has_injection_imports,
                packer: evidence.packer_info.clone(),
            });
        }

        if malware_signal
            || (confidence.malware_score > confidence.cheat_score && confidence.malware_score >= 40)
        {
            let (malware_type, capabilities) = self.infer_malware_details(
                evidence,
                has_credential_access,
                has_mining_indicators,
                has_keylogger_indicators,
                has_ransomware_indicators,
                has_c2_indicators,
            );
            let severity = self.compute_malware_severity(confidence, &capabilities);
            return Classification::Malware(MalwareInfo {
                malware_type,
                severity,
                capabilities,
            });
        }

        if confidence.overall_score >= 20 {
            return Classification::PotentiallyUnwanted;
        }

        if confidence.overall_score >= 10 {
            return Classification::Unknown;
        }

        Classification::Benign
    }

    // --- Private helpers ---

    fn infer_cheat_type(&self, evidence: &ScanEvidence) -> CheatType {
        let has_remote_thread = evidence
            .suspicious_imports
            .iter()
            .any(|i| i.to_lowercase().contains("createremotethread"));
        let has_memory_write = evidence
            .suspicious_imports
            .iter()
            .any(|i| i.to_lowercase().contains("writeprocessmemory"));

        let is_trainer = evidence.suspicious_strings.iter().any(|s| {
            let lower = s.to_lowercase();
            lower.contains("trainer") || lower.contains("num1") || lower.contains("hotkey")
        });

        if is_trainer {
            return CheatType::Trainer;
        }
        if has_remote_thread {
            return CheatType::Injector;
        }
        if has_memory_write {
            return CheatType::MemoryEditor;
        }
        if evidence.packer_info.is_some() {
            return CheatType::Loader;
        }
        CheatType::Other("unknown cheat type".into())
    }

    fn extract_game_names(&self, evidence: &ScanEvidence) -> Vec<String> {
        let known_games = [
            "csgo", "cs2", "valorant", "fortnite", "apex", "overwatch", "pubg", "rust",
            "dota2", "leagueoflegends", "gta5", "eft", "tarkov", "r6", "rainbow6",
        ];
        let mut found = Vec::new();
        for s in &evidence.suspicious_strings {
            let lower = s.to_lowercase();
            for game in &known_games {
                if lower.contains(game) && !found.contains(&(*game).to_string()) {
                    found.push((*game).to_string());
                }
            }
        }
        found
    }

    fn infer_malware_details(
        &self,
        _evidence: &ScanEvidence,
        has_credential_access: bool,
        has_mining: bool,
        has_keylogger: bool,
        has_ransomware: bool,
        has_c2: bool,
    ) -> (MalwareType, Vec<String>) {
        let mut capabilities = Vec::new();

        if has_c2 {
            capabilities.push("command_and_control".into());
        }
        if has_credential_access {
            capabilities.push("credential_theft".into());
        }
        if has_mining {
            capabilities.push("cryptocurrency_mining".into());
        }
        if has_keylogger {
            capabilities.push("keystroke_logging".into());
        }
        if has_ransomware {
            capabilities.push("file_encryption".into());
        }

        let malware_type = if has_ransomware {
            MalwareType::Ransomware
        } else if has_mining {
            MalwareType::Miner
        } else if has_keylogger {
            MalwareType::Keylogger
        } else if has_credential_access && has_c2 {
            MalwareType::Stealer
        } else if has_c2 {
            MalwareType::RAT
        } else {
            MalwareType::Trojan
        };

        (malware_type, capabilities)
    }

    fn compute_malware_severity(
        &self,
        confidence: &ConfidenceResult,
        capabilities: &[String],
    ) -> u8 {
        let base = (confidence.malware_score as f64 / 10.0).ceil() as u8;
        let cap_bonus = capabilities.len() as u8;
        base.saturating_add(cap_bonus).min(10).max(1)
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}
